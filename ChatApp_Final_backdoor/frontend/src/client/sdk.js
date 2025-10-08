import {
  generateKeypair, aesEncrypt, aesDecrypt, aesDecryptText,
  wrapKeyWithRSA_OAEP, unwrapKeyWithRSA_OAEP,
  signPSS, verifyPSS, sha256Bytes, b64u
} from "../crypto/e2ee.js";

let websocket = null;
let eventListeners = new Set();
let connectionState = 'disconnected';
let reconnectAttempts = 0;
let maxReconnectAttempts = 5;
let reconnectInterval = 1000;

function emit(event){ eventListeners.forEach(callback=>callback(event)); }
export function onEvent(callback){ eventListeners.add(callback); return ()=>eventListeners.delete(callback); }

export function getConnectionState() {
  return connectionState;
}

export function isConnected() {
  return websocket && websocket.readyState === WebSocket.OPEN;
}

function handleConnectionError() {
  connectionState = 'disconnected';
  emit({ type: 'error', code: 'CONNECTION_LOST', detail: 'Connection lost' });
  
  if (reconnectAttempts < maxReconnectAttempts) {
    connectionState = 'reconnecting';
    reconnectAttempts++;
    
    emit({ type: 'reconnecting', attempt: reconnectAttempts, maxAttempts: maxReconnectAttempts });
    
    setTimeout(() => {
      connect().catch(error => {
        if (reconnectAttempts >= maxReconnectAttempts) {
          emit({ type: 'error', code: 'RECONNECT_FAILED', detail: 'Reconnect failed' });
        }
      });
    }, reconnectInterval * reconnectAttempts);
  } else {
    emit({ type: 'error', code: 'MAX_RECONNECT_ATTEMPTS', detail: 'Max reconnect attempts reached' });
  }
}

function resetReconnectState() {
  reconnectAttempts = 0;
  connectionState = 'connected';
}

let my = { userId: null, keys: null, pubPem: null, privPem: null };

function generateUUID() {
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, function(char) {
    const random = Math.random() * 16 | 0;
    const value = char == 'x' ? random : (random & 0x3 | 0x8);
    return value.toString(16);
  });
}

export function setUserId(userId) {
  // Reset key state if user changes
  if (my.userId !== userId) {
    my.keys = null;
    my.pubPem = null;
    my.privPem = null;
  }
  my.userId = userId;
}

export function getUserId() {
  return my.userId;
}

export function hasKeypairForUser(userId) {
  const keyStorageKey = `socp_keys_${userId}`;
  const saved = localStorage.getItem(keyStorageKey);
  return saved !== null;
}

export function downloadUserKeys(userId, pubPem, privPem) {
  // Create key file content
  const keyData = {
    userId: userId,
    pubkey: pubPem,
    privatekey: privPem,
    generatedAt: new Date().toISOString(),
    version: "1.0"
  };
  
  // Create download file
  const fileBlob = new Blob([JSON.stringify(keyData, null, 2)], { type: 'application/json' });
  const downloadUrl = URL.createObjectURL(fileBlob);
  const downloadLink = document.createElement('a');
  downloadLink.href = downloadUrl;
  downloadLink.download = `socp_keys_${userId}.json`;
  document.body.appendChild(downloadLink);
  downloadLink.click();
  document.body.removeChild(downloadLink);
  URL.revokeObjectURL(downloadUrl);
}

export async function setUserKeys(userId, pubPem, privPem) {
  // Set user keys directly without generating new ones
  const keyStorageKey = `socp_keys_${userId}`;
  localStorage.setItem(keyStorageKey, JSON.stringify({ pubPem, privPem }));
  
  // Update current user state
  my.userId = userId;
  my.pubPem = pubPem;
  my.privPem = privPem;
  
  // Import key objects immediately
  my.keys = await importKeypairFromPem(pubPem, privPem);
}

export async function generateUserIdFromPubkey(pubPem) {
  // Generate deterministic user ID from public key
  const encoder = new TextEncoder();
  const data = encoder.encode(pubPem);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  const hashHex = hashArray.map(byte => byte.toString(16).padStart(2, '0')).join('');
  
  // Convert hash to UUID format
  const uuid = [
    hashHex.substring(0, 8),
    hashHex.substring(8, 12),
    '4' + hashHex.substring(13, 16), // Version 4
    ((parseInt(hashHex.substring(16, 17), 16) & 0x3) | 0x8).toString(16) + hashHex.substring(17, 20), // Variant
    hashHex.substring(20, 32)
  ].join('-');
  
  return uuid;
}

export async function listUsers() {
  if (!isConnected()) {
    throw new Error("Not connected to server");
  }
  
  return new Promise((resolve, reject) => {
    const timeout = setTimeout(() => {
      reject(new Error("Get users timeout"));
    }, 5000);
    
    const handleResponse = (event) => {
      if (event.type === "USERS_LIST") {
        clearTimeout(timeout);
        eventListeners.delete(handleResponse);
        resolve(event.payload.users);
      } else if (event.type === "error" && event.code === "GET_USERS_FAILED") {
        clearTimeout(timeout);
        eventListeners.delete(handleResponse);
        reject(new Error(event.detail || "Get users failed"));
      }
    };
    
    eventListeners.add(handleResponse);
    
    try {
      websocket.send(JSON.stringify({
        type: "GET_USERS",
        from: my.userId,
        to: "server_local",
        ts: Date.now(),
        payload: {},
        sig: ""
      }));
    } catch (error) {
      eventListeners.delete(handleResponse);
      clearTimeout(timeout);
      reject(error);
    }
  });
}
const keyCache = new Map(); // userId -> {pubPem, imported:{oaepPub, pssPub}}
let chunkedFiles = new Map(); // fileId -> {filename, filesize, mimeType, totalChunks, receivedChunks, wrappedKey, sender}

// ---- util ----
function now(){ return Date.now(); }

// Format file size
function formatBytes(bytes) {
  if (!bytes) return "0 B";
  if (bytes < 1024) return bytes + " B";
  if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
  return (bytes / 1024 / 1024).toFixed(1) + " MB";
}

async function importPubForOAEP(pubPem){
  const raw = pubPem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, "");
  
  // Use standard base64 decoding
  const b64 = raw.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((raw.length + 3) % 4);
  const bin = atob(b64);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    der[i] = bin.charCodeAt(i);
  }
  
  return crypto.subtle.importKey("spki", der, { name:"RSA-OAEP", hash:"SHA-256" }, true, ["encrypt"]);
}

async function importPubForPSS(pubPem){
  const raw = pubPem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, "");
  
  // Use standard base64 decoding
  const b64 = raw.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((raw.length + 3) % 4);
  const bin = atob(b64);
  const der = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    der[i] = bin.charCodeAt(i);
  }
  
  return crypto.subtle.importKey("spki", der, { name:"RSA-PSS", hash:"SHA-256" }, true, ["verify"]);
}

// Import keypair from PEM format
async function importKeypairFromPem(pubPem, privPem) {
  const oaepPub = await importPubForOAEP(pubPem);
  const pssPub = await importPubForPSS(pubPem);
  
  // Import private key - use safer method for PEM format
  const rawPriv = privPem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, "");
  
  // Use standard base64 decoding instead of b64u
  const b64 = rawPriv.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((rawPriv.length + 3) % 4);
  const bin = atob(b64);
  const derPriv = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    derPriv[i] = bin.charCodeAt(i);
  }
  
  const oaepPriv = await crypto.subtle.importKey("pkcs8", derPriv, { name:"RSA-OAEP", hash:"SHA-256" }, true, ["decrypt"]);
  const pssPriv = await crypto.subtle.importKey("pkcs8", derPriv, { name:"RSA-PSS", hash:"SHA-256" }, true, ["sign"]);
  
  return { pubPem, privPem, oaepPub, oaepPriv, pssPub, pssPriv };
}

// ---- 1) Generate/load local keys and send USER_HELLO on first connection ----
export async function ensureKeypair(){
  if (!my.userId) {
    throw new Error("User ID not set, call setUserId() first");
  }
  
  // Create independent key storage for each user ID
  const keyStorageKey = `socp_keys_${my.userId}`;
  const saved = localStorage.getItem(keyStorageKey);
  
  if (!saved){
    const kp = await generateKeypair();
    localStorage.setItem(keyStorageKey, JSON.stringify({ pubPem: kp.pubPem, privPem: kp.privPem }));
    my.keys = kp;
    my.pubPem = kp.pubPem; my.privPem = kp.privPem;
  }else{
    const { pubPem, privPem } = JSON.parse(saved);
    my.pubPem = pubPem; my.privPem = privPem;
    // Re-import key objects from saved PEM format
    my.keys = await importKeypairFromPem(pubPem, privPem);
  }
  return { pubPem: my.pubPem };
}

export async function connect(url = "ws://localhost:8080"){
  if (!my.userId) {
    throw new Error("User ID not set, call setUserId() first");
  }
  if (!my.keys) await ensureKeypair();

  return new Promise((resolve, reject) => {
    if (websocket) {
      websocket.close();
    }
    
    connectionState = 'connecting';
    emit({ type: 'connecting', url });
    
    websocket = new WebSocket(url);

    websocket.onopen = async () => {
      connectionState = 'connected';
      resetReconnectState();
      
      const helloFrame = {
        type: "USER_HELLO",
        from: my.userId,
        to: "server_local",
        ts: now(),
        payload: {
          user_id: my.userId,
          pubkey: my.pubPem,
          privkey_store: my.privPem,
          pake_password: "web-client-password",
          meta: JSON.stringify({ client: "web-v1", name: "Web User" }),
          version: 1
        },
        sig: ""
      };
      
      try {
        websocket.send(JSON.stringify(helloFrame));
        emit({ type: 'connected', serverId: "server_local" });
        resolve({ serverId: "server_local", pinned: true });
      } catch (error) {
        reject(error);
      }
    };

    websocket.onmessage = async (event) => {
      let message; 
      try { 
        message = JSON.parse(event.data); 
      } catch (error) { 
        return; 
      }
      
      if (message.type === "USER_DELIVER") {
        const payload = message.payload;
        
        if (payload.total_chunks && payload.total_chunks > 1) {
          if (!chunkedFiles) {
            chunkedFiles = new Map();
          }
          
          const fileId = payload.file_id;
          chunkedFiles.set(fileId, {
            filename: payload.filename,
            filesize: payload.filesize,
            mimeType: payload.mime_type,
            totalChunks: payload.total_chunks,
            receivedChunks: new Map(),
            wrappedKey: payload.wrapped_key,
            sender: payload.sender
          });
          return;
        }
        
        const rawKey = await unwrapKeyWithRSA_OAEP(my.keys.oaepPriv, payload.wrapped_key);
        const plaintext = await aesDecryptText({ ciphertext: payload.ciphertext, iv: payload.iv, rawKey });
        // Prefer sender field in payload, this is the real sender ID
        // message.from is server ID, not sender ID
        const senderId = payload.sender;
        const { pssPub } = await getPubKey(senderId);
        
        const parts = [
          new TextEncoder().encode(payload.ciphertext),
          new TextEncoder().encode(payload.iv),
          new TextEncoder().encode(payload.tag ?? ""),
          new TextEncoder().encode(senderId),
          new TextEncoder().encode(message.to),
          new TextEncoder().encode(String(message.ts))
        ];
        
        const concatenated = new Uint8Array(parts.reduce((acc, part) => acc + part.length, 0));
        let offset = 0;
        for (const part of parts) {
          concatenated.set(part, offset);
          offset += part.length;
        }
        
        const contentHash = await crypto.subtle.digest("SHA-256", concatenated);
        
        if (payload.content_sig) {
          const ok = await verifyPSS(pssPub, contentHash, payload.content_sig);
          if (!ok) {
            emit({ type:"error", code:"INVALID_SIG", detail:"content signature failed" });
          }
        }
        
        emit({ 
          type:"incoming", 
          id: crypto.randomUUID(), 
          from: senderId, 
          to: message.to, 
          channel: undefined,
          ts: message.ts, 
          text: plaintext,
          messageType: "text",
          isFile: false
        });
        return;
      }

      if (message.type === "MSG_PUBLIC_CHANNEL") {
        const payload = message.payload;
        const channelId = message.to;
        
        const channelKeyData = await getChannelKey(channelId);
        
        const ivBytes = new Uint8Array(b64u.dec(payload.iv));
        const ciphertextBytes = b64u.dec(payload.ciphertext);
        
        let plaintext;
        try {
          const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBytes },
            channelKeyData.key,
            ciphertextBytes
          );
          plaintext = new TextDecoder().decode(decrypted);
        } catch (err) {
          emit({ type:"error", code:"DECRYPT_FAILED", detail: err.message });
          return;
        }
        
        // For public channel messages, message.from is the sender ID
        const senderId = message.from;
        
        if (payload.content_sig && senderId !== my.userId) {
          try {
            let senderPub;
            if (keyCache.has(senderId)) {
              senderPub = keyCache.get(senderId);
            } else {
              senderPub = await getPubKey(senderId);
            }
            
            const contentHash = await sha256Bytes(
              new TextEncoder().encode(payload.ciphertext),
              new TextEncoder().encode(payload.iv),
              new TextEncoder().encode(senderId),
              new TextEncoder().encode(channelId),
              new TextEncoder().encode(String(message.ts))
            );
            
            const sigOk = await verifyPSS(senderPub.pssPub, contentHash, payload.content_sig);
            if (!sigOk) {
              emit({ type:"error", code:"INVALID_SIG", detail:"channel message sig failed" });
              return;
            }
          } catch (err) {
            console.warn("Could not verify signature:", err.message);
          }
        }
        
        emit({ 
          type:"incoming", 
          id: crypto.randomUUID(), 
          from: senderId, 
          to: undefined,
          channel: channelId,
          ts: message.ts, 
          text: plaintext,
          messageType: "text",
          isFile: false
        });
        return;
      }

      if (message.type === "FILE_DELIVER") {
        if (message.payload?.total_chunks && message.payload?.total_chunks > 1) {
          message.type = "FILE_INIT";
        } else {
          const payload = message.payload;
          const actualSenderId = payload.sender;
        
        try {
          let aesKeyRaw;
          const isDM = message.to && message.to !== "public" && message.to !== "server_local";
          const isChannel = !isDM && (message.to === "public" || message.to === "server_local");
          
          if (actualSenderId !== my.userId) {
            if (isDM) {
              aesKeyRaw = await unwrapKeyWithRSA_OAEP(my.keys.oaepPriv, payload.wrapped_key);
            } else if (isChannel) {
              const channelKeyData = await getChannelKey("public");
              const keyData = b64u.dec(payload.wrapped_key);
              const keyIv = keyData.slice(0, 12);
              const encryptedKey = keyData.slice(12);
              
              aesKeyRaw = await crypto.subtle.decrypt(
                { name: "AES-GCM", iv: keyIv },
                channelKeyData.key,
                encryptedKey
              );
            } else {
              aesKeyRaw = await unwrapKeyWithRSA_OAEP(my.keys.oaepPriv, payload.wrapped_key);
            }
          } else {
            aesKeyRaw = b64u.dec(payload.wrapped_key);
          }
          
          const aesKey = await crypto.subtle.importKey(
            "raw",
            aesKeyRaw,
            { name: "AES-GCM" },
            false,
            ["decrypt"]
          );
          
          const ivBytes = b64u.dec(payload.iv);
          const ciphertextBytes = b64u.dec(payload.ciphertext);
          
          const decrypted = await crypto.subtle.decrypt(
            { name: "AES-GCM", iv: ivBytes },
            aesKey,
            ciphertextBytes
          );
          
          if (payload.file_sig && actualSenderId !== my.userId) {
            try {
              let senderPub;
              if (keyCache.has(actualSenderId)) {
                senderPub = keyCache.get(actualSenderId);
              } else {
                senderPub = await getPubKey(actualSenderId);
              }
              
              const fileMetadata = JSON.stringify({
                fileId: payload.file_id,
                fileName: payload.filename,
                fileSize: payload.filesize,
                mimeType: payload.mime_type,
                ts: message.ts
              });
              
              const fileParts = [
                new TextEncoder().encode(fileMetadata),
                new TextEncoder().encode(payload.ciphertext),
                new TextEncoder().encode(payload.iv)
              ];
              
              const fileConcatenated = new Uint8Array(fileParts.reduce((acc, part) => acc + part.length, 0));
              let fileOffset = 0;
              for (const part of fileParts) {
                fileConcatenated.set(part, fileOffset);
                fileOffset += part.length;
              }
              
              const metaHash = await crypto.subtle.digest("SHA-256", fileConcatenated);
              
              if (!payload.file_sig) {
                return;
              }
              
              const sigOk = await verifyPSS(senderPub.pssPub, metaHash, payload.file_sig);
              if (!sigOk) {
                console.warn("File signature verification failed");
              }
            } catch (err) {
              console.warn("Could not verify file signature:", err.message);
            }
          }
          
          emit({
            type: "incoming",
            id: payload.file_id || crypto.randomUUID(),
            from: actualSenderId,
            to: message.to,
            channel: payload.channel || (message.to === "public" ? "public" : undefined),
            ts: message.ts,
            text: `${payload.filename} (${formatBytes(payload.filesize)})`,
            messageType: "file",
            isFile: true,
            fileData: {
              filename: payload.filename,
              filesize: payload.filesize,
              mimeType: payload.mime_type,
              data: decrypted
            }
          });
          
        } catch (err) {
          emit({ type:"error", code:"FILE_DECRYPT_FAILED", detail: err.message });
        }
        
        return;
        }
      }

      if (message.type === "FILE_INIT") {
        if (!chunkedFiles) {
          chunkedFiles = new Map();
        }
        
        const fileId = message.payload.file_id;
        
        chunkedFiles.set(fileId, {
          filename: message.payload.filename,
          filesize: message.payload.filesize,
          mimeType: message.payload.mime_type,
          totalChunks: message.payload.total_chunks,
          receivedChunks: new Map(),
          wrappedKey: message.payload.wrapped_key,
          sender: message.payload.sender,
          to: message.to,
          channel: message.payload.channel
        });
        
        return;
      }

      if (message.type === "FILE_CHUNK" || message.type === "MSG_FILE_CHUNK") {
        const fileId = message.payload.file_id;
        const chunkIndex = message.payload.chunk_index;
        
        if (!chunkedFiles || !chunkedFiles.has(fileId)) {
          return;
        }
        
        const fileInfo = chunkedFiles.get(fileId);
        
        if (!message.payload.ciphertext || !message.payload.iv) {
          return;
        }
        
        fileInfo.receivedChunks.set(chunkIndex, {
          ciphertext: message.payload.ciphertext,
          iv: message.payload.iv,
          chunkSig: message.payload.chunk_sig
        });
        
        if (fileInfo.receivedChunks.size === fileInfo.totalChunks) {
          await reassembleChunkedFile(fileId, fileInfo);
        }
        return;
      }

      if (message.type === "FILE_COMPLETE") {
        return;
      }

      if (message.type === "PUBKEY") {
        const { user_id, pubkey_b64 } = message.payload;
        const pubPem = atob(pubkey_b64);
        const oaepPub = await importPubForOAEP(pubPem);
        const pssPub = await importPubForPSS(pubPem);
        keyCache.set(user_id, { pubPem, oaepPub, pssPub, ts: now() });
        return;
      }

      if (message.type === "USERS_LIST") {
        emit({ type: "USERS_LIST", payload: message.payload });
        return;
      }

      if (message.type === "USER_LIST_UPDATED") {
        try {
          const users = await listUsers();
          emit({ type: "USERS_LIST", payload: { users } });
        } catch (error) {
          console.error("Failed to get users:", error);
        }
        return;
      }

      if (message.type === "PUBKEY_RESPONSE") {
        const { user_id, pubkey, meta } = message.payload;
        const oaepPub = await importPubForOAEP(pubkey);
        const pssPub = await importPubForPSS(pubkey);
        keyCache.set(user_id, { pubkey, oaepPub, pssPub, ts: now() });
        return;
      }

      if (message.type === "PUBLIC_CHANNEL_KEY") {
        const payload = message.payload;
        
        try {
          const wrappedKeyBytes = b64u.dec(payload.wrapped_key);
          const wrappedKeyStr = b64u.enc(wrappedKeyBytes);
          const rawKey = await unwrapKeyWithRSA_OAEP(my.keys.oaepPriv, wrappedKeyStr);
          
          const aesKey = await crypto.subtle.importKey(
            "raw",
            rawKey,
            { name: "AES-GCM" },
            false,
            ["encrypt", "decrypt"]
          );
          
          channelKeys.set("public", {
            key: aesKey,
            rawKey: rawKey,
            createdAt: Date.now()
          });
        } catch (err) {
          console.error("Failed to decrypt channel key:", err);
        }
        return;
      }

      if (message.type === "ERROR") {
        emit({ type:"error", code: message.payload?.code, detail: message.payload?.detail });
        return;
      }
    };

    websocket.onclose = (event) => { 
      connectionState = 'disconnected';
      
      if (event.code !== 1000) {
        handleConnectionError();
      } else {
        emit({ type: 'disconnected', code: event.code, reason: event.reason });
      }
    };
    
    websocket.onerror = (e) => { 
      connectionState = 'disconnected';
      emit({ type: 'error', code: 'WEBSOCKET_ERROR', detail: e.message || 'WebSocket connection error' });
      reject(e); 
    };
  });
}

export function disconnect() {
  if (websocket) {
    websocket.close(1000, 'User disconnected');
    websocket = null;
  }
  connectionState = 'disconnected';
  resetReconnectState();
  emit({ type: 'disconnected', code: 1000, reason: 'User disconnected' });
}

async function getPubKey(userId){
  if (keyCache.has(userId)) return keyCache.get(userId);
  const req = {
    type: "GET_PUBKEY",
    from: my.userId,
    to: "server_local",
    ts: now(),
    payload: { user_id: userId },
    sig: ""
  };
  websocket?.send(JSON.stringify(req));
  
  const start = now();
  while (now() - start < 5000) {
    if (keyCache.has(userId)) return keyCache.get(userId);
    await new Promise(r=>setTimeout(r,50));
  }
  throw new Error("GET_PUBKEY TIMEOUT");
}

export async function sendDM({ toUserId, plaintext }){
  if (!websocket || websocket.readyState !== 1) throw new Error("websocket_NOT_CONNECTED");
  const recip = await getPubKey(toUserId);

  const { ciphertext, iv, rawKey } = await aesEncrypt(plaintext);
  const wrapped_key = await wrapKeyWithRSA_OAEP(recip.oaepPub, rawKey);

  const ts = now();
  const contentHash = await sha256Bytes(
    new TextEncoder().encode(ciphertext),
    new TextEncoder().encode(iv),
    new TextEncoder().encode(""),
    new TextEncoder().encode(my.userId),
    new TextEncoder().encode(toUserId),
    new TextEncoder().encode(String(ts))
  );
  
  const content_sig = await signPSS(my.keys.pssPriv, contentHash);

  const frame = {
    type: "MSG_DIRECT",
    from: my.userId,
    to: toUserId,
    ts,
    payload: {
      ciphertext, iv,
      tag: "",
      wrapped_key,
      sender_pub: btoa(my.pubPem),
      content_sig
    },
    sig: ""
  };
  websocket.send(JSON.stringify(frame));
  return { ok:true, id: crypto.randomUUID() };
}

const channelKeys = new Map();

async function getChannelKey(channelId) {
  if (channelKeys.has(channelId)) {
    return channelKeys.get(channelId);
  }
  
  const key = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 }, 
    true, 
    ["encrypt", "decrypt"]
  );
  const rawKey = await crypto.subtle.exportKey("raw", key);
  
  channelKeys.set(channelId, {
    key: key,
    rawKey: rawKey,
    createdAt: Date.now()
  });
  
  return channelKeys.get(channelId);
}

export async function sendPublic({ plaintext, channelId = "public" }){
  if (!websocket || websocket.readyState !== 1) {
    throw new Error("websocket_NOT_CONNECTED");
  }
  
  const channelKeyData = await getChannelKey(channelId);
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encodedText = new TextEncoder().encode(plaintext);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv }, 
    channelKeyData.key, 
    encodedText
  );
  
  const ciphertextB64 = b64u.enc(ciphertext);
  const ivB64 = b64u.enc(iv);
  
  const ts = now();
  const contentToSign = await sha256Bytes(
    new TextEncoder().encode(ciphertextB64),
    new TextEncoder().encode(ivB64),
    new TextEncoder().encode(my.userId),
    new TextEncoder().encode(channelId),
    new TextEncoder().encode(String(ts))
  );
  const sig = await signPSS(my.keys.pssPriv, contentToSign);
  
  const frame = {
    type: "MSG_PUBLIC_CHANNEL",
    from: my.userId,
    to: channelId,
    ts: ts,
    payload: {
      ciphertext: ciphertextB64,
      iv: ivB64,
      content_sig: sig,
      sender_pub: btoa(my.pubPem)
    },
    sig: ""
  };
  
  websocket.send(JSON.stringify(frame));
  
  return { ok: true, id: crypto.randomUUID() };
}


export async function sendFile({ file, toUserId, channelId, onProgress }) {
  if (!websocket || websocket.readyState !== 1) {
    throw new Error("websocket_NOT_CONNECTED");
  }
  
  const chunkThreshold = 5 * 1048576;
  if (file.size > chunkThreshold) {
    return sendFileChunked({ file, toUserId, channelId, onProgress });
  }
  
  const fileData = await file.arrayBuffer();
  const maxSize = 50 * 1048576;
  if (fileData.byteLength > maxSize) {
    throw new Error("FILE_TOO_LARGE");
  }
  
  const fileId = crypto.randomUUID();
  
  if (onProgress) onProgress(10);
  
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const encrypted = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv: iv },
    aesKey,
    fileData
  );
  
  if (onProgress) onProgress(50);
  
  const rawKey = await crypto.subtle.exportKey("raw", aesKey);
  
  let wrappedKey;
  if (toUserId) {
    const recipPub = await getPubKey(toUserId);
    wrappedKey = await wrapKeyWithRSA_OAEP(recipPub.oaepPub, rawKey);
  } else if (channelId) {
    const channelKeyData = await getChannelKey(channelId);
    
    const keyIv = crypto.getRandomValues(new Uint8Array(12));
    const encryptedKey = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: keyIv },
      channelKeyData.key,
      rawKey
    );
    
    const keyData = new Uint8Array(keyIv.length + encryptedKey.byteLength);
    keyData.set(keyIv, 0);
    keyData.set(new Uint8Array(encryptedKey), keyIv.length);
    wrappedKey = b64u.enc(keyData);
  }
  
  if (onProgress) onProgress(70);
  
  const ts = now();
  const fileMetadata = JSON.stringify({
    fileId: fileId,
    fileName: file.name,
    fileSize: file.size,
    mimeType: file.type,
    ts: ts
  });
  
  const ciphertextB64 = b64u.enc(encrypted);
  const ivB64 = b64u.enc(iv);
  
  const sendFileParts = [
    new TextEncoder().encode(fileMetadata),
    new TextEncoder().encode(ciphertextB64),
    new TextEncoder().encode(ivB64)
  ];
  
  const sendFileConcatenated = new Uint8Array(sendFileParts.reduce((acc, part) => acc + part.length, 0));
  let sendFileOffset = 0;
  for (const part of sendFileParts) {
    sendFileConcatenated.set(part, sendFileOffset);
    sendFileOffset += part.length;
  }
  
  const metaHash = await crypto.subtle.digest("SHA-256", sendFileConcatenated);
  const fileSig = await signPSS(my.keys.pssPriv, metaHash);
  
  if (onProgress) onProgress(80);
  
  // Assemble message
  const frame = {
    type: "MSG_FILE",
    from: my.userId,
    to: toUserId || channelId,
    ts: ts,
    payload: {
      file_id: fileId,
      filename: file.name,
      filesize: file.size,
      mime_type: file.type,
      ciphertext: ciphertextB64,
      iv: ivB64,
      wrapped_key: wrappedKey,
      file_sig: fileSig
    }
  };
  
  websocket.send(JSON.stringify(frame));
  
  if (onProgress) onProgress(100);
  
  return { ok: true, fileId: fileId };
}

async function sendFileChunked({ file, toUserId, channelId, onProgress }) {
  const fileId = crypto.randomUUID();
  const chunkSize = 1048576;
  const totalChunks = Math.ceil(file.size / chunkSize);
  
  const aesKey = await crypto.subtle.generateKey(
    { name: "AES-GCM", length: 256 },
    true,
    ["encrypt", "decrypt"]
  );
  const rawKey = await crypto.subtle.exportKey("raw", aesKey);
  
  let wrappedKey;
  if (toUserId) {
    const recipPub = await getPubKey(toUserId);
    wrappedKey = await wrapKeyWithRSA_OAEP(recipPub.oaepPub, rawKey);
  } else if (channelId) {
    wrappedKey = b64u.enc(rawKey);
  }
  
  const initFrame = {
    type: "MSG_FILE_INIT",
    from: my.userId,
    to: toUserId || channelId,
    ts: now(),
    payload: {
      file_id: fileId,
      filename: file.name,
      filesize: file.size,
      mime_type: file.type,
      total_chunks: totalChunks,
      chunk_size: chunkSize,
      wrapped_key: wrappedKey
    }
  };
  
  websocket.send(JSON.stringify(initFrame));
  
  if (onProgress) onProgress(5);
  
  for (let i = 0; i < totalChunks; i++) {
    const start = i * chunkSize;
    const end = Math.min(start + chunkSize, file.size);
    const chunk = file.slice(start, end);
    
    const chunkData = await chunk.arrayBuffer();
    
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: iv },
      aesKey,
      chunkData
    );
    
    const chunkHash = await sha256Bytes(
      new TextEncoder().encode(fileId),
      new TextEncoder().encode(String(i))
    );
    const chunkSig = await signPSS(my.keys.pssPriv, chunkHash);
    
    const chunkFrame = {
      type: "MSG_FILE_CHUNK",
      from: my.userId,
      to: toUserId || channelId,
      ts: now(),
      payload: {
        file_id: fileId,
        chunk_index: i,
        ciphertext: b64u.enc(encrypted),
        iv: b64u.enc(iv),
        chunk_sig: chunkSig
      }
    };
    
    websocket.send(JSON.stringify(chunkFrame));
    
    const progress = 5 + Math.floor((i + 1) / totalChunks * 90);
    if (onProgress) onProgress(progress);
    
    await new Promise(r => setTimeout(r, 10));
  }
  
  const completeFrame = {
    type: "MSG_FILE_COMPLETE",
    from: my.userId,
    to: toUserId || channelId,
    ts: now(),
    payload: {
      file_id: fileId
    }
  };
  
  websocket.send(JSON.stringify(completeFrame));
  
  if (onProgress) onProgress(100);
  
  return { ok: true, fileId: fileId };
}

async function reassembleChunkedFile(fileId, fileInfo) {
  try {
    let aesKeyRaw;
    if (fileInfo.sender !== my.userId) {
      const isDM = fileInfo.to && fileInfo.to !== "public" && fileInfo.to !== "server_local";
      const isChannel = !isDM && (fileInfo.to === "public" || fileInfo.to === "server_local");
      
      if (isDM) {
        aesKeyRaw = await unwrapKeyWithRSA_OAEP(my.keys.oaepPriv, fileInfo.wrappedKey);
      } else if (isChannel) {
        const channelKeyData = await getChannelKey("public");
        
        try {
          const keyData = b64u.dec(fileInfo.wrappedKey);
          
          if (keyData.byteLength === 32) {
            aesKeyRaw = keyData;
          } else if (keyData.byteLength >= 28) {
            const keyIv = keyData.slice(0, 12);
            const encryptedKey = keyData.slice(12);
            
            aesKeyRaw = await crypto.subtle.decrypt(
              { name: "AES-GCM", iv: keyIv },
              channelKeyData.key,
              encryptedKey
            );
          } else {
            throw new Error(`Invalid key data length: ${keyData.byteLength} bytes`);
          }
        } catch (err) {
          throw err;
        }
      } else {
        return;
      }
    } else {
      return;
    }
    
    const decryptedChunks = [];
    for (let i = 0; i < fileInfo.totalChunks; i++) {
      const chunkData = fileInfo.receivedChunks.get(i);
      if (!chunkData) {
        return;
      }
      
      const chunkDecrypted = await aesDecrypt({
        ciphertext: chunkData.ciphertext,
        iv: chunkData.iv,
        rawKey: aesKeyRaw
      });
      
      decryptedChunks.push(chunkDecrypted);
    }
    
    const totalSize = decryptedChunks.reduce((sum, chunk) => sum + chunk.byteLength, 0);
    const mergedFile = new Uint8Array(totalSize);
    let offset = 0;
    
    for (const chunk of decryptedChunks) {
      mergedFile.set(new Uint8Array(chunk), offset);
      offset += chunk.byteLength;
    }
    
    emit({
      type: "incoming",
      id: fileId,
      from: fileInfo.sender,
      to: my.userId,
      channel: fileInfo.channel || (fileInfo.to === "public" ? "public" : undefined),
      ts: Date.now(),
      text: `${fileInfo.filename} (${formatBytes(fileInfo.filesize)})`,
      messageType: "file",
      isFile: true,
      fileData: {
        filename: fileInfo.filename,
        filesize: fileInfo.filesize,
        mimeType: fileInfo.mimeType,
        data: mergedFile.buffer
      }
    });
    
    chunkedFiles.delete(fileId);
    
  } catch (err) {
    emit({ type: "error", code: "CHUNKED_FILE_REASSEMBLE_FAILED", detail: err.message });
  }
}
