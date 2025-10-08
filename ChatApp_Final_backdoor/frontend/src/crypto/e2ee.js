const textEnc = new TextEncoder();
const textDec = new TextDecoder();

export const b64u = {
  enc: (buf) => {
    const uint8Array = new Uint8Array(buf);
    let binary = '';
    const chunkSize = 8192;
    
    for (let i = 0; i < uint8Array.length; i += chunkSize) {
      const chunk = uint8Array.slice(i, i + chunkSize);
      binary += String.fromCharCode(...chunk);
    }
    
    const b64 = btoa(binary);
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  },
  dec: (str) => {
    if (!str || typeof str !== 'string') {
      throw new Error('Invalid input');
    }
    const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
    return bytes.buffer;
  },
};

async function importRsaKey(pem, usages, alg) {
  const raw = pem.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, "");
  const der = b64u.dec(raw);
  return crypto.subtle.importKey(
    pem.includes("PUBLIC KEY") ? "spki" : "pkcs8",
    der,
    alg,
    true,
    usages
  );
}

async function exportPem(key, kind) {
  const fmt = kind === "public" ? "spki" : "pkcs8";
  const der = await crypto.subtle.exportKey(fmt, key);
  const b64 = btoa(String.fromCharCode(...new Uint8Array(der)));
  const wrap = (s, n = 64) => s.replace(new RegExp(`(.{1,${n}})`, "g"), "$1\n");
  const head = kind === "public" ? "PUBLIC KEY" : "PRIVATE KEY";
  return `-----BEGIN ${head}-----\n${wrap(b64)}-----END ${head}-----`;
}

const RSA_PSS = { name: "RSA-PSS", hash: "SHA-256", modulusLength: 4096, publicExponent: new Uint8Array([1,0,1]) };
const RSA_OAEP = { name: "RSA-OAEP", hash: "SHA-256", modulusLength: 4096, publicExponent: new Uint8Array([1,0,1]) };

export async function generateKeypair() {
  const { publicKey, privateKey } = await crypto.subtle.generateKey(RSA_PSS, true, ["sign", "verify"]);
  const pubPem = await exportPem(publicKey, "public");
  const privPem = await exportPem(privateKey, "private");
  const oaepPub  = await importRsaKey(pubPem,  ["encrypt"], RSA_OAEP);
  const oaepPriv = await importRsaKey(privPem, ["decrypt"], RSA_OAEP);
  const pssPub   = await importRsaKey(pubPem,  ["verify"],  RSA_PSS);
  const pssPriv  = await importRsaKey(privPem, ["sign"],    RSA_PSS);
  return { pubPem, privPem, oaepPub, oaepPriv, pssPub, pssPriv };
}

export async function aesEncrypt(plaintext) {
  const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt","decrypt"]);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv }, key, textEnc.encode(plaintext));
  const rawKey = await crypto.subtle.exportKey("raw", key);
  return { ciphertext: b64u.enc(ct), iv: b64u.enc(iv), rawKey }; 
}

export async function aesDecrypt({ ciphertext, iv, rawKey }) {
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(b64u.dec(iv)) }, key, b64u.dec(ciphertext));
  return pt;
}

export async function aesDecryptText({ ciphertext, iv, rawKey }) {
  const key = await crypto.subtle.importKey("raw", rawKey, { name: "AES-GCM" }, false, ["decrypt"]);
  const pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: new Uint8Array(b64u.dec(iv)) }, key, b64u.dec(ciphertext));
  return textDec.decode(pt);
}

export async function wrapKeyWithRSA_OAEP(receiverPub, rawKey) {
  const wrapped = await crypto.subtle.encrypt({ name: "RSA-OAEP" }, receiverPub, rawKey);
  return b64u.enc(wrapped);
}

export async function unwrapKeyWithRSA_OAEP(myPriv, wrappedB64) {
  const raw = await crypto.subtle.decrypt({ name: "RSA-OAEP" }, myPriv, b64u.dec(wrappedB64));
  return raw;
}

export async function signPSS(priv, bytes) {
  const sig = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, priv, bytes);
  return b64u.enc(sig);
}

export async function verifyPSS(pub, bytes, sigB64) {
  return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pub, b64u.dec(sigB64), bytes);
}

export async function sha256Bytes(...parts) {
  const cat = parts.reduce((acc, p) => {
    const buf = typeof p === "string" ? textEnc.encode(p) : p;
    const out = new Uint8Array(acc.length + buf.length);
    out.set(acc, 0); out.set(buf, acc.length);
    return out;
  }, new Uint8Array());
  return crypto.subtle.digest("SHA-256", cat);
}
