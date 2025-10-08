// Backend encryption module - consistent with frontend
// Uses Web Crypto API to ensure complete consistency between frontend and backend

import { webcrypto } from 'crypto';

// Use Node.js Web Crypto API
const crypto = webcrypto;

// ---------- helpers ----------
const textEnc = new TextEncoder();
const textDec = new TextDecoder();

export const b64u = {
  enc: (buf) => {
    const b64 = Buffer.from(buf).toString('base64');
    return b64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
  },
  dec: (str) => {
    const b64 = str.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((str.length + 3) % 4);
    return Buffer.from(b64, 'base64');
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

// ---------- sign/verify (RSA-PSS) ----------
export async function signPSS(priv, bytes) {
  const sig = await crypto.subtle.sign({ name: "RSA-PSS", saltLength: 32 }, priv, bytes);
  return b64u.enc(sig);
}

export async function verifyPSS(pub, bytes, sigB64) {
  return crypto.subtle.verify({ name: "RSA-PSS", saltLength: 32 }, pub, b64u.dec(sigB64), bytes);
}

// ---------- content hash ----------
export async function sha256Bytes(...parts) {
  const cat = parts.reduce((acc, p) => {
    const buf = typeof p === "string" ? textEnc.encode(p) : p;
    const out = new Uint8Array(acc.length + buf.length);
    out.set(acc, 0); out.set(buf, acc.length);
    return out;
  }, new Uint8Array());
  return crypto.subtle.digest("SHA-256", cat);
}

// ---------- verify content signature ----------
export async function verifyContentSig(payload, pubKeyPem, from, to, ts) {
  // Check if necessary fields exist
  if (!payload.content_sig) {
    console.warn('[WARN] Missing content_sig in payload');
    return false;
  }
  
  if (!payload.ciphertext) {
    console.warn('[WARN] Missing ciphertext in payload');
    return false;
  }

  console.log('[DEBUG] ===== Unified encryption module signature verification =====');
  console.log('[DEBUG] Raw data:');
  console.log('  - ciphertext:', payload.ciphertext.substring(0, 20) + '...');
  console.log('  - iv:', payload.iv);
  console.log('  - tag:', payload.tag);
  console.log('  - from:', from);
  console.log('  - to:', to);
  console.log('  - ts:', ts);

  try {
    console.log('[DEBUG] Raw public key first 100 chars:', pubKeyPem.substring(0, 100));
    console.log('[DEBUG] Raw public key full length:', pubKeyPem.length);
    console.log('[DEBUG] Raw public key contains BEGIN:', pubKeyPem.includes('BEGIN PUBLIC KEY'));
    console.log('[DEBUG] Raw public key contains END:', pubKeyPem.includes('END PUBLIC KEY'));
    
    const publicKey = await importRsaKey(pubKeyPem, ["verify"], { name: "RSA-PSS", hash: "SHA-256" });
    console.log('[DEBUG] Public key imported successfully');
    
    const contentHash = await sha256Bytes(
      textEnc.encode(payload.ciphertext),
      textEnc.encode(payload.iv || ''),
      textEnc.encode(payload.tag || ''),
      textEnc.encode(from),
      textEnc.encode(to),
      textEnc.encode(String(ts))
    );
    
    console.log('[DEBUG] Calculated hash value:', Buffer.from(contentHash).toString('hex'));
    console.log('[DEBUG] Hash length:', contentHash.byteLength);
    console.log('[DEBUG] Signature length:', payload.content_sig.length);
    console.log('[DEBUG] Signature first 50 chars:', payload.content_sig.substring(0, 50));
    
    const parts = [
      textEnc.encode(payload.ciphertext),
      textEnc.encode(payload.iv || ''),
      textEnc.encode(payload.tag || ''),
      textEnc.encode(from),
      textEnc.encode(to),
      textEnc.encode(String(ts))
    ];
    console.log('[DEBUG] Part lengths:', parts.map(p => p.length));
    console.log('[DEBUG] Part first 20 bytes:', parts.map(p => Buffer.from(p).toString('hex', 0, 20)));
    
    console.log('[DEBUG] Starting signature verification...');
    const result = await verifyPSS(publicKey, contentHash, payload.content_sig);
    
    console.log('[DEBUG] Verification result:', result);
    
    if (!result) {
      console.log('[DEBUG] Signature verification failed, possible reasons:');
      console.log('  1. Public key does not match private key');
      console.log('  2. Signature data does not match verification data');
      console.log('  3. Timestamp difference too large');
      console.log('  4. Public key format issue');
    }
    
    return result;
  } catch (err) {
    console.warn('[WARN] Signature verification failed:', err.message);
    return false;
  }
}
