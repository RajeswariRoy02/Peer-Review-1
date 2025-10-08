import crypto, { createSign, createVerify } from 'crypto';
import { serverPrivKey } from '../state/tables.js';
import { verifyContentSig as verifyContentSigWebCrypto } from '../crypto/e2ee.js';

async function sha256Bytes(...dataParts) {
  const concatenatedData = dataParts.reduce((accumulator, part) => {
    const buffer = typeof part === "string" ? new TextEncoder().encode(part) : part;
    const output = new Uint8Array(accumulator.length + buffer.length);
    output.set(accumulator, 0); output.set(buffer, accumulator.length);
    return output;
  }, new Uint8Array());
  return crypto.subtle.digest("SHA-256", concatenatedData);
}

async function importRsaKey(pemString, keyUsages, algorithm) {
  const rawKey = pemString.replace(/-----BEGIN [^-]+-----|-----END [^-]+-----|\s/g, "");
  const derBuffer = Buffer.from(rawKey, 'base64');
  return crypto.subtle.importKey(
    pemString.includes("PUBLIC KEY") ? "spki" : "pkcs8",
    derBuffer,
    algorithm,
    true,
    keyUsages
  );
}

export function signPayload(payload) {
  const jsonString = JSON.stringify(payload, Object.keys(payload).sort());

  const signatureCreator = createSign('RSA-SHA256');
  signatureCreator.update(jsonString);
  signatureCreator.end();

  const paddingMode = crypto.constants?.RSA_PKCS1_PSS_PADDING ?? 6;

  const signature = signatureCreator.sign({
    key: serverPrivKey,
    padding: paddingMode,
    saltLength: 32,
  });

  return toBase64Url(signature);
}

export function verifySignature(payload, signatureBase64Url, publicKeyPem) {
  const jsonString = JSON.stringify(payload, Object.keys(payload).sort());

  const signatureVerifier = createVerify('RSA-SHA256');
  signatureVerifier.update(jsonString);
  signatureVerifier.end();

  const paddingMode = crypto.constants?.RSA_PKCS1_PSS_PADDING ?? 6;

  const signatureBuffer = Buffer.from(
    signatureBase64Url.replace(/-/g, '+').replace(/_/g, '/'),
    'base64'
  );

  return signatureVerifier.verify(
    {
      key: publicKeyPem,
      padding: paddingMode,
      saltLength: 32,
    },
    signatureBuffer
  );
}

export async function verifyContentSig(payload, pubKeyPem, from, to, ts) {
  if (!payload.content_sig || !payload.ciphertext) {
    return false;
  }

  const crypto = await import('crypto');
  
  const parts = [
    Buffer.from(payload.ciphertext, 'utf8'),
    Buffer.from(payload.iv || '', 'utf8'),
    Buffer.from(payload.tag || '', 'utf8'),
    Buffer.from(from, 'utf8'),
    Buffer.from(to, 'utf8'),
    Buffer.from(String(ts), 'utf8')
  ];
  
  const concatenated = Buffer.concat(parts);

  try {
    const sig = Buffer.from(
      payload.content_sig.replace(/-/g, '+').replace(/_/g, '/'),
      'base64'
    );

    let publicKeyPem = pubKeyPem;
    if (!pubKeyPem.includes('BEGIN PUBLIC KEY')) {
      const base64 = pubKeyPem.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((pubKeyPem.length + 3) % 4);
      publicKeyPem = `-----BEGIN PUBLIC KEY-----\n${base64.match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`;
    }
    
    const hash = crypto.createHash('sha256').update(concatenated).digest();
    const verifier = crypto.createVerify('RSA-PSS');
    verifier.update(hash);
    
    const result = verifier.verify(
      {
        key: publicKeyPem,
        padding: crypto.constants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      },
      sig
    );
    
    return result;
  } catch (err) {
    return false;
  }
}

export async function verifyFileSig(payload, pubKeyPem, from, to, ts) {
  if (!payload.file_sig || !payload.file_id) {
    return false;
  }

  const crypto = await import('crypto');
  
  const fileMetadata = JSON.stringify({
    fileId: payload.file_id,
    fileName: payload.filename,
    fileSize: payload.filesize,
    mimeType: payload.mime_type,
    ts: ts
  });
  
  const parts = [
    Buffer.from(fileMetadata, 'utf8'),
    Buffer.from(payload.ciphertext, 'utf8'),
    Buffer.from(payload.iv, 'utf8')
  ];
  
  const concatenated = Buffer.concat(parts);
  const hash = crypto.createHash('sha256').update(concatenated).digest();

  try {
    const sig = Buffer.from(
      payload.file_sig.replace(/-/g, '+').replace(/_/g, '/'),
      'base64'
    );

    const publicKey = await importRsaKey(pubKeyPem, ["verify"], { name: "RSA-PSS", hash: "SHA-256" });
    
    const result = await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      publicKey,
      sig,
      hash
    );
    
    return result;
  } catch (err) {
    return false;
  }
}

export async function verifyChunkSig(payload, pubKeyPem, from, to, ts) {
  if (!payload.chunk_sig || !payload.file_id) {
    return false;
  }

  const chunkHash = await sha256Bytes(
    new TextEncoder().encode(payload.file_id),
    new TextEncoder().encode(String(payload.chunk_index))
  );
  
  try {
    const sig = Buffer.from(
      payload.chunk_sig.replace(/-/g, '+').replace(/_/g, '/'),
      'base64'
    );
    
    const publicKey = await importRsaKey(pubKeyPem, ["verify"], { name: "RSA-PSS", hash: "SHA-256" });
    
    const result = await crypto.subtle.verify(
      { name: "RSA-PSS", saltLength: 32 },
      publicKey,
      sig,
      chunkHash
    );
    
    return result;
  } catch (err) {
    return false;
  }
}

export function toBase64Url(buf) {
  return buf.toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

// Use unified encryption module verification function
export async function verifyContentSigUnified(payload, pubKeyPem, from, to, ts) {
  return await verifyContentSigWebCrypto(payload, pubKeyPem, from, to, ts);
}
