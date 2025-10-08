import { describe, it, expect } from 'vitest';
import {
  generateKeypair,
  aesEncrypt,
  aesDecrypt,
  signPSS,
  verifyPSS,
  wrapKeyWithRSA_OAEP,
  unwrapKeyWithRSA_OAEP,
  sha256Bytes
} from './e2ee.js';

describe('E2EE Crypto Functions', () => {
  
  it('should encrypt and decrypt with AES-GCM', async () => {
    const plaintext = "Hello, World!";
    
    const { ciphertext, iv, rawKey } = await aesEncrypt(plaintext);
    
    expect(ciphertext).toBeDefined();
    expect(iv).toBeDefined();
    expect(rawKey).toBeDefined();
    
    const decrypted = await aesDecrypt({ ciphertext, iv, rawKey });
    
    expect(decrypted).toBe(plaintext);
  });
  
  it('should generate RSA keypair', async () => {
    const kp = await generateKeypair();
    
    expect(kp.pubPem).toBeDefined();
    expect(kp.privPem).toBeDefined();
    expect(kp.pubPem).toContain('BEGIN PUBLIC KEY');
    expect(kp.privPem).toContain('BEGIN PRIVATE KEY');
  });
  
  it('should sign and verify with RSA-PSS', async () => {
    const kp = await generateKeypair();
    const message = new TextEncoder().encode("test message");
    
    const signature = await signPSS(kp.pssPriv, message);
    expect(signature).toBeDefined();
    
    const valid = await verifyPSS(kp.pssPub, message, signature);
    expect(valid).toBe(true);
    
    const wrongMessage = new TextEncoder().encode("wrong message");
    const invalid = await verifyPSS(kp.pssPub, wrongMessage, signature);
    expect(invalid).toBe(false);
  });
  
  it('should wrap and unwrap AES key with RSA-OAEP', async () => {
    const kp = await generateKeypair();
    
    const aesKey = crypto.getRandomValues(new Uint8Array(32));
    
    const wrapped = await wrapKeyWithRSA_OAEP(kp.oaepPub, aesKey);
    expect(wrapped).toBeDefined();
    
    const unwrapped = await unwrapKeyWithRSA_OAEP(kp.oaepPriv, wrapped);
    expect(new Uint8Array(unwrapped)).toEqual(new Uint8Array(aesKey));
  });
  
  it('should hash content with SHA-256', async () => {
    const data1 = new TextEncoder().encode("hello");
    const data2 = new TextEncoder().encode("world");
    
    const hash = await sha256Bytes(data1, data2);
    
    expect(hash).toBeDefined();
    expect(hash.byteLength).toBe(32);
  });
  
  it('should produce different ciphertexts for same plaintext', async () => {
    const plaintext = "same message";
    
    const enc1 = await aesEncrypt(plaintext);
    const enc2 = await aesEncrypt(plaintext);
    
    expect(enc1.iv).not.toBe(enc2.iv);
    expect(enc1.ciphertext).not.toBe(enc2.ciphertext);
    
    const dec1 = await aesDecrypt(enc1);
    const dec2 = await aesDecrypt(enc2);
    
    expect(dec1).toBe(plaintext);
    expect(dec2).toBe(plaintext);
  });
});

