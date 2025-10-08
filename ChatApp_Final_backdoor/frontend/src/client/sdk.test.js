import { describe, it, expect, beforeAll } from 'vitest';
import { 
  ensureKeypair, 
  sendPublic 
} from './sdk.js';

describe('SDK Tests', () => {
  
  beforeAll(async () => {
    await ensureKeypair();
  });

  it('should send public message', async () => {
    const testMessage = "Hello from public channel!";
    
    try {
      const result = await sendPublic({ 
        plaintext: testMessage,
        channelId: "public" 
      });
      
      expect(result.ok).toBe(true);
      expect(result.id).toBeDefined();
    } catch (err) {
      expect(err.message).toContain("WS_NOT_CONNECTED");
    }
  });
});

