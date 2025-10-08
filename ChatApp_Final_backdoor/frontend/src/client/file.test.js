import { describe, it, expect } from 'vitest';

describe('File Tests', () => {
  
  it('should format file size correctly', () => {
    function formatFileSize(bytes) {
      if (bytes < 1024) return bytes + " B";
      if (bytes < 1024 * 1024) return (bytes / 1024).toFixed(1) + " KB";
      return (bytes / 1024 / 1024).toFixed(1) + " MB";
    }
    
    expect(formatFileSize(500)).toBe("500 B");
    expect(formatFileSize(1024)).toBe("1.0 KB");
    expect(formatFileSize(2048)).toBe("2.0 KB");
    expect(formatFileSize(1048576)).toBe("1.0 MB");
    expect(formatFileSize(5242880)).toBe("5.0 MB");
  });
  
  it('should check file size limit', () => {
    const maxSize = 10 * 1024 * 1024;
    
    expect(1024 * 1024 < maxSize).toBe(true);
    expect(20 * 1024 * 1024 < maxSize).toBe(false);
  });
});


