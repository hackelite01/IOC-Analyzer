import { describe, it, expect } from '@jest/globals';
import { detectIOCType, normalizeIOC, validateIOCList } from '@/lib/detect';

describe('IOC Detection', () => {
  describe('detectIOCType', () => {
    it('should detect IP addresses', () => {
      expect(detectIOCType('192.168.1.1')).toBe('ip');
      expect(detectIOCType('8.8.8.8')).toBe('ip');
      expect(detectIOCType('2001:4860:4860::8888')).toBe('ip');
    });

    it('should detect domains', () => {
      expect(detectIOCType('example.com')).toBe('domain');
      expect(detectIOCType('malware.test.org')).toBe('domain');
      expect(detectIOCType('sub.domain.co.uk')).toBe('domain');
    });

    it('should detect URLs', () => {
      expect(detectIOCType('http://example.com')).toBe('url');
      expect(detectIOCType('https://malware.test.org/path')).toBe('url');
    });

    it('should detect hashes', () => {
      expect(detectIOCType('d41d8cd98f00b204e9800998ecf8427e')).toBe('hash'); // MD5
      expect(detectIOCType('da39a3ee5e6b4b0d3255bfef95601890afd80709')).toBe('hash'); // SHA1
      expect(detectIOCType('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')).toBe('hash'); // SHA256
    });
  });

  describe('normalizeIOC', () => {
    it('should normalize domains', () => {
      expect(normalizeIOC('EXAMPLE.COM', 'domain')).toBe('example.com');
      expect(normalizeIOC('http://example.com', 'domain')).toBe('example.com');
    });

    it('should normalize hashes', () => {
      expect(normalizeIOC('D41D8CD98F00B204E9800998ECF8427E', 'hash')).toBe('d41d8cd98f00b204e9800998ecf8427e');
    });

    it('should preserve URLs', () => {
      expect(normalizeIOC('HTTP://EXAMPLE.COM/path', 'url')).toBe('HTTP://EXAMPLE.COM/path');
    });
  });

  describe('validateIOCList', () => {
    it('should validate a list of mixed IOCs', () => {
      const iocs = [
        '8.8.8.8',
        'example.com',
        'http://test.com',
        'd41d8cd98f00b204e9800998ecf8427e',
        '', // empty
        'invalid..domain'
      ];

      const result = validateIOCList(iocs);
      
      expect(result.valid).toHaveLength(4);
      expect(result.invalid).toHaveLength(2);
    });
  });
});
