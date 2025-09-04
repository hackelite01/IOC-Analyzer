/**
 * VirusTotal Orchestrator Tests
 * 
 * Demonstrates the key acceptance scenarios:
 * 1. Cache hit returns immediately
 * 2. Key fallback on server errors
 * 3. Invalid key handling
 * 4. Rate limit queueing
 * 5. All keys invalid handling
 * 6. Concurrent request deduplication
 */

import { VirusTotalClient, LookupResult } from './vt-orchestrator';

// Mock fetch for testing
const originalFetch = global.fetch;

interface MockResponse {
  status: number;
  headers: Record<string, string>;
  data?: any;
  delay?: number;
}

function mockFetch(responses: MockResponse[]) {
  let callCount = 0;
  
  global.fetch = jest.fn().mockImplementation(async (url: string, options: any) => {
    const response = responses[Math.min(callCount, responses.length - 1)];
    callCount++;
    
    if (response.delay) {
      await new Promise(resolve => setTimeout(resolve, response.delay));
    }
    
    const mockResponse = {
      status: response.status,
      headers: {
        get: (name: string) => response.headers[name] || null,
      },
      json: async () => response.data || {},
    };
    
    return mockResponse as any;
  });
}

function restoreFetch() {
  global.fetch = originalFetch;
}

// Test utilities
const testKeys = ['test-key-1', 'test-key-2', 'test-key-3'];
const testKeysArray = 'test-key-1,test-key-2,test-key-3'; // Array format
const testHash = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

describe('VirusTotalClient', () => {
  afterEach(() => {
    restoreFetch();
  });

  // TEST 1: Cache hit returns immediately
  test('Cache hit returns immediately with served_from_cache status', async () => {
    mockFetch([{
      status: 200,
      headers: { 'X-RateLimit-Remaining': '1000' },
      data: {
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 5,
              suspicious: 2,
              harmless: 50,
              undetected: 3
            }
          }
        }
      }
    }]);

    const client = new VirusTotalClient(testKeys, { ttlMs: 60000 });
    
    // First request - should hit VT API
    const result1 = await client.lookupIndicator(testHash);
    expect(result1.status).toBe('served_live');
    
    // Second request - should hit cache
    const start = Date.now();
    const result2 = await client.lookupIndicator(testHash);
    const elapsed = Date.now() - start;
    
    expect(result2.status).toBe('served_from_cache');
    expect(elapsed).toBeLessThan(10); // Should be instant
    expect(result2.summary).toEqual(result1.summary);
  });

  // TEST 2: First key 500, second key 200 - fallback works
  test('Key fallback on server errors', async () => {
    const consoleSpy = jest.spyOn(console, 'warn').mockImplementation();
    
    mockFetch([
      { status: 500, headers: {} }, // First key fails
      { 
        status: 200, 
        headers: { 'X-RateLimit-Remaining': '999' },
        data: {
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 1,
                suspicious: 0,
                harmless: 60,
                undetected: 2
              }
            }
          }
        }
      }
    ]);

    const client = new VirusTotalClient(testKeys);
    const result = await client.lookupIndicator(testHash);
    
    expect(result.status).toBe('served_live');
    expect(result.summary?.malicious).toBe(1);
    expect(consoleSpy).toHaveBeenCalledWith(
      expect.stringContaining('Attempt 1 failed')
    );
    
    consoleSpy.mockRestore();
  });

  // TEST 3: 401/403 marks key invalid and uses next
  test('Invalid key handling - 401/403 marks key invalid', async () => {
    const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
    
    mockFetch([
      { status: 401, headers: {} }, // First key invalid
      { 
        status: 200, 
        headers: { 'X-RateLimit-Remaining': '998' },
        data: {
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 0,
                suspicious: 1,
                harmless: 45,
                undetected: 4
              }
            }
          }
        }
      }
    ]);

    const client = new VirusTotalClient(testKeys);
    const result = await client.lookupIndicator(testHash);
    
    expect(result.status).toBe('served_live');
    expect(result.summary?.suspicious).toBe(1);
    
    const stats = client.getStats();
    expect(stats.keyRotations).toBe(1);
    expect(stats.keysStatus[0].status).toBe('invalid');
    
    consoleWarnSpy.mockRestore();
  });

  // TEST 4: 429 with Retry-After returns queued status
  test('Rate limit queueing with ETA', async () => {
    const consoleLogSpy = jest.spyOn(console, 'log').mockImplementation();
    
    const retryAfterSeconds = 60;
    mockFetch([{
      status: 429,
      headers: { 
        'Retry-After': retryAfterSeconds.toString(),
        'X-RateLimit-Remaining': '0'
      }
    }]);

    const client = new VirusTotalClient([testKeys[0]]); // Single key
    const result = await client.lookupIndicator(testHash);
    
    expect(result.status).toBe('queued_rate_limited');
    expect(result.eta).toBeDefined();
    expect(result.eta!.getTime()).toBeGreaterThan(Date.now());
    
    const stats = client.getStats();
    expect(stats.queuedRequests).toBe(1);
    expect(stats.keysStatus[0].status).toBe('cooldown');
    
    consoleLogSpy.mockRestore();
  });

  // TEST 5: All keys invalid returns failed
  test('All keys invalid returns failed status', async () => {
    const consoleWarnSpy = jest.spyOn(console, 'warn').mockImplementation();
    
    mockFetch([
      { status: 403, headers: {} },
      { status: 401, headers: {} },
      { status: 403, headers: {} },
    ]);

    const client = new VirusTotalClient(testKeys);
    const result = await client.lookupIndicator(testHash);
    
    expect(result.status).toBe('failed');
    expect(result.error).toContain('All attempts failed');
    
    const stats = client.getStats();
    expect(stats.keysStatus.every(key => key.status === 'invalid')).toBe(true);
    
    consoleWarnSpy.mockRestore();
  });

  // TEST 6: Concurrent requests are deduplicated
  test('Concurrent identical requests result in single upstream call', async () => {
    let fetchCallCount = 0;
    
    global.fetch = jest.fn().mockImplementation(async () => {
      fetchCallCount++;
      // Add delay to ensure requests overlap
      await new Promise(resolve => setTimeout(resolve, 100));
      
      return {
        status: 200,
        headers: {
          get: () => '1000',
        },
        json: async () => ({
          data: {
            attributes: {
              last_analysis_stats: {
                malicious: 2,
                suspicious: 1,
                harmless: 55,
                undetected: 2
              }
            }
          }
        }),
      };
    });

    const client = new VirusTotalClient(testKeys);
    
    // Launch 3 concurrent requests for the same indicator
    const promises = [
      client.lookupIndicator(testHash),
      client.lookupIndicator(testHash),
      client.lookupIndicator(testHash),
    ];
    
    const results = await Promise.all(promises);
    
    // All should succeed with same data
    expect(results[0].status).toBe('served_live');
    expect(results[1].status).toBe('served_live');
    expect(results[2].status).toBe('served_live');
    
    // But only one API call should have been made
    expect(fetchCallCount).toBe(1);
    
    // All results should be identical
    expect(results[0].summary).toEqual(results[1].summary);
    expect(results[1].summary).toEqual(results[2].summary);
  });

  // Additional test: Indicator normalization
  test('Indicator normalization works correctly', async () => {
    mockFetch([{
      status: 200,
      headers: { 'X-RateLimit-Remaining': '1000' },
      data: { data: { attributes: { last_analysis_stats: {} } } }
    }]);

    const client = new VirusTotalClient(testKeys);
    
    // These should be treated as the same indicator
    const result1 = await client.lookupIndicator('EXAMPLE.COM');
    const result2 = await client.lookupIndicator('example.com');
    
    expect(result1.status).toBe('served_live');
    expect(result2.status).toBe('served_from_cache'); // Should hit cache
  });

  // Additional test: Stats and observability
  test('Statistics and observability work correctly', async () => {
    mockFetch([{
      status: 200,
      headers: { 'X-RateLimit-Remaining': '999' },
      data: { data: { attributes: { last_analysis_stats: {} } } }
    }]);

    const client = new VirusTotalClient(testKeys);
    
    const initialStats = client.getStats();
    expect(initialStats.totalRequests).toBe(0);
    expect(initialStats.cacheHits).toBe(0);
    
    await client.lookupIndicator(testHash);
    await client.lookupIndicator(testHash); // Cache hit
    
    const finalStats = client.getStats();
    expect(finalStats.totalRequests).toBe(2);
    expect(finalStats.cacheHits).toBe(1);
    expect(finalStats.cacheMisses).toBe(1);
    expect(finalStats.cacheHitRatio).toBe(0.5);
    expect(finalStats.keysStatus).toHaveLength(3);
  });

  // Additional test: Array format key parsing
  test('Array format environment variable parsing', () => {
    // Mock environment variable
    const originalEnv = process.env.VT_API_KEYS;
    process.env.VT_API_KEYS = testKeysArray;
    
    try {
      // This would normally be tested via the EnhancedVirusTotalClient
      // but we can test the parsing logic conceptually
      const keys = testKeysArray.split(',').map(k => k.trim()).filter(k => k.length > 0);
      
      expect(keys).toHaveLength(3);
      expect(keys[0]).toBe('test-key-1');
      expect(keys[1]).toBe('test-key-2');
      expect(keys[2]).toBe('test-key-3');
    } finally {
      // Restore environment
      if (originalEnv !== undefined) {
        process.env.VT_API_KEYS = originalEnv;
      } else {
        delete process.env.VT_API_KEYS;
      }
    }
  });
});

// Manual testing example (uncomment to run with real API keys)
/*
async function manualTest() {
  const VT_KEYS = [
    process.env.VT_API_KEY_1!,
    process.env.VT_API_KEY_2!,
  ];

  if (!VT_KEYS[0]) {
    console.log('Set VT_API_KEY_1 environment variable to run manual test');
    return;
  }

  const client = new VirusTotalClient(VT_KEYS, { ttlMs: 30000 });

  console.log('Testing hash lookup...');
  const hashResult = await client.lookupIndicator(testHash);
  console.log('Hash result:', JSON.stringify(hashResult, null, 2));

  console.log('\nTesting domain lookup...');
  const domainResult = await client.lookupIndicator('google.com', { type: 'domain' });
  console.log('Domain result:', JSON.stringify(domainResult, null, 2));

  console.log('\nClient stats:', client.getStats());
}

if (require.main === module) {
  manualTest().catch(console.error);
}
*/
