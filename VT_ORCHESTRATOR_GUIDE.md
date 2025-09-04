# VirusTotal Orchestrator Setup and Usage Guide

## Overview

The VirusTotal Orchestrator provides a robust, production-ready solution for interacting with the VirusTotal API with the following features:

- **Multi-key management** with intelligent fallback
- **Rate limit respect** - queues requests instead of overwhelming the API
- **In-memory caching** with TTL (45 minutes default)
- **Request deduplication** - identical concurrent requests share a single API call
- **Exponential backoff** for transient errors
- **Comprehensive observability** with stats and logging

## Environment Variables Setup

Add your VirusTotal API keys to your `.env.local` or `.env` file. The orchestrator supports multiple formats:

### Method 1: Array Format (Recommended - Easy to Manage)

```bash
# Comma-separated array of API keys
VT_API_KEYS=key1-here,key2-here,key3-here,key4-here

# Example with your keys:
VT_API_KEYS=dd9136c086ff1946b50905ab51493e5d5059d61562cfdfa11ffd14bd180f10ea,another-key-here,third-key-here
```

### Method 2: Individual Keys (Backward Compatibility)

```bash
# Primary API key (required)
VT_API_KEY=your-primary-virustotal-api-key-here

# Additional API keys for fallback (optional but recommended)
VT_API_KEY_1=your-second-virustotal-api-key-here
VT_API_KEY_2=your-third-virustotal-api-key-here
VT_API_KEY_3=your-fourth-virustotal-api-key-here
```

### Method 3: Mixed Format (Both Supported)

```bash
# The system will combine keys from both formats and remove duplicates
VT_API_KEYS=key1,key2,key3
VT_API_KEY=key1  # Will be deduplicated
VT_API_KEY_1=key4  # Will be added
```

**Benefits of Array Format:**
- ✅ Easier to read and maintain
- ✅ Simple to add/remove keys
- ✅ No need to remember numbered variables
- ✅ Copy-paste friendly
- ✅ Supports unlimited number of keys

## Usage Examples

### Basic Usage (Backward Compatible)

```typescript
import { vtClient } from '@/lib/vt';

// Legacy method - maintains existing API contract
const result = await vtClient.lookupIOC('malicious-hash', 'hash');
console.log('Malicious detections:', result.data.attributes.last_analysis_stats?.malicious);
```

### Enhanced Usage (New Features)

```typescript
import { vtClient } from '@/lib/vt';

// Enhanced method with full orchestrator features
const result = await vtClient.lookupIOCEnhanced('example.com', 'domain');

if (result.status === 'served_from_cache') {
  console.log('Result served from cache instantly');
} else if (result.status === 'served_live') {
  console.log('Fresh data from VirusTotal API');
} else if (result.status === 'queued_rate_limited') {
  console.log(`Request queued due to rate limits. ETA: ${result.eta}`);
} else if (result.status === 'failed') {
  console.log(`Lookup failed: ${result.error}`);
}

// Access detection summary
if (result.summary) {
  console.log(`Malicious: ${result.summary.malicious}/${result.summary.totalScans}`);
  console.log(`Suspicious: ${result.summary.suspicious}/${result.summary.totalScans}`);
}

// Direct link to VirusTotal results
console.log(`View on VT: ${result.vtLink}`);
```

### Monitoring and Observability

```typescript
import { vtClient } from '@/lib/vt';

// Get comprehensive statistics
const stats = vtClient.getStats();
console.log('VT Client Statistics:', {
  totalRequests: stats.totalRequests,
  cacheHitRatio: (stats.cacheHitRatio * 100).toFixed(1) + '%',
  queueDepth: stats.queueDepth,
  cacheSize: stats.cacheSize,
  failedRequests: stats.failedRequests,
  keyRotations: stats.keyRotations,
});

// Check status of each API key
stats.keysStatus.forEach(key => {
  console.log(`Key ${key.id}: ${key.status} (${key.remaining} requests remaining)`);
});
```

### Manual Cache and Queue Management

```typescript
import { vtClient } from '@/lib/vt';

// Clear cache (useful for testing or forced refresh)
vtClient.clearCache();

// Manually process queued requests (useful in serverless environments)
await vtClient.runQueue();
```

## Rate Limit Behavior

The orchestrator handles rate limits intelligently:

### When Rate Limited (HTTP 429)
1. **Does NOT rotate keys** to push through limits
2. **Puts the key in cooldown** until reset time
3. **Queues the request** for processing when limits reset
4. **Returns immediately** with `status: "queued_rate_limited"` and ETA

### Key Selection Logic
1. Prefers keys with `status: "ok"`
2. Avoids keys in `"cooldown"` or marked `"invalid"`
3. Among available keys, picks the one with most remaining quota
4. Falls back to key with earliest reset time

### Error Handling and Fallback
- **Network errors/timeouts**: Try next key
- **HTTP 5xx errors**: Try next key  
- **HTTP 401/403**: Mark key invalid for 5 minutes, try next key
- **HTTP 404**: Return empty result (not an error)
- **HTTP 429**: Put key in cooldown, queue request

## Cache Behavior

- **TTL**: 45 minutes by default
- **Key format**: `{type}:{normalized_indicator}` (e.g., `domain:example.com`)
- **Normalization**: 
  - Domains/URLs: lowercase
  - Hashes: lowercase
  - IPs: unchanged
- **Automatic cleanup**: Expired entries removed periodically
- **Cache bypass**: Use `forceRefresh: true` option

## Concurrent Request Deduplication

When multiple requests for the same indicator arrive simultaneously:
1. Only one API call is made to VirusTotal
2. All callers wait for the same Promise
3. Result is fanned out to all waiting requests
4. Subsequent requests hit the cache

## Integration with Existing Code

The orchestrator is designed to be a drop-in replacement:

### Before (Old Implementation)
```typescript
const result = await vtClient.lookupIOC(ioc, type);
const malicious = result.data.attributes.last_analysis_stats?.malicious || 0;
```

### After (No Code Changes Required)
The same code works but now benefits from:
- Multi-key fallback
- Rate limit respect
- Caching
- Better error handling

### Enhanced Usage (Optional)
```typescript
const result = await vtClient.lookupIOCEnhanced(ioc, type);
if (result.status === 'served_live' && result.summary) {
  const malicious = result.summary.malicious;
  console.log(`Used key: ${result.keyId}, Rate limit remaining: ${result.rateLimitInfo?.remaining}`);
}
```

## Production Deployment Checklist

1. **API Keys**: Set up multiple VT API keys in environment variables
2. **Monitoring**: Log `vtClient.getStats()` periodically to track performance
3. **Error Handling**: Handle `queued_rate_limited` status appropriately in UI
4. **Queue Processing**: In serverless environments, consider calling `runQueue()` manually
5. **Cache Sizing**: Monitor `cacheSize` and adjust `ttlMs` if needed

## Performance Characteristics

- **Cache Hit**: ~1ms response time
- **First Request**: Full VT API latency (~200-2000ms depending on endpoint)
- **Rate Limited**: Immediate response with queue status
- **Memory Usage**: ~1KB per cached indicator
- **Concurrent Requests**: Deduplicates automatically, single upstream call

## Troubleshooting

### All requests fail with "failed" status
- Check that at least one valid API key is configured
- Verify API keys have remaining quota
- Check network connectivity to virustotal.com

### High queue depth
- Indicates rate limiting across all keys
- Consider adding more API keys
- Review request patterns for optimization opportunities

### Low cache hit ratio
- Indicates requests for different indicators
- Consider pre-warming cache for common indicators
- Review TTL settings (may be too short)

### Key rotation issues
- Check for 401/403 responses (invalid keys)
- Verify API key format and validity
- Monitor `keyRotations` in stats for unusual patterns
