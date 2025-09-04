# VirusTotal API Keys - Array Format Examples

## Super Easy Multi-Key Setup 🎯

Just add your keys separated by commas - no need to remember numbered variables!

### Single Key
```bash
VT_API_KEYS=dd9136c086ff1946b50905ab51493e5d5059d61562cfdfa11ffd14bd180f10ea
```

### Multiple Keys (Copy-Paste Friendly)
```bash
VT_API_KEYS=key1-here,key2-here,key3-here,key4-here,key5-here
```

### Real Example with Your Key + More
```bash
VT_API_KEYS=dd9136c086ff1946b50905ab51493e5d5059d61562cfdfa11ffd14bd180f10ea,second-api-key-here,third-api-key-here
```

## Benefits vs Old Method ✨

### ❌ Old Way (Tedious)
```bash
VT_API_KEY=key1
VT_API_KEY_1=key2
VT_API_KEY_2=key3
VT_API_KEY_3=key4
VT_API_KEY_4=key5  # What was the next number again?
```

### ✅ New Way (Simple)
```bash
VT_API_KEYS=key1,key2,key3,key4,key5,key6,key7,key8,key9,key10
```

## Features

- **No Limits**: Add as many keys as you want
- **Auto-Deduplication**: Same key multiple times? No problem, it's filtered out
- **Backward Compatible**: Old `VT_API_KEY` variables still work
- **Mixed Support**: Can use both formats together
- **Copy-Paste Friendly**: Easy to share configurations
- **Space Tolerant**: Spaces around commas are automatically trimmed

## Usage in Code

```typescript
// The orchestrator automatically detects your setup:
const stats = vtClient.getStats();
console.log(`Using ${stats.keysStatus.length} API keys`);
console.log(`Active keys: ${stats.keysStatus.filter(k => k.status === 'ok').length}`);

// Each key gets a masked ID for logging:
stats.keysStatus.forEach(key => {
  console.log(`Key ${key.id}: ${key.status} (${key.remaining} remaining)`);
});
```

## Quick Start Guide

1. **Add your keys to .env:**
   ```bash
   VT_API_KEYS=your-first-key,your-second-key,your-third-key
   ```

2. **That's it!** The orchestrator will:
   - Load all keys automatically
   - Use them for fallback and load balancing  
   - Respect rate limits across all keys
   - Cache results for 45 minutes
   - Handle errors gracefully

3. **Monitor performance:**
   ```bash
   # Check logs for key usage
   [VT-Client] Initialized with 3 API key(s)
   [VT-Orchestrator] Making request using key abcd1234...
   ```

Perfect for production deployments with multiple VirusTotal API subscriptions! 🚀
