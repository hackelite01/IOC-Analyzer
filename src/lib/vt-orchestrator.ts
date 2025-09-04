/**
 * VirusTotal Orchestrator with Multi-Key Fallback and Rate Limit Respect
 * 
 * A production-ready VirusTotal API client that:
 * - Uses multiple API keys with intelligent fallback
 * - Respects rate limits and queues requests when needed
 * - Provides in-memory caching with TTL
 * - Deduplicates concurrent identical requests
 * - Handles errors gracefully with exponential backoff
 * - Never logs sensitive API keys
 */

// ============================================================================
// TYPES & INTERFACES
// ============================================================================

export type IndicatorType = "hash" | "url" | "ip" | "domain";

export type KeyStatus = "ok" | "cooldown" | "invalid";

export interface ApiKey {
  id: string; // First 8 chars of key for logging (never the full key)
  key: string; // Full API key
  status: KeyStatus;
  remaining?: number; // Remaining quota
  resetAt?: Date; // When quota resets
  lastError?: string; // Last error message
}

export interface RateLimitInfo {
  remaining?: number;
  resetAt?: Date;
  retryAfter?: number; // Seconds
}

export interface LookupResult {
  status: "served_from_cache" | "served_live" | "queued_rate_limited" | "failed";
  indicator: string;
  summary?: {
    malicious: number;
    suspicious: number;
    clean: number;
    undetected: number;
    totalScans: number;
  };
  vtLink?: string;
  keyId?: string;
  rateLimitInfo?: RateLimitInfo;
  eta?: Date; // When queued request will be processed
  error?: string;
}

export interface LookupOptions {
  type?: IndicatorType;
  forceRefresh?: boolean; // Skip cache
}

interface CacheEntry {
  data: any;
  expiresAt: Date;
  indicator: string;
}

interface QueuedRequest {
  indicator: string;
  type: IndicatorType;
  resolve: (result: LookupResult) => void;
  reject: (error: Error) => void;
  queuedAt: Date;
}

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * Normalizes indicators for consistent caching and deduplication
 */
function normalizeIndicator(indicator: string, type?: IndicatorType): { normalized: string; detectedType: IndicatorType } {
  const trimmed = indicator.trim();
  
  // Auto-detect type if not provided
  let detectedType: IndicatorType;
  
  if (type) {
    detectedType = type;
  } else {
    // Hash detection (MD5: 32, SHA1: 40, SHA256: 64, SHA512: 128)
    if (/^[a-fA-F0-9]{32}$|^[a-fA-F0-9]{40}$|^[a-fA-F0-9]{64}$|^[a-fA-F0-9]{128}$/.test(trimmed)) {
      detectedType = "hash";
    }
    // URL detection
    else if (/^https?:\/\//.test(trimmed)) {
      detectedType = "url";
    }
    // IP detection (simplified IPv4)
    else if (/^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(trimmed)) {
      detectedType = "ip";
    }
    // Default to domain
    else {
      detectedType = "domain";
    }
  }
  
  // Normalize based on type
  switch (detectedType) {
    case "hash":
      return { normalized: trimmed.toLowerCase(), detectedType };
    case "domain":
      return { normalized: trimmed.toLowerCase(), detectedType };
    case "ip":
      return { normalized: trimmed, detectedType };
    case "url":
      // Basic URL normalization - remove trailing slashes, lowercase domain
      try {
        const url = new URL(trimmed);
        url.hostname = url.hostname.toLowerCase();
        return { normalized: url.toString(), detectedType };
      } catch {
        return { normalized: trimmed.toLowerCase(), detectedType };
      }
    default:
      return { normalized: trimmed.toLowerCase(), detectedType };
  }
}

/**
 * Generates exponential backoff delay with jitter
 */
function calculateBackoff(attempt: number, maxDelayMs = 30000): number {
  const baseDelay = Math.min(1000 * Math.pow(2, attempt), maxDelayMs);
  const jitter = Math.random() * 0.1 * baseDelay; // 10% jitter
  return Math.floor(baseDelay + jitter);
}

/**
 * Sleep utility for delays
 */
function sleep(ms: number): Promise<void> {
  return new Promise(resolve => setTimeout(resolve, ms));
}

/**
 * Masks API key for logging (shows only first 8 characters)
 */
function maskApiKey(key: string): string {
  return key.length > 8 ? `${key.substring(0, 8)}...` : key;
}

// ============================================================================
// VIRUSTOTAL CLIENT IMPLEMENTATION
// ============================================================================

export class VirusTotalClient {
  private readonly keys: ApiKey[];
  private readonly cache = new Map<string, CacheEntry>();
  private readonly inFlightRequests = new Map<string, Promise<LookupResult>>();
  private readonly requestQueue: QueuedRequest[] = [];
  private readonly ttlMs: number;
  private queueProcessorRunning = false;
  
  // Observability counters
  private stats = {
    cacheHits: 0,
    cacheMisses: 0,
    totalRequests: 0,
    queuedRequests: 0,
    failedRequests: 0,
    keyRotations: 0,
  };

  constructor(apiKeys: string[], options: { ttlMs?: number } = {}) {
    if (!apiKeys || apiKeys.length === 0) {
      throw new Error("At least one VirusTotal API key is required");
    }

    this.keys = apiKeys.map(key => ({
      id: maskApiKey(key),
      key,
      status: "ok" as KeyStatus,
    }));

    this.ttlMs = options.ttlMs || 45 * 60 * 1000; // 45 minutes default
    
    console.log(`[VT-Orchestrator] Initialized with ${this.keys.length} API keys, TTL: ${this.ttlMs / 1000}s`);
  }

  /**
   * Main lookup method - handles caching, deduplication, and rate limiting
   */
  async lookupIndicator(indicator: string, options: LookupOptions = {}): Promise<LookupResult> {
    const { normalized, detectedType } = normalizeIndicator(indicator, options.type);
    const cacheKey = `${detectedType}:${normalized}`;
    
    this.stats.totalRequests++;
    
    // Check cache first (unless force refresh)
    if (!options.forceRefresh) {
      const cached = this._getCached(cacheKey);
      if (cached) {
        this.stats.cacheHits++;
        console.log(`[VT-Orchestrator] Cache hit for ${detectedType}:${normalized.substring(0, 20)}...`);
        return {
          status: "served_from_cache",
          indicator: normalized,
          summary: this._parseVTResponse(cached.data),
          vtLink: this._generateVTLink(normalized, detectedType),
        };
      }
    }
    
    this.stats.cacheMisses++;
    
    // Check if request is already in flight
    const existingRequest = this.inFlightRequests.get(cacheKey);
    if (existingRequest) {
      console.log(`[VT-Orchestrator] Deduplicating concurrent request for ${cacheKey}`);
      return existingRequest;
    }
    
    // Create new request promise
    const requestPromise = this._executeRequest(normalized, detectedType);
    this.inFlightRequests.set(cacheKey, requestPromise);
    
    try {
      const result = await requestPromise;
      return result;
    } finally {
      // Clean up in-flight tracking
      this.inFlightRequests.delete(cacheKey);
    }
  }

  /**
   * Executes the actual VT API request with fallback and rate limiting
   */
  private async _executeRequest(indicator: string, type: IndicatorType): Promise<LookupResult> {
    const maxAttempts = 3;
    let lastError: string = "";
    
    for (let attempt = 0; attempt < maxAttempts; attempt++) {
      try {
        const key = this._pickAvailableKey();
        
        if (!key) {
          // All keys unavailable - queue the request
          return this._queueRequest(indicator, type);
        }
        
        const result = await this._makeVTRequest(indicator, type, key);
        
        // Cache successful results
        if (result.status === "served_live" && result.summary) {
          const cacheKey = `${type}:${indicator}`;
          this._setCached(cacheKey, result.summary);
        }
        
        return result;
        
      } catch (error) {
        lastError = error instanceof Error ? error.message : String(error);
        console.warn(`[VT-Orchestrator] Attempt ${attempt + 1} failed: ${lastError}`);
        
        if (attempt < maxAttempts - 1) {
          const delayMs = calculateBackoff(attempt);
          console.log(`[VT-Orchestrator] Backing off for ${delayMs}ms before retry`);
          await sleep(delayMs);
        }
      }
    }
    
    this.stats.failedRequests++;
    return {
      status: "failed",
      indicator,
      error: `All attempts failed. Last error: ${lastError}`,
    };
  }

  /**
   * Makes the actual HTTP request to VirusTotal API
   */
  private async _makeVTRequest(indicator: string, type: IndicatorType, key: ApiKey): Promise<LookupResult> {
    const endpoint = this._getEndpoint(indicator, type);
    const url = `https://www.virustotal.com/api/v3${endpoint}`;
    
    console.log(`[VT-Orchestrator] Making request to VT for ${type}:${indicator.substring(0, 20)}... using key ${key.id}`);
    
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 30000); // 30s timeout
    
    try {
      const response = await fetch(url, {
        method: 'GET',
        headers: {
          'x-apikey': key.key,
          'User-Agent': 'IOC-Analyzer-Pro/1.0',
        },
        signal: controller.signal,
      });
      
      clearTimeout(timeoutId);
      
      // Update key state from response headers
      this._updateKeyStateFromHeaders(key, response);
      
      // Handle different response codes
      if (response.status === 200) {
        const data = await response.json();
        return {
          status: "served_live",
          indicator,
          summary: this._parseVTResponse(data),
          vtLink: this._generateVTLink(indicator, type),
          keyId: key.id,
          rateLimitInfo: this._extractRateLimitInfo(response),
        };
      }
      
      if (response.status === 429) {
        // Rate limited - put key in cooldown and queue request
        this._handleRateLimit(key, response);
        return this._queueRequest(indicator, type);
      }
      
      if (response.status === 401 || response.status === 403) {
        // Invalid key - mark as invalid
        this._markKeyInvalid(key, `HTTP ${response.status}`);
        this.stats.keyRotations++;
        throw new Error(`Key ${key.id} marked invalid: HTTP ${response.status}`);
      }
      
      if (response.status === 404) {
        // Not found - return empty result but don't cache
        return {
          status: "served_live",
          indicator,
          summary: { malicious: 0, suspicious: 0, clean: 0, undetected: 0, totalScans: 0 },
          vtLink: this._generateVTLink(indicator, type),
          keyId: key.id,
        };
      }
      
      if (response.status >= 500) {
        throw new Error(`Server error: HTTP ${response.status}`);
      }
      
      throw new Error(`Unexpected response: HTTP ${response.status}`);
      
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof Error && error.name === 'AbortError') {
        throw new Error('Request timeout');
      }
      
      throw error;
    }
  }

  /**
   * Picks the best available API key
   */
  private _pickAvailableKey(): ApiKey | null {
    const now = new Date();
    const availableKeys = this.keys.filter(key => {
      if (key.status === "invalid") return false;
      if (key.status === "cooldown" && key.resetAt && now < key.resetAt) return false;
      return true;
    });
    
    if (availableKeys.length === 0) {
      return null;
    }
    
    // Pick key with most remaining quota, or earliest reset time
    return availableKeys.sort((a, b) => {
      if (a.remaining !== undefined && b.remaining !== undefined) {
        return b.remaining - a.remaining; // Most remaining first
      }
      if (a.resetAt && b.resetAt) {
        return a.resetAt.getTime() - b.resetAt.getTime(); // Earliest reset first
      }
      return 0;
    })[0];
  }

  /**
   * Updates key state based on response headers
   */
  private _updateKeyStateFromHeaders(key: ApiKey, response: Response): void {
    const remaining = response.headers.get('X-RateLimit-Remaining');
    const reset = response.headers.get('X-RateLimit-Reset');
    
    if (remaining) {
      key.remaining = parseInt(remaining, 10);
    }
    
    if (reset) {
      key.resetAt = new Date(parseInt(reset, 10) * 1000);
    }
    
    // Reset status if was in cooldown and quota available
    if (key.status === "cooldown" && key.remaining && key.remaining > 0) {
      key.status = "ok";
    }
  }

  /**
   * Handles rate limit response by putting key in cooldown
   */
  private _handleRateLimit(key: ApiKey, response: Response): void {
    const retryAfter = response.headers.get('Retry-After');
    const rateLimitReset = response.headers.get('X-RateLimit-Reset');
    
    let resetAt: Date;
    
    if (retryAfter) {
      const seconds = parseInt(retryAfter, 10);
      resetAt = new Date(Date.now() + seconds * 1000);
    } else if (rateLimitReset) {
      resetAt = new Date(parseInt(rateLimitReset, 10) * 1000);
    } else {
      // Default cooldown of 1 minute if no headers
      resetAt = new Date(Date.now() + 60 * 1000);
    }
    
    key.status = "cooldown";
    key.resetAt = resetAt;
    key.remaining = 0;
    key.lastError = "Rate limited";
    
    console.log(`[VT-Orchestrator] Key ${key.id} rate limited until ${resetAt.toISOString()}`);
  }

  /**
   * Marks a key as invalid
   */
  private _markKeyInvalid(key: ApiKey, reason: string): void {
    key.status = "invalid";
    key.lastError = reason;
    key.resetAt = new Date(Date.now() + 5 * 60 * 1000); // Invalid for 5 minutes
    
    console.warn(`[VT-Orchestrator] Key ${key.id} marked invalid: ${reason}`);
  }

  /**
   * Queues a request for later processing
   */
  private _queueRequest(indicator: string, type: IndicatorType): Promise<LookupResult> {
    return new Promise((resolve, reject) => {
      const queuedRequest: QueuedRequest = {
        indicator,
        type,
        resolve,
        reject,
        queuedAt: new Date(),
      };
      
      this.requestQueue.push(queuedRequest);
      this.stats.queuedRequests++;
      
      const eta = this._getEarliestResetTime();
      
      console.log(`[VT-Orchestrator] Queued request for ${type}:${indicator.substring(0, 20)}... ETA: ${eta?.toISOString()}`);
      
      // Start queue processor if not running
      if (!this.queueProcessorRunning) {
        this._startQueueProcessor();
      }
      
      // Return immediate response indicating queued status
      resolve({
        status: "queued_rate_limited",
        indicator,
        eta,
        rateLimitInfo: { resetAt: eta },
      });
    });
  }

  /**
   * Gets the earliest time when any key will be available
   */
  private _getEarliestResetTime(): Date | undefined {
    const now = new Date();
    const resetTimes = this.keys
      .filter(key => key.resetAt && key.resetAt > now)
      .map(key => key.resetAt!)
      .sort((a, b) => a.getTime() - b.getTime());
    
    return resetTimes[0];
  }

  /**
   * Starts the queue processor
   */
  private async _startQueueProcessor(): Promise<void> {
    if (this.queueProcessorRunning) return;
    
    this.queueProcessorRunning = true;
    console.log('[VT-Orchestrator] Starting queue processor');
    
    while (this.requestQueue.length > 0) {
      const earliestReset = this._getEarliestResetTime();
      
      if (earliestReset && earliestReset > new Date()) {
        const waitMs = earliestReset.getTime() - Date.now();
        console.log(`[VT-Orchestrator] Waiting ${waitMs}ms for rate limit reset`);
        await sleep(Math.min(waitMs, 60000)); // Max 1 minute wait
        continue;
      }
      
      // Process next queued request
      const request = this.requestQueue.shift();
      if (request) {
        try {
          const result = await this._executeRequest(request.indicator, request.type);
          request.resolve(result);
        } catch (error) {
          request.reject(error instanceof Error ? error : new Error(String(error)));
        }
      }
      
      // Small delay between requests
      await sleep(100);
    }
    
    this.queueProcessorRunning = false;
    console.log('[VT-Orchestrator] Queue processor stopped');
  }

  /**
   * Cache management methods
   */
  private _getCached(key: string): any | null {
    const entry = this.cache.get(key);
    if (!entry) return null;
    
    if (new Date() > entry.expiresAt) {
      this.cache.delete(key);
      return null;
    }
    
    return entry.data;
  }

  private _setCached(key: string, data: any): void {
    const entry: CacheEntry = {
      data,
      expiresAt: new Date(Date.now() + this.ttlMs),
      indicator: key,
    };
    
    this.cache.set(key, entry);
    
    // Simple cache cleanup - remove expired entries occasionally
    if (Math.random() < 0.01) { // 1% chance
      this._cleanupCache();
    }
  }

  private _cleanupCache(): void {
    const now = new Date();
    let cleanedCount = 0;
    
    for (const [key, entry] of this.cache.entries()) {
      if (now > entry.expiresAt) {
        this.cache.delete(key);
        cleanedCount++;
      }
    }
    
    if (cleanedCount > 0) {
      console.log(`[VT-Orchestrator] Cleaned up ${cleanedCount} expired cache entries`);
    }
  }

  /**
   * VirusTotal API endpoint helpers
   */
  private _getEndpoint(indicator: string, type: IndicatorType): string {
    switch (type) {
      case "hash":
        return `/files/${indicator}`;
      case "url":
        const urlId = Buffer.from(indicator).toString('base64').replace(/=/g, '');
        return `/urls/${urlId}`;
      case "ip":
        return `/ip_addresses/${indicator}`;
      case "domain":
        return `/domains/${indicator}`;
      default:
        throw new Error(`Unsupported indicator type: ${type}`);
    }
  }

  private _generateVTLink(indicator: string, type: IndicatorType): string {
    switch (type) {
      case "hash":
        return `https://www.virustotal.com/gui/file/${indicator}`;
      case "url":
        return `https://www.virustotal.com/gui/url/${Buffer.from(indicator).toString('base64url')}`;
      case "ip":
        return `https://www.virustotal.com/gui/ip-address/${indicator}`;
      case "domain":
        return `https://www.virustotal.com/gui/domain/${indicator}`;
      default:
        return `https://www.virustotal.com/gui/search/${encodeURIComponent(indicator)}`;
    }
  }

  /**
   * Parses VirusTotal API response into standardized summary
   */
  private _parseVTResponse(data: any): LookupResult['summary'] {
    if (!data?.data?.attributes?.last_analysis_stats) {
      return { malicious: 0, suspicious: 0, clean: 0, undetected: 0, totalScans: 0 };
    }
    
    const stats = data.data.attributes.last_analysis_stats;
    const malicious = stats.malicious || 0;
    const suspicious = stats.suspicious || 0;
    const clean = stats.harmless || 0;
    const undetected = stats.undetected || 0;
    
    return {
      malicious,
      suspicious,
      clean,
      undetected,
      totalScans: malicious + suspicious + clean + undetected,
    };
  }

  /**
   * Extracts rate limit information from response headers
   */
  private _extractRateLimitInfo(response: Response): RateLimitInfo {
    const remaining = response.headers.get('X-RateLimit-Remaining');
    const reset = response.headers.get('X-RateLimit-Reset');
    const retryAfter = response.headers.get('Retry-After');
    
    return {
      remaining: remaining ? parseInt(remaining, 10) : undefined,
      resetAt: reset ? new Date(parseInt(reset, 10) * 1000) : undefined,
      retryAfter: retryAfter ? parseInt(retryAfter, 10) : undefined,
    };
  }

  /**
   * Observability methods
   */
  getStats() {
    return {
      ...this.stats,
      cacheSize: this.cache.size,
      queueDepth: this.requestQueue.length,
      cacheHitRatio: this.stats.totalRequests > 0 ? this.stats.cacheHits / this.stats.totalRequests : 0,
      keysStatus: this.keys.map(key => ({
        id: key.id,
        status: key.status,
        remaining: key.remaining,
        resetAt: key.resetAt?.toISOString(),
      })),
    };
  }

  /**
   * Manual queue processing trigger (useful for testing)
   */
  async runQueue(): Promise<void> {
    if (!this.queueProcessorRunning) {
      await this._startQueueProcessor();
    }
  }

  /**
   * Clear cache (useful for testing)
   */
  clearCache(): void {
    this.cache.clear();
    console.log('[VT-Orchestrator] Cache cleared');
  }
}

// ============================================================================
// USAGE EXAMPLE
// ============================================================================

/* Example usage:

const VT_KEYS = [
  'your-virustotal-api-key-1',
  'your-virustotal-api-key-2',
  'your-virustotal-api-key-3',
];

const vtClient = new VirusTotalClient(VT_KEYS, { ttlMs: 45 * 60 * 1000 });

// Hash lookup
const hashResult = await vtClient.lookupIndicator('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855');
console.log('Hash result:', hashResult);

// Domain lookup with explicit type
const domainResult = await vtClient.lookupIndicator('malicious-domain.com', { type: 'domain' });
console.log('Domain result:', domainResult);

// URL lookup
const urlResult = await vtClient.lookupIndicator('https://suspicious-site.com/path');
console.log('URL result:', urlResult);

// IP lookup
const ipResult = await vtClient.lookupIndicator('192.168.1.1');
console.log('IP result:', ipResult);

// Check stats
console.log('Client stats:', vtClient.getStats());

*/
