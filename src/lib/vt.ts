import { VirusTotalClient, LookupResult, IndicatorType } from './vt-orchestrator';
import { IOCType } from './validators';

// Legacy interface for backward compatibility
interface VTResponse {
  data: {
    attributes: {
      last_analysis_stats?: {
        malicious: number;
        suspicious: number;
        undetected: number;
        harmless: number;
        timeout?: number;
      };
      reputation?: number;
      categories?: Record<string, string>;
      tags?: string[];
      last_modification_date?: number;
      creation_date?: number;
    };
    id: string;
    type: string;
  };
}

// Enhanced VT client using the new orchestrator
class EnhancedVirusTotalClient {
  private orchestrator: VirusTotalClient;

  constructor() {
    // Get API keys from environment variables - support both array and individual formats
    const apiKeys = this.getApiKeysFromEnv();

    if (apiKeys.length === 0) {
      throw new Error('At least one VirusTotal API key must be provided. Use VT_API_KEYS (comma-separated) or individual VT_API_KEY variables.');
    }

    console.log(`[VT-Client] Initialized with ${apiKeys.length} API key(s)`);

    // Initialize orchestrator with 45-minute cache TTL
    this.orchestrator = new VirusTotalClient(apiKeys, { ttlMs: 45 * 60 * 1000 });
  }

  /**
   * Parse API keys from environment variables supporting multiple formats
   */
  private getApiKeysFromEnv(): string[] {
    const keys: string[] = [];

    // Method 1: Comma-separated array (preferred)
    if (process.env.VT_API_KEYS) {
      const arrayKeys = process.env.VT_API_KEYS
        .split(',')
        .map(key => key.trim())
        .filter(key => key.length > 0);
      keys.push(...arrayKeys);
    }

    // Method 2: Individual numbered keys (backward compatibility)
    const individualKeys = [
      process.env.VT_API_KEY,
      process.env.VT_API_KEY_1,
      process.env.VT_API_KEY_2,
      process.env.VT_API_KEY_3,
      process.env.VT_API_KEY_4,
      process.env.VT_API_KEY_5,
    ].filter(Boolean) as string[];

    // Add individual keys that aren't already in the array
    for (const key of individualKeys) {
      if (!keys.includes(key)) {
        keys.push(key);
      }
    }

    // Remove duplicates and validate
    const uniqueKeys = [...new Set(keys)].filter(key => key && key.length >= 32);

    return uniqueKeys;
  }

  /**
   * Enhanced lookup method using the new orchestrator
   */
  async lookupIOCEnhanced(ioc: string, type: IOCType): Promise<LookupResult> {
    console.log(`[VT-Client] Enhanced lookup starting for ${ioc} (type: ${type})`);
    const indicatorType = this.mapIOCTypeToIndicatorType(type);
    console.log(`[VT-Client] Mapped type ${type} -> ${indicatorType}`);
    
    const result = await this.orchestrator.lookupIndicator(ioc, { type: indicatorType });
    console.log(`[VT-Client] Orchestrator result for ${ioc}:`, result);
    
    return result;
  }

  /**
   * Legacy lookup method for backward compatibility
   * Converts new orchestrator results to legacy format
   */
  async lookupIOC(ioc: string, type: IOCType): Promise<VTResponse> {
    try {
      console.log(`[VT-Client] Starting lookupIOC for ${ioc} (type: ${type})`);
      const result = await this.lookupIOCEnhanced(ioc, type);
      console.log(`[VT-Client] Enhanced lookup completed for ${ioc}:`, result);
      
      // Convert to legacy format
      const legacyResponse: VTResponse = {
        data: {
          attributes: {
            last_analysis_stats: result.summary ? {
              malicious: result.summary.malicious,
              suspicious: result.summary.suspicious,
              undetected: result.summary.undetected,
              harmless: result.summary.clean,
            } : {
              malicious: 0,
              suspicious: 0,
              undetected: 0,
              harmless: 0,
            },
          },
          id: ioc,
          type: type,
        },
      };

      console.log(`[VT-Client] Legacy response for ${ioc}:`, legacyResponse);
      return legacyResponse;
      
    } catch (error) {
      console.error(`[VT-Client] Error in lookupIOC for ${ioc}:`, error);
      // Return empty result for errors (maintains legacy behavior)
      return {
        data: {
          attributes: {
            last_analysis_stats: {
              malicious: 0,
              suspicious: 0,
              undetected: 0,
              harmless: 0,
            },
          },
          id: ioc,
          type,
        },
      };
    }
  }

  /**
   * Get orchestrator statistics for monitoring
   */
  getStats() {
    return this.orchestrator.getStats();
  }

  /**
   * Clear cache (useful for testing or manual cache invalidation)
   */
  clearCache() {
    return this.orchestrator.clearCache();
  }

  /**
   * Manually trigger queue processing
   */
  async runQueue() {
    return await this.orchestrator.runQueue();
  }

  /**
   * Maps legacy IOC types to new indicator types
   */
  private mapIOCTypeToIndicatorType(iocType: IOCType): IndicatorType {
    switch (iocType) {
      case 'ip':
        return 'ip';
      case 'domain':
        return 'domain';
      case 'hash':
        return 'hash';
      case 'url':
        return 'url';
      default:
        throw new Error(`Unsupported IOC type: ${iocType}`);
    }
  }
}

export const vtClient = new EnhancedVirusTotalClient();
