import { VTNormalized, Verdict } from './validators';

interface VTRawData {
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
    last_analysis_results?: Record<string, {
      engine_name: string;
      category: string;
      result: string;
    }>;
  };
  id: string;
  type: string;
}

/**
 * Normalize VirusTotal response to our standard format
 */
export function normalizeVTResponse(vtData: VTRawData): VTNormalized {
  const attrs = vtData.attributes;
  const stats = attrs.last_analysis_stats || {
    malicious: 0,
    suspicious: 0,
    undetected: 0,
    harmless: 0,
  };

  // Compute verdict based on stats
  const verdict = computeVerdict(stats);

  // Extract provider information
  const providers = attrs.last_analysis_results
    ? Object.entries(attrs.last_analysis_results).map(([engine, result]) => ({
        engine: result.engine_name || engine,
        category: result.category,
        result: result.result,
      }))
    : undefined;

  // Extract categories
  const categories = attrs.categories 
    ? Object.keys(attrs.categories)
    : undefined;

  // Format last analysis date
  const last_analysis_date = attrs.last_modification_date
    ? new Date(attrs.last_modification_date * 1000).toISOString()
    : undefined;

  return {
    verdict,
    stats: {
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      harmless: stats.harmless,
      undetected: stats.undetected,
      timeout: stats.timeout,
    },
    reputation: attrs.reputation,
    categories,
    tags: attrs.tags,
    last_analysis_date,
    providers,
  };
}

/**
 * Compute verdict from analysis stats
 */
function computeVerdict(stats: {
  malicious: number;
  suspicious: number;
  harmless: number;
  undetected: number;
}): Verdict {
  const { malicious, suspicious, harmless, undetected } = stats;

  if (malicious >= 1) {
    return 'malicious';
  } else if (suspicious >= 1) {
    return 'suspicious';
  } else if (harmless > 0 && malicious === 0 && suspicious === 0) {
    return 'harmless';
  } else if (malicious === 0 && suspicious === 0 && harmless === 0 && undetected >= 0) {
    return 'undetected';
  } else {
    return 'unknown';
  }
}

/**
 * Get verdict color for UI display
 */
export function getVerdictColor(verdict: Verdict): string {
  switch (verdict) {
    case 'malicious':
      return 'destructive';
    case 'suspicious':
      return 'secondary';
    case 'harmless':
      return 'default';
    case 'undetected':
      return 'outline';
    case 'unknown':
    default:
      return 'secondary';
  }
}

/**
 * Get verdict display text
 */
export function getVerdictText(verdict: Verdict): string {
  switch (verdict) {
    case 'malicious':
      return 'Malicious';
    case 'suspicious':
      return 'Suspicious';
    case 'harmless':
      return 'Harmless';
    case 'undetected':
      return 'Undetected';
    case 'unknown':
    default:
      return 'Unknown';
  }
}
