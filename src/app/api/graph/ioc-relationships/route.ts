import { NextRequest, NextResponse } from 'next/server';
import dbConnect from '@/lib/db';
import { IOC, IIOC } from '@/lib/models/IOC';

interface IOCNode {
  id: string;
  type: 'file' | 'domain' | 'ip' | 'hash';
  value: string;
  threatLevel: 'critical' | 'high' | 'medium' | 'low';
  detectionRatio?: number;
  confidenceScore?: number;
  source: string[];
  firstSeen?: string;
  lastSeen?: string;
  malwareFamily?: string;
  tags?: string[];
}

interface IOCEdge {
  source: string;
  target: string;
  relationship: string;
  confidence: number;
  source_feed: string;
}

interface GraphData {
  nodes: IOCNode[];
  links: IOCEdge[];
}

interface GraphStats {
  totalNodes: number;
  totalEdges: number;
  criticalThreats: number;
  nodeTypes: {
    file: number;
    domain: number;
    ip: number;
    hash: number;
  };
  threatLevels: {
    critical: number;
    high: number;
    medium: number;
    low: number;
  };
}

// Helper function to determine IOC type
function determineIOCType(value: string): 'file' | 'domain' | 'ip' | 'hash' {
  // Hash patterns
  const md5Pattern = /^[a-fA-F0-9]{32}$/;
  const sha1Pattern = /^[a-fA-F0-9]{40}$/;
  const sha256Pattern = /^[a-fA-F0-9]{64}$/;
  
  // IP pattern
  const ipPattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  
  // Domain pattern
  const domainPattern = /^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;

  if (md5Pattern.test(value) || sha1Pattern.test(value) || sha256Pattern.test(value)) {
    return 'hash';
  } else if (ipPattern.test(value)) {
    return 'ip';
  } else if (domainPattern.test(value)) {
    return 'domain';
  } else {
    return 'file';
  }
}

// Helper function to determine threat level based on VirusTotal data
function determineThreatLevel(virusTotalData: any): 'critical' | 'high' | 'medium' | 'low' {
  if (!virusTotalData || !virusTotalData.positives) return 'low';

  const detectionRatio = virusTotalData.positives / (virusTotalData.total || 1);
  
  if (detectionRatio >= 0.7) return 'critical';
  if (detectionRatio >= 0.4) return 'high';
  if (detectionRatio >= 0.1) return 'medium';
  return 'low';
}

// Helper function to extract malware families from VirusTotal data
function extractMalwareFamily(virusTotalData: any): string | undefined {
  if (!virusTotalData || !virusTotalData.scans) return undefined;

  const scans = virusTotalData.scans;
  const detections = Object.values(scans)
    .filter((scan: any) => scan.detected && scan.result)
    .map((scan: any) => scan.result as string);

  // Look for common malware family patterns
  const familyPatterns = [
    /trojan/i, /malware/i, /virus/i, /worm/i, /rootkit/i,
    /ransomware/i, /spyware/i, /adware/i, /keylogger/i, /backdoor/i
  ];

  for (const detection of detections) {
    for (const pattern of familyPatterns) {
      if (pattern.test(detection)) {
        return detection.split(/[.\-_\s/]/)[0];
      }
    }
  }

  return detections[0]?.split(/[.\-_\s/]/)[0];
}

// Helper function to find relationships between IOCs
function findRelationships(iocs: IIOC[]): IOCEdge[] {
  const relationships: IOCEdge[] = [];
  const processed = new Set<string>();

  for (let i = 0; i < iocs.length; i++) {
    for (let j = i + 1; j < iocs.length; j++) {
      const ioc1 = iocs[i];
      const ioc2 = iocs[j];
      
      const relationshipKey = `${ioc1._id}-${ioc2._id}`;
      const reverseKey = `${ioc2._id}-${ioc1._id}`;
      
      if (processed.has(relationshipKey) || processed.has(reverseKey)) continue;

      let relationship = '';
      let confidence = 0;

      // Get IOC types for relationship analysis
      const type1 = determineIOCType(ioc1.ioc);
      const type2 = determineIOCType(ioc2.ioc);

      // Check for direct relationships in VirusTotal data
      if (ioc1.vt?.raw && ioc2.vt?.raw) {
        const vt1 = ioc1.vt.raw as any;
        const vt2 = ioc2.vt.raw as any;
        
        // Hash to domain/IP relationship
        if (type1 === 'hash' && (type2 === 'domain' || type2 === 'ip')) {
          if (vt1.behaviour?.network?.dns_lookups?.includes(ioc2.ioc) ||
              vt1.behaviour?.network?.http_conversations?.some((conv: any) => 
                conv.url?.includes(ioc2.ioc))) {
            relationship = 'communicates_with';
            confidence = 0.9;
          }
        }

        // Domain to IP relationship
        if (type1 === 'domain' && type2 === 'ip') {
          if (Array.isArray(vt1.resolutions) && vt1.resolutions.some((res: any) => res.ip_address === ioc2.ioc)) {
            relationship = 'resolves_to';
            confidence = 0.95;
          }
        }

        // Same malware family relationship
        const family1 = extractMalwareFamily(vt1);
        const family2 = extractMalwareFamily(vt2);
        
        if (family1 && family2 && family1.toLowerCase() === family2.toLowerCase()) {
          relationship = 'related_malware';
          confidence = 0.8;
        }

        // Same campaign/tag relationship
        const tags1 = Array.isArray(vt1.tags) ? vt1.tags : [];
        const tags2 = Array.isArray(vt2.tags) ? vt2.tags : [];
        const commonTags = tags1.filter((tag: string) => tags2.includes(tag));
        
        if (commonTags.length > 0) {
          relationship = relationship || 'related_campaign';
          confidence = Math.max(confidence, 0.6 + (commonTags.length * 0.1));
        }
      }
      
      // Fallback relationships using normalized data
      if (!relationship && ioc1.vt?.normalized && ioc2.vt?.normalized) {
        const norm1 = ioc1.vt.normalized;
        const norm2 = ioc2.vt.normalized;
        
        // Same verdict relationship (both malicious, both suspicious, etc.)
        if (norm1.verdict === norm2.verdict && norm1.verdict !== 'harmless') {
          relationship = 'same_verdict';
          confidence = norm1.verdict === 'malicious' ? 0.7 : 0.5;
        }
        
        // Category overlap
        const cats1 = norm1.categories || [];
        const cats2 = norm2.categories || [];
        const commonCats = cats1.filter(cat => cats2.includes(cat));
        
        if (commonCats.length > 0 && !relationship) {
          relationship = 'related_category';
          confidence = 0.4 + (commonCats.length * 0.1);
        }
        
        // Tag overlap
        const tags1 = norm1.tags || [];
        const tags2 = norm2.tags || [];
        const commonTags = tags1.filter(tag => tags2.includes(tag));
        
        if (commonTags.length > 0 && !relationship) {
          relationship = 'related_tags';
          confidence = 0.3 + (commonTags.length * 0.1);
        }
      }

      // Temporal correlation (scanned around the same time)
      const time1 = new Date(ioc1.fetchedAt);
      const time2 = new Date(ioc2.fetchedAt);
      const timeDiff = Math.abs(time1.getTime() - time2.getTime());
      const hoursDiff = timeDiff / (1000 * 60 * 60);
      
      if (hoursDiff <= 24 && !relationship) { // Within 24 hours
        relationship = 'temporal_correlation';
        confidence = Math.max(0.3, 0.6 - (hoursDiff / 24 * 0.3));
      }

      // Type-based relationships for better visualization
      if (!relationship) {
        // Connect similar types with lower confidence
        if (type1 === type2) {
          relationship = 'same_type';
          confidence = 0.2;
        }
        // Connect complementary types (hash with domain/IP)
        else if ((type1 === 'hash' && (type2 === 'domain' || type2 === 'ip')) ||
                 (type2 === 'hash' && (type1 === 'domain' || type1 === 'ip'))) {
          relationship = 'potential_relation';
          confidence = 0.25;
        }
        // Connect domain with IP
        else if ((type1 === 'domain' && type2 === 'ip') || (type1 === 'ip' && type2 === 'domain')) {
          relationship = 'network_relation';
          confidence = 0.3;
        }
      }

      if (relationship && confidence > 0.15) { // Lower threshold for more connections
        relationships.push({
          source: (ioc1._id as any).toString(),
          target: (ioc2._id as any).toString(),
          relationship,
          confidence,
          source_feed: 'Analysis'
        });
        
        processed.add(relationshipKey);
      }
    }
  }

  return relationships;
}

export async function GET(request: NextRequest) {
  try {
    await dbConnect();

    console.log('Graph API: Starting IOC relationship analysis...');

    // Get total IOC count for debugging
    const totalIOCs = await IOC.countDocuments({});
    console.log(`Graph API: Total IOCs in database: ${totalIOCs}`);

    // Check how many have VT data (try different patterns)
    const vtRawCount = await IOC.countDocuments({
      'vt.raw': { $exists: true, $ne: null }
    });
    const vtNormalizedCount = await IOC.countDocuments({
      'vt.normalized': { $exists: true, $ne: null }
    });
    const vtAnyCount = await IOC.countDocuments({
      'vt': { $exists: true, $ne: null }
    });
    
    console.log(`Graph API: IOCs with vt.raw: ${vtRawCount}`);
    console.log(`Graph API: IOCs with vt.normalized: ${vtNormalizedCount}`);
    console.log(`Graph API: IOCs with any vt data: ${vtAnyCount}`);

    // Fetch recent IOCs - try different queries based on what data exists
    let recentIOCs = [];
    
    if (vtRawCount > 0) {
      recentIOCs = await IOC.find({
        'vt.raw': { $exists: true, $ne: null },
        fetchedAt: { 
          $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        }
      })
      .sort({ fetchedAt: -1 })
      .limit(100)
      .exec();
    } else if (vtNormalizedCount > 0) {
      recentIOCs = await IOC.find({
        'vt.normalized': { $exists: true, $ne: null },
        fetchedAt: { 
          $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        }
      })
      .sort({ fetchedAt: -1 })
      .limit(100)
      .exec();
    } else if (vtAnyCount > 0) {
      recentIOCs = await IOC.find({
        'vt': { $exists: true, $ne: null },
        fetchedAt: { 
          $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000)
        }
      })
      .sort({ fetchedAt: -1 })
      .limit(100)
      .exec();
    }

    console.log(`Graph API: Found ${recentIOCs.length} recent IOCs with VT data`);

    // If no recent data, try all IOCs with any VT data
    if (recentIOCs.length === 0) {
      const allVTIOCs = await IOC.find({
        $or: [
          { 'vt.raw': { $exists: true, $ne: null } },
          { 'vt.normalized': { $exists: true, $ne: null } },
          { 'vt': { $exists: true, $ne: null } }
        ]
      })
      .sort({ fetchedAt: -1 })
      .limit(50)
      .exec();
      
      console.log(`Graph API: Fallback - Found ${allVTIOCs.length} total IOCs with any VT data`);
      recentIOCs = allVTIOCs;
    }

    // Convert IOCs to graph nodes
    const nodes: IOCNode[] = recentIOCs.map((ioc: IIOC) => {
      const iocType = determineIOCType(ioc.ioc);
      
      // Try to get threat data from different VT structures
      let threatLevel: 'critical' | 'high' | 'medium' | 'low' = 'low';
      let detectionRatio = 0;
      let confidenceScore: number | undefined;
      let malwareFamily: string | undefined;
      let tags: string[] = [];
      
      // Check vt.raw first
      if (ioc.vt?.raw) {
        const vtRaw = ioc.vt.raw as any;
        threatLevel = determineThreatLevel(vtRaw);
        malwareFamily = extractMalwareFamily(vtRaw);
        detectionRatio = vtRaw?.positives && vtRaw?.total ? (vtRaw.positives / vtRaw.total) : 0;
        confidenceScore = vtRaw?.positives && vtRaw?.total ? Math.round((vtRaw.positives / vtRaw.total) * 100) : undefined;
        tags = Array.isArray(vtRaw?.tags) ? vtRaw.tags : [];
      }
      // Fallback to vt.normalized
      else if (ioc.vt?.normalized) {
        const vtNorm = ioc.vt.normalized;
        threatLevel = vtNorm.verdict === 'malicious' ? 'critical' :
                     vtNorm.verdict === 'suspicious' ? 'high' :
                     vtNorm.verdict === 'harmless' ? 'low' : 'medium';
        
        if (vtNorm.stats) {
          const total = vtNorm.stats.malicious + vtNorm.stats.suspicious + vtNorm.stats.harmless + vtNorm.stats.undetected;
          const positive = vtNorm.stats.malicious + vtNorm.stats.suspicious;
          detectionRatio = total > 0 ? positive / total : 0;
          confidenceScore = total > 0 ? Math.round((positive / total) * 100) : undefined;
        }
        
        tags = Array.isArray(vtNorm.tags) ? vtNorm.tags : [];
      }
      
      return {
        id: (ioc._id as any).toString(),
        type: iocType,
        value: ioc.ioc,
        threatLevel,
        detectionRatio,
        confidenceScore,
        source: ['VirusTotal'],
        firstSeen: ioc.fetchedAt?.toISOString?.() || new Date().toISOString(),
        lastSeen: ioc.updatedAt?.toISOString?.() || new Date().toISOString(),
        malwareFamily,
        tags
      };
    });

    // Find relationships between IOCs
    const links = findRelationships(recentIOCs);

    // Calculate statistics
    const stats: GraphStats = {
      totalNodes: nodes.length,
      totalEdges: links.length,
      criticalThreats: nodes.filter(n => n.threatLevel === 'critical').length,
      nodeTypes: {
        file: nodes.filter(n => n.type === 'file').length,
        domain: nodes.filter(n => n.type === 'domain').length,
        ip: nodes.filter(n => n.type === 'ip').length,
        hash: nodes.filter(n => n.type === 'hash').length
      },
      threatLevels: {
        critical: nodes.filter(n => n.threatLevel === 'critical').length,
        high: nodes.filter(n => n.threatLevel === 'high').length,
        medium: nodes.filter(n => n.threatLevel === 'medium').length,
        low: nodes.filter(n => n.threatLevel === 'low').length
      }
    };

    const graphData: GraphData = { nodes, links };

    console.log('Graph API: Returning graph data:', {
      nodes: nodes.length,
      links: links.length,
      stats
    });

    return NextResponse.json({
      success: true,
      graph: graphData,
      stats,
      lastUpdated: new Date().toISOString(),
      message: `Generated graph with ${nodes.length} nodes and ${links.length} relationships`,
      debug: {
        totalIOCs,
        vtRawCount,
        vtNormalizedCount, 
        vtAnyCount,
        recentIOCsFound: recentIOCs.length,
        nodesSample: nodes.slice(0, 2).map(n => ({
          id: n.id,
          type: n.type,
          value: n.value.substring(0, 20) + '...',
          threatLevel: n.threatLevel
        }))
      }
    });

  } catch (error) {
    console.error('Error generating IOC relationship graph:', error);
    
    return NextResponse.json({
      success: false,
      error: 'Failed to generate IOC relationship graph',
      details: error instanceof Error ? error.message : 'Unknown error'
    }, { status: 500 });
  }
}
