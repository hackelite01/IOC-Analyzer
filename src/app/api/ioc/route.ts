import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/db';
import { IOC } from '@/lib/models/IOC';
import { detectIOCType, normalizeIOC } from '@/lib/detect';
import { VTNormalized } from '@/lib/validators';
import { vtClient } from '@/lib/vt';
import { authenticateAndLog } from '@/lib/middleware';

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    await connectDB();

    // Authenticate user
    const { user, error } = await authenticateAndLog(request, 'GET_IOC_STATUS');
    
    if (error) {
      return error;
    }

    return NextResponse.json({ 
      message: 'IOC API endpoint working',
      authenticated: !!user,
      user: user ? { id: user.userId, role: user.role } : null 
    });
  } catch (error) {
    console.error('IOC GET error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}

interface IOCSubmission {
  iocs: string[];
  label?: string;
  requestId?: string;
  searchType?: string;
}

interface SubmissionResult {
  _id: string;
  ioc: string;
  type: string;
  verdict: string;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  console.log('🔍 IOC POST request received');
  
  try {
    await connectDB();
    console.log('📡 Database connected');

    // Authenticate user
    const { user, error } = await authenticateAndLog(request, 'SUBMIT_IOC_ANALYSIS');
    
    if (error) {
      console.log('❌ Authentication failed');
      return error;
    }

    if (!user) {
      console.log('❌ No user found after authentication');
      return NextResponse.json(
        { error: 'Authentication required' },
        { status: 401 }
      );
    }

    console.log('✅ User authenticated:', user.userId);

    const body: IOCSubmission = await request.json();
    console.log('📋 Request body:', body);
    
    if (!body.iocs || !Array.isArray(body.iocs) || body.iocs.length === 0) {
      console.log('❌ Invalid IOCs in request');
      return NextResponse.json(
        { error: 'IOCs array is required and must not be empty' },
        { status: 400 }
      );
    }

    const results: SubmissionResult[] = [];
    const errors: string[] = [];
    let created = 0;
    let fromCache = 0;

    console.log(`🎯 Processing ${body.iocs.length} IOCs...`);

    for (const iocString of body.iocs) {
      try {
        console.log(`🔍 Processing IOC: ${iocString}`);
        const trimmedIOC = iocString.trim();
        if (!trimmedIOC) continue;

        const type = detectIOCType(trimmedIOC);
        const normalizedIOC = normalizeIOC(trimmedIOC, type);
        console.log(`📝 Normalized IOC: ${normalizedIOC}, Type: ${type}`);

        // Check if IOC already exists in database
        let iocDoc = await IOC.findOne({ ioc: normalizedIOC });
        console.log(`🔍 Database lookup result: ${iocDoc ? 'FOUND' : 'NOT FOUND'}`);
        
        if (iocDoc) {
          fromCache++;
          console.log(`📋 Using cached result for ${normalizedIOC}`);
          results.push({
            _id: iocDoc._id.toString(),
            ioc: iocDoc.ioc,
            type: iocDoc.type,
            verdict: iocDoc.vt.normalized.verdict || 'unknown'
          });
        } else {
          console.log(`🔍 Fetching from VirusTotal for ${normalizedIOC}`);
          // Fetch real data from VirusTotal
          let vtData: VTNormalized;
          try {
            const vtResponse = await vtClient.lookupIOC(normalizedIOC, type);
            console.log(`✅ VirusTotal response received for ${normalizedIOC}`);
            const stats = vtResponse.data?.attributes?.last_analysis_stats || {};
            console.log(`📊 VT Stats for ${normalizedIOC}:`, stats);
            
            vtData = {
              verdict: stats.malicious > 0 ? 'malicious' : 
                      stats.suspicious > 0 ? 'suspicious' : 
                      stats.harmless > 0 ? 'harmless' : 'undetected',
              stats: {
                malicious: stats.malicious || 0,
                suspicious: stats.suspicious || 0,
                harmless: stats.harmless || 0,
                undetected: stats.undetected || 0,
              },
              providers: []
            };
          } catch (error) {
            console.error(`VirusTotal API error for ${normalizedIOC}:`, error);
            // Fallback to placeholder data if VirusTotal fails
            vtData = {
              verdict: 'unknown',
              stats: { malicious: 0, suspicious: 0, harmless: 0, undetected: 0 },
              providers: []
            };
          }

          iocDoc = new IOC({
            ioc: normalizedIOC,
            type,
            label: body.label,
            vt: {
              raw: {},
              normalized: vtData
            },
            fetchedAt: new Date(),
            updatedAt: new Date(),
            cacheTtlSec: 3600, // 1 hour
          });

          await iocDoc.save();
          created++;

          results.push({
            _id: iocDoc._id.toString(),
            ioc: iocDoc.ioc,
            type: iocDoc.type,
            verdict: vtData.verdict
          });
        }
      } catch (error) {
        console.error(`Error processing IOC ${iocString}:`, error);
        errors.push(`Failed to process IOC: ${iocString}`);
      }
    }

    // Collect threat statistics from results
    const threatStats = {
      malicious: 0,
      suspicious: 0,
      clean: 0,
      unknown: 0
    };

    const threatBreakdown: Array<{ type: string; count: number; color: string }> = [];

    results.forEach(result => {
      switch (result.verdict) {
        case 'malicious':
          threatStats.malicious++;
          break;
        case 'suspicious':
          threatStats.suspicious++;
          break;
        case 'harmless':
          threatStats.clean++;
          break;
        default:
          threatStats.unknown++;
          break;
      }
    });

    // Create threat breakdown for chart
    if (threatStats.malicious > 0) {
      threatBreakdown.push({ type: 'Malicious', count: threatStats.malicious, color: '#EF4444' });
    }
    if (threatStats.suspicious > 0) {
      threatBreakdown.push({ type: 'Suspicious', count: threatStats.suspicious, color: '#F59E0B' });
    }
    if (threatStats.clean > 0) {
      threatBreakdown.push({ type: 'Clean', count: threatStats.clean, color: '#10B981' });
    }
    if (threatStats.unknown > 0) {
      threatBreakdown.push({ type: 'Unknown', count: threatStats.unknown, color: '#6B7280' });
    }

    // Save analysis results for threat overview
    if (body.requestId) {
      try {
        const { getDatabase } = await import('@/lib/db');
        const db = await getDatabase();
        
        await db.collection('analyses').insertOne({
          requestId: body.requestId,
          query: `${body.iocs.length} IOCs analyzed`,
          timestamp: new Date(),
          totalAnalyzed: results.length,
          malicious: threatStats.malicious,
          suspicious: threatStats.suspicious,
          clean: threatStats.clean,
          unknown: threatStats.unknown,
          threatBreakdown,
          searchType: body.searchType || 'auto',
          label: body.label || 'Threat Hunt Analysis'
        });
      } catch (error) {
        console.error('Error saving analysis results:', error);
        // Don't fail the main request if analysis save fails
      }
    }

    return NextResponse.json({
      total: body.iocs.length,
      created,
      fromCache,
      errors,
      analyzed: results.length,
      threats: {
        malicious: threatStats.malicious,
        suspicious: threatStats.suspicious,
        clean: threatStats.clean,
        unknown: threatStats.unknown
      },
      threatBreakdown,
      items: results
    });
  } catch (error) {
    console.error('IOC POST error:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}
