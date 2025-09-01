import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/db';
import { IOC } from '@/lib/models/IOC';
import { detectIOCType, normalizeIOC } from '@/lib/detect';
import { VTNormalized } from '@/lib/validators';
import { vtClient } from '@/lib/vt';

export async function GET(): Promise<NextResponse> {
  try {
    await connectDB();
    return NextResponse.json({ message: 'IOC API endpoint working' });
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
}

interface SubmissionResult {
  _id: string;
  ioc: string;
  type: string;
  verdict: string;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    await connectDB();
    const body: IOCSubmission = await request.json();
    
    if (!body.iocs || !Array.isArray(body.iocs) || body.iocs.length === 0) {
      return NextResponse.json(
        { error: 'IOCs array is required and must not be empty' },
        { status: 400 }
      );
    }

    const results: SubmissionResult[] = [];
    const errors: string[] = [];
    let created = 0;
    let fromCache = 0;

    for (const iocString of body.iocs) {
      try {
        const trimmedIOC = iocString.trim();
        if (!trimmedIOC) continue;

        const type = detectIOCType(trimmedIOC);
        const normalizedIOC = normalizeIOC(trimmedIOC, type);

        // Check if IOC already exists in database
        let iocDoc = await IOC.findOne({ ioc: normalizedIOC });
        
        if (iocDoc) {
          fromCache++;
          results.push({
            _id: iocDoc._id.toString(),
            ioc: iocDoc.ioc,
            type: iocDoc.type,
            verdict: iocDoc.vt.normalized.verdict || 'unknown'
          });
        } else {
          // Fetch real data from VirusTotal
          let vtData: VTNormalized;
          try {
            const vtResponse = await vtClient.lookupIOC(normalizedIOC, type);
            const stats = vtResponse.data?.attributes?.last_analysis_stats || {};
            
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

    return NextResponse.json({
      total: body.iocs.length,
      created,
      fromCache,
      errors,
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
