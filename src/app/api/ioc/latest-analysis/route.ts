import { NextRequest, NextResponse } from 'next/server';
import { getDatabase } from '@/lib/db';

export async function GET(request: NextRequest) {
  try {
    const db = await getDatabase();
    
    if (!db) {
      return NextResponse.json({
        success: false,
        error: 'Database connection failed'
      }, { status: 500 });
    }
    
    // Get the most recent analysis results
    const latestAnalysis = await db.collection('analyses').findOne(
      {},
      { sort: { timestamp: -1 } }
    );

    if (!latestAnalysis) {
      return NextResponse.json({
        success: true,
        analysis: null
      });
    }

    // Transform the database record to match our ThreatOverviewResult interface
    const analysisResult = {
      query: latestAnalysis.query || `${latestAnalysis.totalAnalyzed || 0} IOCs analyzed`,
      timestamp: latestAnalysis.timestamp || new Date(),
      totalAnalyzed: latestAnalysis.totalAnalyzed || 0,
      malicious: latestAnalysis.malicious || 0,
      suspicious: latestAnalysis.suspicious || 0,
      clean: latestAnalysis.clean || 0,
      threatBreakdown: latestAnalysis.threatBreakdown || [],
      requestId: latestAnalysis.requestId || 'unknown'
    };

    return NextResponse.json({
      success: true,
      analysis: analysisResult
    });

  } catch (error) {
    console.error('Error fetching latest analysis:', error);
    return NextResponse.json(
      { 
        success: false, 
        error: 'Failed to fetch latest analysis' 
      },
      { status: 500 }
    );
  }
}
