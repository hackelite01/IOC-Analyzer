import { NextRequest, NextResponse } from 'next/server';
import dbConnect from '@/lib/db';
import { IOC } from '@/lib/models/IOC';

export async function GET(request: NextRequest) {
  try {
    await dbConnect();

    // Get a sample of recent IOCs to understand the data structure
    const sampleIOCs = await IOC.find({})
      .sort({ fetchedAt: -1 })
      .limit(5)
      .exec();

    // Get total count
    const totalCount = await IOC.countDocuments({});

    // Get count with vt data
    const vtDataCount = await IOC.countDocuments({
      'vt.raw': { $exists: true, $ne: null }
    });

    // Get recent IOCs
    const recentIOCs = await IOC.find({
      fetchedAt: { 
        $gte: new Date(Date.now() - 30 * 24 * 60 * 60 * 1000) // Last 30 days
      }
    })
    .sort({ fetchedAt: -1 })
    .limit(10)
    .exec();

    return NextResponse.json({
      success: true,
      debug: {
        totalIOCs: totalCount,
        iocsWithVTData: vtDataCount,
        recentIOCsCount: recentIOCs.length,
        sampleData: sampleIOCs.map(ioc => ({
          id: ioc._id,
          ioc: ioc.ioc,
          type: ioc.type,
          hasVTRaw: !!ioc.vt?.raw,
          hasVTNormalized: !!ioc.vt?.normalized,
          vtVerdict: ioc.vt?.normalized?.verdict,
          fetchedAt: ioc.fetchedAt,
          vtDataStructure: ioc.vt?.raw ? Object.keys(ioc.vt.raw as any) : []
        })),
        recentIOCs: recentIOCs.map(ioc => ({
          id: ioc._id,
          ioc: ioc.ioc,
          type: ioc.type,
          verdict: ioc.vt?.normalized?.verdict,
          fetchedAt: ioc.fetchedAt
        }))
      }
    });

  } catch (error) {
    console.error('Debug API error:', error);
    return NextResponse.json({
      success: false,
      error: error instanceof Error ? error.message : 'Unknown error',
      debug: {
        errorType: typeof error,
        errorString: String(error)
      }
    }, { status: 500 });
  }
}
