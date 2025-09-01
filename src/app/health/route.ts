import { NextResponse } from 'next/server';
import connectDB from '@/lib/db';

export async function GET(): Promise<NextResponse> {
  const health = {
    ok: true,
    timestamp: new Date().toISOString(),
    mongo: 'disconnected',
    vt: 'unconfigured',
  };

  try {
    await connectDB();
    health.mongo = 'connected';
  } catch (error) {
    console.error('MongoDB health check failed:', error);
    health.ok = false;
    health.mongo = 'error';
  }

  try {
    if (process.env.VT_API_KEY && process.env.VT_API_KEY !== 'your-virustotal-api-key-here') {
      health.vt = 'configured';
    }
  } catch (error) {
    console.error('VT health check failed:', error);
  }

  const statusCode = health.ok ? 200 : 503;
  return NextResponse.json(health, { status: statusCode });
}
