import { NextRequest, NextResponse } from 'next/server';
import { authenticateAndLog } from '@/lib/middleware';

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    // Test authentication middleware
    const { user, error } = await authenticateAndLog(request, 'AUTH_TEST');
    
    if (error) {
      return error;
    }

    return NextResponse.json({
      message: 'Authentication successful',
      user: user ? {
        id: user.userId,
        username: user.username,
        email: user.email,
        role: user.role,
      } : null,
      timestamp: new Date().toISOString(),
    });
  } catch (error) {
    console.error('Auth test error:', error);
    return NextResponse.json(
      { error: 'Auth test failed' },
      { status: 500 }
    );
  }
}
