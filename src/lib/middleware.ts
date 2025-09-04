import { NextRequest, NextResponse } from 'next/server';
import { verifyToken, extractTokenFromHeader, TokenPayload } from '@/lib/auth';
import { UserActivity } from '@/lib/models/UserActivity';
import connectDB from '@/lib/db';

export interface AuthenticatedRequest extends NextRequest {
  user?: TokenPayload;
}

/**
 * Simplified auth token verification function
 */
export async function verifyAuthToken(request: NextRequest): Promise<{ success: boolean; user: TokenPayload | null; error?: NextResponse }> {
  try {
    const authHeader = request.headers.get('authorization');
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      return {
        success: false,
        user: null,
        error: NextResponse.json(
          { error: 'Authentication required' },
          { status: 401 }
        )
      };
    }

    const user = verifyToken(token);
    if (!user) {
      return {
        success: false,
        user: null,
        error: NextResponse.json(
          { error: 'Invalid or expired token' },
          { status: 401 }
        )
      };
    }

    return {
      success: true,
      user
    };

  } catch (error) {
    console.error('Token verification error:', error);
    return {
      success: false,
      user: null,
      error: NextResponse.json(
        { error: 'Authentication failed' },
        { status: 401 }
      )
    };
  }
}

/**
 * Authentication middleware that validates JWT tokens
 */
export async function authMiddleware(request: NextRequest): Promise<{ user: TokenPayload | null; error: NextResponse | null }> {
  try {
    const authHeader = request.headers.get('authorization');
    const token = extractTokenFromHeader(authHeader);

    if (!token) {
      return {
        user: null,
        error: NextResponse.json(
          { error: 'Access token is required' },
          { status: 401 }
        ),
      };
    }

    const user = verifyToken(token);
    
    if (!user) {
      return {
        user: null,
        error: NextResponse.json(
          { error: 'Invalid or expired access token' },
          { status: 401 }
        ),
      };
    }

    return { user, error: null };
  } catch (error) {
    console.error('Authentication middleware error:', error);
    return {
      user: null,
      error: NextResponse.json(
        { error: 'Authentication failed' },
        { status: 500 }
      ),
    };
  }
}

/**
 * Role-based authorization middleware
 */
export function requireRole(allowedRoles: ('admin' | 'user')[]): (user: TokenPayload) => NextResponse | null {
  return (user: TokenPayload): NextResponse | null => {
    if (!allowedRoles.includes(user.role)) {
      return NextResponse.json(
        { error: 'Insufficient permissions' },
        { status: 403 }
      );
    }
    return null;
  };
}

/**
 * Admin-only middleware
 */
export const requireAdmin = requireRole(['admin']);

/**
 * Log user activity
 */
export async function logActivity(
  userId: string,
  action: string,
  details?: Record<string, any>,
  request?: NextRequest
): Promise<void> {
  try {
    await connectDB();
    
    const activity = new UserActivity({
      userId,
      action,
      details,
      ipAddress: request?.headers.get('x-forwarded-for') || request?.headers.get('x-real-ip') || 'unknown',
      userAgent: request?.headers.get('user-agent'),
      timestamp: new Date(),
    });

    await activity.save();
  } catch (error) {
    console.error('Error logging activity:', error);
    // Don't throw error to avoid breaking the main request
  }
}

/**
 * Combined auth middleware with activity logging
 */
export async function authenticateAndLog(
  request: NextRequest,
  action: string,
  details?: Record<string, any>
): Promise<{ user: TokenPayload | null; error: NextResponse | null }> {
  const { user, error } = await authMiddleware(request);
  
  if (user) {
    // Log the activity in the background
    logActivity(user.userId, action, details, request).catch(console.error);
  }
  
  return { user, error };
}
