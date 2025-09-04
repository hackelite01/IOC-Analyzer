import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/db';
import { User } from '@/lib/models/User';
import { authenticateAndLog } from '@/lib/middleware';

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    await connectDB();

    // Authenticate user
    const { user, error } = await authenticateAndLog(request, 'GET_PROFILE');
    
    if (error) {
      return error;
    }

    if (!user) {
      return NextResponse.json(
        { error: 'Authentication failed' },
        { status: 401 }
      );
    }

    // Get fresh user data from database
    const currentUser = await User.findById(user.userId).select('-password');
    
    if (!currentUser) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(
      {
        user: {
          id: currentUser._id,
          username: currentUser.username,
          email: currentUser.email,
          role: currentUser.role,
          createdAt: currentUser.createdAt,
          updatedAt: currentUser.updatedAt,
        },
      },
      { status: 200 }
    );
  } catch (error) {
    console.error('Get profile error:', error);
    return NextResponse.json(
      { error: 'Failed to get user profile' },
      { status: 500 }
    );
  }
}
