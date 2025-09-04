import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/db';
import { UserActivity } from '@/lib/models/UserActivity';
import { User } from '@/lib/models/User';
import { authenticateAndLog } from '@/lib/middleware';

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    await connectDB();

    // Authenticate user
    const { user, error } = await authenticateAndLog(request, 'GET_ACTIVITIES');
    
    if (error) {
      return error;
    }

    if (!user) {
      return NextResponse.json(
        { error: 'Authentication failed' },
        { status: 401 }
      );
    }

    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '50'), 100); // Max 100 per page
    const targetUserId = url.searchParams.get('userId');
    const action = url.searchParams.get('action');
    
    const skip = (page - 1) * limit;

    // Build query based on user role
    let query: any = {};
    
    if (user.role === 'admin') {
      // Admin can view all activities or specific user's activities
      if (targetUserId) {
        query.userId = targetUserId;
      }
    } else {
      // Regular users can only view their own activities
      query.userId = user.userId;
    }

    // Filter by action if specified
    if (action) {
      query.action = { $regex: action, $options: 'i' };
    }

    // Get total count for pagination
    const totalCount = await UserActivity.countDocuments(query);

    // Fetch activities with pagination
    const activities = await UserActivity.find(query)
      .populate('userId', 'username email role')
      .sort({ timestamp: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Format response
    const formattedActivities = activities.map(activity => ({
      id: activity._id,
      userId: activity.userId._id,
      username: activity.userId.username,
      email: activity.userId.email,
      userRole: activity.userId.role,
      action: activity.action,
      details: activity.details,
      ipAddress: activity.ipAddress,
      userAgent: activity.userAgent,
      timestamp: activity.timestamp,
    }));

    const totalPages = Math.ceil(totalCount / limit);

    return NextResponse.json(
      {
        activities: formattedActivities,
        pagination: {
          currentPage: page,
          totalPages,
          totalCount,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
          limit,
        },
        meta: {
          canViewAllUsers: user.role === 'admin',
          viewingUserId: user.role === 'admin' ? targetUserId || 'all' : user.userId,
        },
      },
      { status: 200 }
    );
  } catch (error) {
    console.error('Get activities error:', error);
    return NextResponse.json(
      { error: 'Failed to get activities' },
      { status: 500 }
    );
  }
}
