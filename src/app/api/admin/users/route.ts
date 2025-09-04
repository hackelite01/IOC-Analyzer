import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/db';
import { User } from '@/lib/models/User';
import { authenticateAndLog, requireAdmin } from '@/lib/middleware';

export async function GET(request: NextRequest): Promise<NextResponse> {
  try {
    await connectDB();

    // Authenticate user
    const { user, error } = await authenticateAndLog(request, 'GET_ALL_USERS');
    
    if (error) {
      return error;
    }

    if (!user) {
      return NextResponse.json(
        { error: 'Authentication failed' },
        { status: 401 }
      );
    }

    // Check admin role
    const roleError = requireAdmin(user);
    if (roleError) {
      return roleError;
    }

    const url = new URL(request.url);
    const page = parseInt(url.searchParams.get('page') || '1');
    const limit = Math.min(parseInt(url.searchParams.get('limit') || '20'), 50); // Max 50 per page
    const search = url.searchParams.get('search') || '';
    const role = url.searchParams.get('role') as 'admin' | 'user' | null;
    
    const skip = (page - 1) * limit;

    // Build query
    let query: any = {};
    
    if (search) {
      query.$or = [
        { username: { $regex: search, $options: 'i' } },
        { email: { $regex: search, $options: 'i' } },
      ];
    }
    
    if (role) {
      query.role = role;
    }

    // Get total count for pagination
    const totalCount = await User.countDocuments(query);

    // Fetch users with pagination
    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .skip(skip)
      .limit(limit)
      .lean();

    // Get user statistics
    const stats = {
      totalUsers: await User.countDocuments(),
      adminUsers: await User.countDocuments({ role: 'admin' }),
      regularUsers: await User.countDocuments({ role: 'user' }),
    };

    const totalPages = Math.ceil(totalCount / limit);

    return NextResponse.json(
      {
        users: users.map(user => ({
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
          createdAt: user.createdAt,
          updatedAt: user.updatedAt,
        })),
        pagination: {
          currentPage: page,
          totalPages,
          totalCount,
          hasNextPage: page < totalPages,
          hasPrevPage: page > 1,
          limit,
        },
        stats,
        filters: {
          search,
          role,
        },
      },
      { status: 200 }
    );
  } catch (error) {
    console.error('Get users error:', error);
    return NextResponse.json(
      { error: 'Failed to get users' },
      { status: 500 }
    );
  }
}

export async function PATCH(request: NextRequest): Promise<NextResponse> {
  try {
    await connectDB();

    // Authenticate user
    const { user, error } = await authenticateAndLog(request, 'UPDATE_USER_ROLE');
    
    if (error) {
      return error;
    }

    if (!user) {
      return NextResponse.json(
        { error: 'Authentication failed' },
        { status: 401 }
      );
    }

    // Check admin role
    const roleError = requireAdmin(user);
    if (roleError) {
      return roleError;
    }

    const body = await request.json();
    const { userId, role } = body;

    if (!userId || !role || !['admin', 'user'].includes(role)) {
      return NextResponse.json(
        { error: 'Valid userId and role (admin/user) are required' },
        { status: 400 }
      );
    }

    // Prevent admin from changing their own role
    if (userId === user.userId) {
      return NextResponse.json(
        { error: 'Cannot change your own role' },
        { status: 400 }
      );
    }

    // Update user role
    const updatedUser = await User.findByIdAndUpdate(
      userId,
      { role },
      { new: true }
    ).select('-password');

    if (!updatedUser) {
      return NextResponse.json(
        { error: 'User not found' },
        { status: 404 }
      );
    }

    return NextResponse.json(
      {
        message: 'User role updated successfully',
        user: {
          id: updatedUser._id,
          username: updatedUser.username,
          email: updatedUser.email,
          role: updatedUser.role,
          updatedAt: updatedUser.updatedAt,
        },
      },
      { status: 200 }
    );
  } catch (error) {
    console.error('Update user role error:', error);
    return NextResponse.json(
      { error: 'Failed to update user role' },
      { status: 500 }
    );
  }
}
