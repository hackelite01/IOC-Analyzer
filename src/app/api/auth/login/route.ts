import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/db';
import { User } from '@/lib/models/User';
import { comparePassword, generateToken } from '@/lib/auth';
import { logActivity } from '@/lib/middleware';

interface LoginRequest {
  email: string;
  password: string;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    await connectDB();

    const body: LoginRequest = await request.json();
    const { email, password } = body;

    // Validate input
    if (!email || !password) {
      return NextResponse.json(
        { error: 'Email and password are required' },
        { status: 400 }
      );
    }

    // Find user by email
    const user = await User.findOne({ email: email.toLowerCase() });
    
    if (!user) {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Verify password
    const isPasswordValid = await comparePassword(password, user.password);
    
    if (!isPasswordValid) {
      // Log failed login attempt
      await logActivity(user._id.toString(), 'LOGIN_FAILED', {
        email: user.email,
        reason: 'Invalid password',
      }, request);
      
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Generate JWT token
    const token = generateToken(user);

    // Log successful login
    await logActivity(user._id.toString(), 'LOGIN_SUCCESS', {
      email: user.email,
      username: user.username,
    }, request);

    // Return token and user data (without password)
    return NextResponse.json(
      {
        message: 'Login successful',
        token,
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
          createdAt: user.createdAt,
        },
      },
      { status: 200 }
    );
  } catch (error) {
    console.error('Login error:', error);
    return NextResponse.json(
      { error: 'Login failed' },
      { status: 500 }
    );
  }
}
