import { NextRequest, NextResponse } from 'next/server';
import connectDB from '@/lib/db';
import { User } from '@/lib/models/User';
import { hashPassword, validatePassword, validateEmail, validateUsername } from '@/lib/auth';
import { logActivity } from '@/lib/middleware';

interface RegisterRequest {
  username: string;
  email: string;
  password: string;
}

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    await connectDB();

    const body: RegisterRequest = await request.json();
    const { username, email, password } = body;

    // Validate input
    if (!username || !email || !password) {
      return NextResponse.json(
        { error: 'Username, email, and password are required' },
        { status: 400 }
      );
    }

    // Validate username
    const usernameValidation = validateUsername(username);
    if (!usernameValidation.isValid) {
      return NextResponse.json(
        { error: 'Invalid username', details: usernameValidation.errors },
        { status: 400 }
      );
    }

    // Validate email
    if (!validateEmail(email)) {
      return NextResponse.json(
        { error: 'Invalid email format' },
        { status: 400 }
      );
    }

    // Validate password
    const passwordValidation = validatePassword(password);
    if (!passwordValidation.isValid) {
      return NextResponse.json(
        { error: 'Invalid password', details: passwordValidation.errors },
        { status: 400 }
      );
    }

    // Check if user already exists
    const existingUser = await User.findOne({
      $or: [{ email: email.toLowerCase() }, { username }],
    });

    if (existingUser) {
      const field = existingUser.email === email.toLowerCase() ? 'email' : 'username';
      return NextResponse.json(
        { error: `User with this ${field} already exists` },
        { status: 409 }
      );
    }

    // Hash password
    const hashedPassword = await hashPassword(password);

    // Create user
    const user = new User({
      username,
      email: email.toLowerCase(),
      password: hashedPassword,
      role: 'user', // Default role
    });

    await user.save();

    // Log registration activity
    await logActivity(user._id.toString(), 'USER_REGISTERED', {
      username,
      email: user.email,
    }, request);

    // Return user data (without password)
    return NextResponse.json(
      {
        message: 'User registered successfully',
        user: {
          id: user._id,
          username: user.username,
          email: user.email,
          role: user.role,
          createdAt: user.createdAt,
        },
      },
      { status: 201 }
    );
  } catch (error) {
    console.error('Registration error:', error);
    
    if (error instanceof Error && error.message.includes('duplicate key')) {
      return NextResponse.json(
        { error: 'User with this email or username already exists' },
        { status: 409 }
      );
    }
    
    return NextResponse.json(
      { error: 'Registration failed' },
      { status: 500 }
    );
  }
}
