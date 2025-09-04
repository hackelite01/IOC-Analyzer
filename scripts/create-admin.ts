import mongoose from 'mongoose';
import { User } from '@/lib/models/User';
import { hashPassword } from '@/lib/auth';
import connectDB from '@/lib/db';

async function createAdminUser() {
  try {
    await connectDB();
    
    console.log('Creating admin user: mayank@forensiccybertech.com...');

    // Check if this specific admin user already exists
    const existingAdmin = await User.findOne({ email: 'mayank@forensiccybertech.com' });
    
    if (existingAdmin) {
      console.log('Admin user already exists:', existingAdmin.email);
      console.log('Current role:', existingAdmin.role);
      
      // If user exists but is not admin, upgrade to admin
      if (existingAdmin.role !== 'admin') {
        existingAdmin.role = 'admin';
        await existingAdmin.save();
        console.log('✅ User role updated to admin!');
      }
      
      return;
    }

    // Generate a secure password for the admin user
    const adminPassword = 'ForensicCyber2025!'; // Strong password
    const hashedPassword = await hashPassword(adminPassword);

    // Create admin user
    const adminUser = new User({
      username: 'mayank_admin',
      email: 'mayank@forensiccybertech.com',
      password: hashedPassword,
      role: 'admin',
    });

    await adminUser.save();
    
    console.log('✅ Admin user created successfully!');
    console.log('📧 Email: mayank@forensiccybertech.com');
    console.log('🔑 Password: ForensicCyber2025!');
    console.log('👑 Role: admin');
    console.log('📅 Created:', new Date().toISOString());
    
    console.log('\n🚨 IMPORTANT: Please change the password after first login!');
    
  } catch (error) {
    console.error('❌ Error creating admin user:', error);
    if (error instanceof Error) {
      console.error('Error details:', error.message);
    }
  } finally {
    await mongoose.connection.close();
    console.log('📶 Database connection closed.');
  }
}

// Run the script
createAdminUser();
