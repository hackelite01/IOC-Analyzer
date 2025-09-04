#!/usr/bin/env node

/**
 * Test script to verify the admin user login
 * Run with: node test-admin-login.js
 */

const BASE_URL = 'http://localhost:3000';

async function testAdminLogin() {
  console.log('🧪 Testing Admin Login for mayank@forensiccybertech.com...\n');

  try {
    // Test admin login
    console.log('🔑 Attempting admin login...');
    const loginResponse = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'mayank@forensiccybertech.com',
        password: 'ForensicCyber2025!'
      })
    });

    if (loginResponse.ok) {
      const loginData = await loginResponse.json();
      const token = loginData.token;
      console.log('✅ Admin login successful!');
      console.log('👤 User:', loginData.user.username);
      console.log('📧 Email:', loginData.user.email);
      console.log('👑 Role:', loginData.user.role);

      // Test admin-only endpoint
      console.log('\n🛡️ Testing admin permissions...');
      const usersResponse = await fetch(`${BASE_URL}/api/admin/users`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (usersResponse.ok) {
        const usersData = await usersResponse.json();
        console.log(`✅ Admin users endpoint accessible! Found ${usersData.users.length} users`);
        console.log('📊 User stats:', usersData.stats);
      } else {
        const error = await usersResponse.json();
        console.log('❌ Admin users endpoint failed:', error.error);
      }

      // Test profile
      console.log('\n👤 Getting admin profile...');
      const profileResponse = await fetch(`${BASE_URL}/api/auth/me`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (profileResponse.ok) {
        const profileData = await profileResponse.json();
        console.log('✅ Profile retrieved successfully!');
        console.log('🆔 ID:', profileData.user.id);
        console.log('📅 Created:', new Date(profileData.user.createdAt).toLocaleString());
      }

    } else {
      const error = await loginResponse.json();
      console.log('❌ Admin login failed:', error.error);
      
      if (error.error === 'Invalid credentials') {
        console.log('\n💡 This might mean:');
        console.log('   1. The admin user was not created yet');
        console.log('   2. The password is incorrect');
        console.log('   3. The email is incorrect');
        console.log('\n🔧 Try running: npm run create-admin');
      }
    }

  } catch (error) {
    console.error('❌ Test error:', error.message);
    
    if (error.code === 'ECONNREFUSED') {
      console.log('\n💡 Make sure the server is running:');
      console.log('   npm run dev');
    }
  }
}

// Run the test
testAdminLogin();
