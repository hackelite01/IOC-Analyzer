#!/usr/bin/env node

/**
 * Simple test script to verify authentication endpoints
 * Run with: node test-auth.js
 */

const BASE_URL = 'http://localhost:3001';

async function testAuth() {
  console.log('🧪 Testing Authentication System...\n');

  try {
    // Test 1: Register a new user
    console.log('1️⃣ Testing user registration...');
    const registerResponse = await fetch(`${BASE_URL}/api/auth/register`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        username: 'testuser',
        email: 'test@example.com',
        password: 'TestPass123'
      })
    });

    if (registerResponse.ok) {
      const registerData = await registerResponse.json();
      console.log('✅ Registration successful:', registerData.user.username);
    } else {
      const error = await registerResponse.json();
      console.log('⚠️ Registration response:', error.error);
    }

    // Test 2: Login
    console.log('\n2️⃣ Testing user login...');
    const loginResponse = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'test@example.com',
        password: 'TestPass123'
      })
    });

    if (loginResponse.ok) {
      const loginData = await loginResponse.json();
      const token = loginData.token;
      console.log('✅ Login successful! Token received.');

      // Test 3: Get user profile
      console.log('\n3️⃣ Testing authenticated endpoint (/me)...');
      const profileResponse = await fetch(`${BASE_URL}/api/auth/me`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (profileResponse.ok) {
        const profileData = await profileResponse.json();
        console.log('✅ Profile access successful:', profileData.user.username);
      } else {
        console.log('❌ Profile access failed');
      }

      // Test 4: Test activities endpoint
      console.log('\n4️⃣ Testing activities endpoint...');
      const activitiesResponse = await fetch(`${BASE_URL}/api/activities`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (activitiesResponse.ok) {
        const activitiesData = await activitiesResponse.json();
        console.log(`✅ Activities access successful! Found ${activitiesData.activities.length} activities`);
      } else {
        console.log('❌ Activities access failed');
      }

      // Test 5: Test protected dashboard
      console.log('\n5️⃣ Testing protected dashboard...');
      const dashboardResponse = await fetch(`${BASE_URL}/api/dashboard`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
      });

      if (dashboardResponse.ok) {
        console.log('✅ Dashboard access successful!');
      } else {
        console.log('❌ Dashboard access failed');
      }

    } else {
      const loginError = await loginResponse.json();
      console.log('❌ Login failed:', loginError.error);
    }

    // Test 6: Test admin login
    console.log('\n6️⃣ Testing admin login...');
    const adminLoginResponse = await fetch(`${BASE_URL}/api/auth/login`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        email: 'admin@ioc-analyzer.com',
        password: 'admin123'
      })
    });

    if (adminLoginResponse.ok) {
      const adminData = await adminLoginResponse.json();
      const adminToken = adminData.token;
      console.log('✅ Admin login successful!');

      // Test admin-only endpoint
      console.log('\n7️⃣ Testing admin users endpoint...');
      const usersResponse = await fetch(`${BASE_URL}/api/admin/users`, {
        method: 'GET',
        headers: {
          'Authorization': `Bearer ${adminToken}`,
        },
      });

      if (usersResponse.ok) {
        const usersData = await usersResponse.json();
        console.log(`✅ Admin users access successful! Found ${usersData.users.length} users`);
      } else {
        console.log('❌ Admin users access failed');
      }
    } else {
      console.log('⚠️ Admin login failed (this is expected if admin user doesn\'t exist)');
    }

    console.log('\n🎉 Authentication system test completed!');

  } catch (error) {
    console.error('❌ Test error:', error.message);
  }
}

// Run tests
testAuth();
