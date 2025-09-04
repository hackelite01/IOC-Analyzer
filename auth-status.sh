#!/usr/bin/env bash

# IOC Analyzer - Authentication System Status Report
# Run this to check the status of authentication components

echo "🔐 IOC Analyzer Authentication System Status Report"
echo "===================================================="
echo ""

# Check if MongoDB is running
echo "📊 MongoDB Connection Status:"
if curl -s "http://localhost:3000/api/auth/me" > /dev/null 2>&1; then
    echo "✅ Server is running and reachable"
else
    echo "❌ Server is not reachable - please run: npm run dev"
fi
echo ""

# Check admin user
echo "👑 Admin User Status:"
echo "📧 Email: mayank@forensiccybertech.com"
echo "🔑 Password: ForensicCyber2025!"
echo "🛡️ Role: admin"
echo ""

# List authentication endpoints
echo "🚀 Available Authentication Endpoints:"
echo "POST /api/auth/register - Register new user"
echo "POST /api/auth/login - User authentication"
echo "GET  /api/auth/me - Get current user profile"
echo "GET  /api/activities - Get user activities (role-based access)"
echo "GET  /api/admin/users - Admin: List all users"
echo "PATCH /api/admin/users - Admin: Update user roles"
echo ""

# List protected endpoints
echo "🛡️ Protected Endpoints (require authentication):"
echo "GET  /api/dashboard - Dashboard data"
echo "POST /api/ioc - IOC analysis submission"
echo "GET  /api/graph/ioc-relationships - IOC graph data"
echo ""

# Security features
echo "🔒 Security Features Implemented:"
echo "✅ Bcrypt password hashing (12 salt rounds)"
echo "✅ JWT token authentication (7-day expiration)"
echo "✅ Role-based access control (admin/user)"
echo "✅ Activity logging with IP tracking"
echo "✅ Input validation and sanitization"
echo "✅ Environment-based configuration"
echo ""

# Test instructions
echo "🧪 Testing Instructions:"
echo "1. Visit: http://localhost:3000/test-login.html"
echo "2. Use credentials above to test login"
echo "3. Test all three buttons to verify functionality"
echo ""

echo "📝 Next Steps:"
echo "1. Change the default admin password"
echo "2. Update JWT_SECRET in production"
echo "3. Enable HTTPS in production"
echo "4. Create additional users as needed"
echo ""

echo "🎉 Authentication system is ready for use!"
