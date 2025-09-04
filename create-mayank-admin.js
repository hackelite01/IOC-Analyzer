const { MongoClient } = require('mongodb');
const bcrypt = require('bcryptjs');

async function createMayankAdmin() {
  const client = new MongoClient('mongodb://localhost:27017');
  
  try {
    await client.connect();
    console.log('✅ Connected to MongoDB');
    
    const db = client.db('ioc-analyzer');
    const users = db.collection('users');
    
    // Check if user already exists
    const existingUser = await users.findOne({ email: 'mayank@forensiccybertech.com' });
    
    if (existingUser) {
      console.log('👤 User already exists:', existingUser.email);
      
      // Update role to admin if not already
      if (existingUser.role !== 'admin') {
        await users.updateOne(
          { email: 'mayank@forensiccybertech.com' },
          { $set: { role: 'admin', updatedAt: new Date() } }
        );
        console.log('✅ Role updated to admin!');
      }
    } else {
      // Create new admin user
      const hashedPassword = await bcrypt.hash('ForensicCyber2025!', 12);
      
      const adminUser = {
        username: 'mayank_admin',
        email: 'mayank@forensiccybertech.com',
        password: hashedPassword,
        role: 'admin',
        createdAt: new Date(),
        updatedAt: new Date()
      };
      
      const result = await users.insertOne(adminUser);
      console.log('✅ Admin user created successfully!');
      console.log('🆔 User ID:', result.insertedId);
    }
    
    console.log('\n📧 Email: mayank@forensiccybertech.com');
    console.log('🔑 Password: ForensicCyber2025!');
    console.log('👑 Role: admin');
    console.log('\n🚨 Please change the password after first login!');
    
  } catch (error) {
    console.error('❌ Error:', error.message);
  } finally {
    await client.close();
    console.log('📶 Database connection closed');
  }
}

createMayankAdmin();
