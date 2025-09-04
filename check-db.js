const mongoose = require('mongoose');

const IOCSchema = new mongoose.Schema({
  ioc: { type: String, required: true, unique: true },
  type: { type: String, required: true },
  fetchedAt: { type: Date, default: Date.now },
  vt: {
    normalized: {
      verdict: String,
      categories: [String],
      tags: [String],
      stats: {
        malicious: Number,
        suspicious: Number,
        harmless: Number,
        undetected: Number,
        timeout: Number
      },
      providers: [{
        category: String,
        engine_name: String,
        result: String
      }]
    }
  }
});

const IOC = mongoose.model('IOC', IOCSchema);

async function checkDatabase() {
  try {
    await mongoose.connect('mongodb://localhost:27017/ioc-analyzer');
    console.log('Connected to MongoDB');
    
    const total = await IOC.countDocuments();
    console.log('Total IOCs in database:', total);
    
    if (total === 0) {
      console.log('No IOCs found in database. This explains why Threat Vector Analysis is empty.');
      console.log('You need to analyze some IOCs first using the /analyze page.');
      return;
    }
    
    const verdicts = await IOC.aggregate([
      { $group: { _id: '$vt.normalized.verdict', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);
    
    console.log('\nVerdict distribution:');
    verdicts.forEach(v => console.log(`${v._id}: ${v.count}`));
    
    const maliciousCount = await IOC.countDocuments({
      'vt.normalized.verdict': { $in: ['malicious', 'suspicious'] }
    });
    
    console.log(`\nMalicious/Suspicious IOCs: ${maliciousCount}`);
    
    if (maliciousCount === 0) {
      console.log('No malicious/suspicious IOCs found. This explains the empty Threat Vector Analysis.');
      console.log('Try analyzing some known malicious IOCs or malware hashes to see threat categorization.');
    }
    
  } catch (error) {
    console.error('Error:', error.message);
  } finally {
    await mongoose.connection.close();
  }
}

checkDatabase();
