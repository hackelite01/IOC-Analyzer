// MongoDB initialization script
db = db.getSiblingDB('ioc-analyzer');

// Create collections with validation
db.createCollection('iocs', {
  validator: {
    $jsonSchema: {
      bsonType: 'object',
      required: ['ioc', 'type', 'vt'],
      properties: {
        ioc: { bsonType: 'string' },
        type: { enum: ['ip', 'domain', 'url', 'hash'] },
        label: { bsonType: 'string' },
        vt: {
          bsonType: 'object',
          required: ['raw', 'normalized'],
          properties: {
            raw: { bsonType: 'object' },
            normalized: {
              bsonType: 'object',
              required: ['verdict', 'stats'],
              properties: {
                verdict: { enum: ['malicious', 'suspicious', 'harmless', 'undetected', 'unknown'] },
                stats: {
                  bsonType: 'object',
                  required: ['malicious', 'suspicious', 'harmless', 'undetected'],
                  properties: {
                    malicious: { bsonType: 'number', minimum: 0 },
                    suspicious: { bsonType: 'number', minimum: 0 },
                    harmless: { bsonType: 'number', minimum: 0 },
                    undetected: { bsonType: 'number', minimum: 0 },
                    timeout: { bsonType: 'number', minimum: 0 }
                  }
                }
              }
            }
          }
        },
        fetchedAt: { bsonType: 'date' },
        updatedAt: { bsonType: 'date' },
        cacheTtlSec: { bsonType: 'number', minimum: 0 }
      }
    }
  }
});

// Create indexes
db.iocs.createIndex({ 'ioc': 1, 'type': 1 }, { unique: true });
db.iocs.createIndex({ 'vt.normalized.verdict': 1 });
db.iocs.createIndex({ 'fetchedAt': -1 });
db.iocs.createIndex({ 'label': 1 });
db.iocs.createIndex({ 'meta.caseId': 1 });

print('IOC Analyzer database initialized successfully');
