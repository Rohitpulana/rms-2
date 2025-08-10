require('dotenv').config();
const mongoose = require('mongoose');
const AuditLog = require('./models/AuditLog');

// Connect to MongoDB
mongoose.connect(process.env.MONGODB_URI).then(async () => {
  console.log('Connected to MongoDB for audit test');
  
  // Test creating an audit log entry
  try {
    const testAudit = await AuditLog.create({
      manager: 'test@cbsl.com',
      managerName: 'Test Manager',
      action: 'create',
      employeeCode: 'EMP001',
      employeeName: 'Test Employee',
      projectName: 'Test Project',
      description: 'Test audit log entry',
      changes: { hours: 8 },
      route: '/test',
      timestamp: new Date()
    });
    
    console.log('✅ Audit log created successfully:', testAudit);
    
    // Check if we can retrieve it
    const retrievedAudit = await AuditLog.findById(testAudit._id);
    console.log('✅ Audit log retrieved successfully:', retrievedAudit);
    
    // Clean up test data
    await AuditLog.findByIdAndDelete(testAudit._id);
    console.log('✅ Test audit log cleaned up');
    
  } catch (err) {
    console.error('❌ Error testing audit log:', err);
  }
  
  mongoose.disconnect();
}).catch(err => {
  console.error('❌ MongoDB connection error:', err);
});
