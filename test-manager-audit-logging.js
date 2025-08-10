const mongoose = require('mongoose');
const AuditLog = require('./models/AuditLog');

// Connect to MongoDB
mongoose.connect('mongodb://localhost:27017/rms_database', {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

async function testAuditLogging() {
  console.log('=== Testing Manager Audit Logging ===\n');

  try {
    // Get all audit logs created by managers
    const managerAudits = await AuditLog.find({}).sort({ timestamp: -1 }).limit(20);
    
    console.log(`Found ${managerAudits.length} recent audit entries:\n`);

    managerAudits.forEach((audit, index) => {
      console.log(`${index + 1}. [${audit.timestamp.toLocaleString()}]`);
      console.log(`   Manager: ${audit.manager}`);
      console.log(`   Action: ${audit.action}`);
      console.log(`   Route: ${audit.route}`);
      console.log(`   Description: ${audit.description}`);
      
      if (audit.changes) {
        console.log(`   Operation: ${audit.changes.operation || 'standard'}`);
        
        // Show specific details based on operation type
        if (audit.changes.operation === 'multi_project_drag_fill') {
          console.log(`   - Projects: ${audit.changes.projects.length} projects`);
          console.log(`   - Target cells: ${audit.changes.targets.length} cells`);
          console.log(`   - Results: ${audit.changes.results.updated} updated, ${audit.changes.results.failed} failed`);
        } else if (audit.changes.operation === 'row_drag_fill') {
          console.log(`   - Source: ${audit.changes.source.employee} on ${audit.changes.source.date}`);
          console.log(`   - Projects: ${audit.changes.source.projects.length} projects`);
          console.log(`   - Results: ${audit.changes.results.updated} employees updated`);
        } else if (audit.changes.operation === 'cell_replace_drag_fill') {
          console.log(`   - Source: ${audit.changes.source.employee} (${audit.changes.source.totalHours}h total)`);
          console.log(`   - Results: ${audit.changes.results.updated} cells replaced`);
        } else if (audit.changes.before && audit.changes.after) {
          console.log(`   - Before: ${JSON.stringify(audit.changes.before).substring(0, 100)}...`);
          console.log(`   - After: ${JSON.stringify(audit.changes.after).substring(0, 100)}...`);
        }
      }
      
      console.log(`   Can Revert: ${audit.canRevert}`);
      console.log('   ---\n');
    });

    // Test grouping by route
    console.log('\n=== Audit Entries by Route ===');
    const routeCounts = await AuditLog.aggregate([
      { $group: { _id: '$route', count: { $sum: 1 }, lastActivity: { $max: '$timestamp' } } },
      { $sort: { count: -1 } }
    ]);

    routeCounts.forEach(route => {
      console.log(`${route._id}: ${route.count} entries (last: ${route.lastActivity.toLocaleString()})`);
    });

    // Test grouping by action type
    console.log('\n=== Audit Entries by Action Type ===');
    const actionCounts = await AuditLog.aggregate([
      { $group: { _id: '$action', count: { $sum: 1 } } },
      { $sort: { count: -1 } }
    ]);

    actionCounts.forEach(action => {
      console.log(`${action._id}: ${action.count} entries`);
    });

    // Test finding specific manager activities
    console.log('\n=== Manager Activity Summary ===');
    const managerCounts = await AuditLog.aggregate([
      { $group: { _id: '$manager', count: { $sum: 1 }, lastActivity: { $max: '$timestamp' } } },
      { $sort: { count: -1 } }
    ]);

    managerCounts.forEach(manager => {
      console.log(`${manager._id}: ${manager.count} actions (last: ${manager.lastActivity.toLocaleString()})`);
    });

    console.log('\n=== Audit Logging Test Complete ===');

  } catch (error) {
    console.error('Error testing audit logging:', error);
  } finally {
    mongoose.connection.close();
  }
}

// Run the test
testAuditLogging();
