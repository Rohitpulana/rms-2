# Manager Audit Logging Implementation

## Overview
Complete audit logging system for tracking all manager actions in the Resource Management System (RMS). This system captures every create, update, and delete operation performed by managers across all scheduling and resource allocation pages.

## Key Features
- **Manager-Only Tracking**: Audit logs only manager actions, not admin actions
- **Comprehensive Coverage**: Tracks all CRUD operations across manager interfaces
- **Detailed Change Tracking**: Captures before/after states with descriptive messages
- **Revert Capability**: Allows admins to revert manager changes when needed
- **Route-Specific Context**: Identifies which page/interface the action was performed from

## Database Schema

### AuditLog Model (`models/AuditLog.js`)
```javascript
{
  manager: String,           // Manager's email address
  action: String,           // Type of action: create, update, delete, bulk_assign, bulk_replace
  route: String,            // Source route: manager-schedule, manager-assigned-resources, manager-calendar-view
  assignmentId: ObjectId,   // Reference to affected AssignedSchedule (when applicable)
  description: String,      // Human-readable description of the action
  changes: Object,          // Detailed before/after states and operation metadata
  timestamp: Date,          // When the action occurred
  canRevert: Boolean        // Whether this action can be reverted by admin
}
```

## Tracked Operations

### 1. Manager Schedule Form (`/manager-schedule`)
**Route**: `manager-schedule`

- **Single Employee Assignment**
  - Action: `create`
  - Captures: Employee details, project assignments, date range, hours distribution
  - Description: "Assigned [Employee Name] to [Projects] from [StartDate] to [EndDate]"

- **Multiple Employee Assignment**
  - Action: `bulk_assign`
  - Captures: All selected employees, project details, date ranges
  - Description: "Bulk assigned [N] employees to [Projects] from [StartDate] to [EndDate]"

### 2. Manager Assigned Resources (`/manager-assigned-resources`)
**Route**: `manager-assigned-resources`

- **Update Assignment**
  - Action: `update`
  - Captures: Original vs modified daily hours, project changes
  - Description: "Updated assignment for [Employee] on [Project]: [changes]"

- **Delete Assignment**
  - Action: `delete`
  - Captures: Complete assignment details before deletion
  - Description: "Deleted assignment for [Employee] on [Project] ([total hours]h over [days] days)"

### 3. Manager Calendar View (`/manager-calendar-view`)
**Route**: `manager-calendar-view`

#### Standard CRUD Operations
- **Create Assignment**
  - Action: `create`
  - Captures: Employee, project, date, hours
  - Description: "Created assignment: [Employee] → [Project] on [Date] ([Hours]h)"

- **Update Assignment**
  - Action: `update`
  - Captures: Before/after hours, project changes
  - Description: "Updated [Employee] on [Date]: [changes]"

- **Delete Assignment**
  - Action: `delete`
  - Captures: Deleted assignment details
  - Description: "Deleted [Employee] → [Project] on [Date] ([Hours]h)"

#### Drag-and-Drop Operations
- **Multi-Project Drag Fill**
  - Action: `bulk_assign`
  - Operation: `multi_project_drag_fill`
  - Captures: Source projects, target cells, success/failure counts
  - Description: "Multi-project drag-filled: [Projects] to [N] cells"

- **Row Drag Fill**
  - Action: `bulk_assign`
  - Operation: `row_drag_fill`
  - Captures: Source employee/date, projects, target employees
  - Description: "Row drag-filled from [Employee] on [Date]: [Projects] to [N] cells"

- **Cell Replace Drag Fill**
  - Action: `bulk_replace`
  - Operation: `cell_replace_drag_fill`
  - Captures: Source cell content, replaced cells, total hours
  - Description: "Cell replace drag-filled from [Employee] on [Date]: [Projects] replacing content in [N] cells"

## Utility Functions

### `logAuditAction(params)`
Creates audit log entries with automatic employee/project name resolution.

**Parameters:**
- `manager`: Manager's email from session
- `action`: Action type (create, update, delete, bulk_assign, bulk_replace)
- `route`: Source route identifier
- `assignmentId`: (Optional) Reference to AssignedSchedule
- `description`: Human-readable description
- `changes`: Detailed change information
- `canRevert`: (Optional) Whether action can be reverted

### `revertAuditLog(auditId, adminEmail)`
Reverts a manager action (admin only).

**Process:**
1. Validates audit log exists and can be reverted
2. Restores previous state from `changes.before`
3. Creates new audit entry documenting the revert
4. Marks original audit as reverted

## Implementation Details

### Session Integration
All audit logging checks for manager role:
```javascript
if (req.session.user && req.session.user.role === 'manager') {
  await logAuditAction({...});
}
```

### Error Handling
Audit logging failures don't break the main operation:
```javascript
try {
  await logAuditAction({...});
} catch (auditError) {
  console.error('Error creating audit log:', auditError);
  // Main operation continues
}
```

### Change Detail Structure
Standardized format for different operation types:
```javascript
changes: {
  operation: 'specific_operation_type',
  before: { /* previous state */ },
  after: { /* new state */ },
  // Operation-specific metadata
}
```

## Testing

### Test File: `test-manager-audit-logging.js`
Comprehensive test script that:
- Displays recent audit entries
- Groups entries by route and action type
- Shows manager activity summaries
- Validates audit log structure

### Running Tests
```bash
node test-manager-audit-logging.js
```

## Usage Examples

### Admin Viewing Audit Logs
```javascript
// Get all manager actions in last 24 hours
const recentAudits = await AuditLog.find({
  timestamp: { $gte: new Date(Date.now() - 24*60*60*1000) }
}).sort({ timestamp: -1 });

// Get specific manager's actions
const managerAudits = await AuditLog.find({
  manager: 'manager.DIH@cbsl.com'
}).sort({ timestamp: -1 });

// Get actions on specific route
const calendarAudits = await AuditLog.find({
  route: 'manager-calendar-view'
}).sort({ timestamp: -1 });
```

### Admin Reverting Manager Action
```javascript
// Revert a manager's assignment change
const result = await revertAuditLog(auditId, 'admin@company.com');
if (result.success) {
  console.log('Action reverted successfully');
} else {
  console.log('Revert failed:', result.message);
}
```

## Security Considerations

1. **Role-Based Access**: Only managers trigger audit logs
2. **Admin-Only Revert**: Only admins can revert manager actions
3. **Immutable Logs**: Audit entries cannot be modified, only marked as reverted
4. **Session Validation**: All operations validate user session and role

## Benefits

1. **Accountability**: Complete trail of who did what and when
2. **Error Recovery**: Ability to revert problematic manager changes
3. **Compliance**: Detailed audit trail for organizational requirements
4. **Debugging**: Easy identification of when/how scheduling issues occurred
5. **Performance Monitoring**: Track bulk operation success rates

## Future Enhancements

1. **Admin Dashboard**: Web interface for viewing/managing audit logs
2. **Alerts**: Notifications for suspicious or bulk manager activities
3. **Reporting**: Scheduled reports of manager activity summaries
4. **Retention Policies**: Automatic cleanup of old audit entries
5. **Export Functionality**: CSV/Excel export of audit data

This comprehensive audit logging system ensures complete visibility into all manager actions while maintaining system performance and providing robust error recovery capabilities.
