const mongoose = require('mongoose');

const assignedScheduleSchema = new mongoose.Schema({
  employee: { type: mongoose.Schema.Types.ObjectId, ref: 'Employee' },
  project: { type: mongoose.Schema.Types.ObjectId, ref: 'ProjectMaster' },
  practice: { type: mongoose.Schema.Types.ObjectId, ref: 'PracticeMaster' },
  date: Date,
  hours: Number,
  role: String,
  startDate: Date,
  endDate: Date,
  scheduledBy: String,
  scheduledAt: Date
});

module.exports = mongoose.model('AssignedSchedule', assignedScheduleSchema);