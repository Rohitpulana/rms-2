
require('dotenv').config();
// Manager: Assign Schedule POST

const express = require('express');
const session = require('express-session');
const csrf = require('csurf');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const path = require('path');
const multer = require('multer');
const xlsx = require('xlsx');
const fs = require('fs');
const cookieParser = require('cookie-parser');
const mongoose = require('mongoose');


// Models
const Employee = require('./models/Employee');
const ProjectMaster = require('./models/ProjectMaster');
const PracticeMaster = require('./models/PracticeMaster');
const AssignedSchedule = require('./models/AssignedSchedule');


// mongoose.connect('mongodb://127.0.0.1:27017/hrms-app', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true
// }).then(() => console.log('✅ MongoDB connected'))
//   .catch(err => console.error('❌ MongoDB error:', err));

const mongoURI = process.env.MONGODB_URI;

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB atlas successfully');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});


const app = express();
const port = 3000;
app.use(express.json());

// Dummy Users
const users = [
  {
    email: 'admin@cbsl.com',
    password: bcrypt.hashSync('admin123', 10),
    role: 'admin'
  },
  {
    email: 'manager.DIH@cbsl.com',
    password: bcrypt.hashSync('123', 10),
    role: 'manager'
  }
];

// Multer for uploads
const upload = multer({ dest: 'uploads/' });

// EJS
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));
const expressLayouts = require('express-ejs-layouts');
app.use(expressLayouts);
app.set('layout', 'sidebar-layout');

// Middleware
app.use(express.static(path.join(__dirname, 'public')));
app.use(bodyParser.urlencoded({ extended: false }));
app.use(cookieParser());

// Session
app.use(session({
  secret: 'mySecretKey',
  resave: false,
  saveUninitialized: true,
  cookie: {
    secure: false,
    httpOnly: true,
    sameSite: 'strict'
  }
}));

// CSRF
const csrfProtection = csrf({ cookie: false });

app.use((err, req, res, next) => {
  if (err.code === 'EBADCSRFTOKEN') {
    console.log('CSRF Token Error:', {
      received: req.body._csrf,
      session: req.session.csrfSecret
    });
    return res.status(403).send('Invalid CSRF token');
  }
  next(err);
});

// Auth Middleware
function isAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.session.user?.role === 'admin') return next();
  res.status(403).render('error', { 
    message: 'Access denied: Only administrators can access this page.',
    layout: false,
    title: 'Access Denied',
    user: req.session.user
  });
}

// Login Routes

app.get('/', (req, res) => {
  res.redirect('login');
});

app.get('/login', csrfProtection, (req, res) => {
  res.render('login', {
    title: 'Login',
    messages: [],
    hasErrors: false,
    csrfToken: req.csrfToken(),
    layout: false
  });
});

app.post('/login', csrfProtection, async (req, res) => {
  const { email, password } = req.body;
  const user = users.find(u => u.email === email);

  if (!user || !(await bcrypt.compare(password, user.password))) {
    return res.render('login', {
      title: 'Login',
      messages: ['Invalid credentials'],
      hasErrors: true,
      layout: false,
      csrfToken: req.csrfToken()
    });
  }

  req.session.user = user;

  if (user.role === 'manager') return res.redirect('/dashboard/manager');
  if (user.role === 'admin') return res.redirect('/dashboard/admin');
  res.status(403).send('Unauthorized role');
});

// Dashboards

// Manager Dashboard with sidebar (only Schedule & Assigned Resources)
app.get('/dashboard/manager', isAuth, (req, res) => {
  res.render('manager-welcome', {
    title: 'Manager Dashboard',
    layout: 'sidebar-layout',
    manager: true // flag for sidebar rendering
  });
});


// Manager Calendar Route
app.get('/dashboard/manager/calendar-view', (req, res) => {
    // Manager Calendar View: fetch and pass all required data
    (async () => {
        try {
            const monthFilter = req.query.month || '';

            // Get all schedules (optionally, you can filter by manager's employees/projects if needed)
            const allSchedules = await AssignedSchedule.find()
                .populate('employee')
                .populate('project');

            // Generate dateRange for the selected month (or current month if not selected), skipping weekends
            let year, month;
            if (monthFilter) {
                const parts = monthFilter.split('-');
                year = parseInt(parts[0], 10);
                month = parseInt(parts[1], 10) - 1;
            } else {
                const now = new Date();
                year = now.getFullYear();
                month = now.getMonth();
            }
            const daysInMonth = new Date(year, month + 1, 0).getDate();
            const dateRange = [];
            for (let d = 1; d <= daysInMonth; d++) {
                const dateObj = new Date(year, month, d);
                const dayOfWeek = dateObj.getDay();
                if (dayOfWeek === 0 || dayOfWeek === 6) continue; // skip Sunday/Saturday
                const day = dateObj.getDate();
                const monthName = dateObj.toLocaleString('default', { month: 'short' });
                dateRange.push(`${day}-${monthName}`);
            }

            // Get all employees
            const allEmployees = await Employee.find({}, 'empCode name division designation');

            // Build empDayProjects: { empCode: { date: [ { projectName, hours } ] } }
            const empDayProjects = {};
            allSchedules.forEach(s => {
                const empCode = s.employee?.empCode || 'N/A';
                if (!empDayProjects[empCode]) empDayProjects[empCode] = {};
                if (s.dailyHours && s.project && s.project.projectName) {
                    Object.keys(s.dailyHours).forEach(dateKey => {
                        if (!empDayProjects[empCode][dateKey]) empDayProjects[empCode][dateKey] = [];
                        empDayProjects[empCode][dateKey].push({
                            projectName: s.project.projectName,
                            projectId: s.project._id,
                            assignmentId: s._id,
                            hours: Number(s.dailyHours[dateKey]) || 0
                        });
                    });
                }
            });

            res.render('manager-calendar-view', {
                year: year,
                month: month + 1, // for display
                dateRange,
                allEmployees,
                empDayProjects,
                layout: 'sidebar-layout',
                title: 'Manager Calendar View',
                manager: true
            });
        } catch (err) {
            console.error('Error loading manager calendar view:', err);
            res.status(500).send('Internal Server Error');
        }
    })();
});

// Manager: Schedule page

app.get('/dashboard/manager/schedule', isAuth, async (req, res) => {
  try {
    const employees = await Employee.find();
    const projects = await ProjectMaster.find();
    // Get unique home practices from employees
    const practices = [...new Set(employees.map(emp => emp.homePractice).filter(Boolean))];
    res.render('manager-schedule', {
      employees,
      projects,
      practices,
      csrfToken: req.csrfToken ? req.csrfToken() : '',
      title: 'Manager Schedule',
      layout: 'sidebar-layout',
      manager: true
    });
  } catch (err) {
    console.error('Error loading manager schedule page:', err);
    res.status(500).send('Internal Server Error');
  }
});
app.post('/assigned-resources/add', isAuth, isAdmin, async (req, res) => {
  try {
    const { employee, project, dailyHours } = req.body;
    // Validation
    if (!employee || !project) {
      return res.status(400).json({ success: false, error: 'Employee and Project are required.' });
    }
    if (!dailyHours || typeof dailyHours !== 'object' || Object.keys(dailyHours).length === 0) {
      return res.status(400).json({ success: false, error: 'At least one daily hour entry is required.' });
    }
    // Validate daily hours: all values must be 0-8
    for (const key in dailyHours) {
      const val = Number(dailyHours[key]);
      if (isNaN(val) || val < 0 || val > 8) {
        return res.status(400).json({ success: false, error: `Invalid hours for ${key}: must be 0-8.` });
      }
    }
    // Check employee and project exist
    const employeeDoc = await Employee.findById(employee);
    const projectDoc = await ProjectMaster.findById(project);
    if (!employeeDoc || !projectDoc) {
      return res.status(400).json({ success: false, error: 'Employee or Project not found.' });
    }
    // Check for existing schedule for this employee/project
    let existingSchedule = await AssignedSchedule.findOne({ employee, project });
    if (existingSchedule) {
      // Merge/overwrite dailyHours
      existingSchedule.dailyHours = { ...existingSchedule.dailyHours, ...dailyHours };
      await existingSchedule.save();
      return res.status(200).json({ success: true, schedule: existingSchedule, updated: true });
    } else {
      const newSchedule = new AssignedSchedule({
        employee,
        project,
        dailyHours
      });
      await newSchedule.save();
      return res.status(201).json({ success: true, schedule: newSchedule, created: true });
    }
  } catch (err) {
    console.error('Error in POST /assigned-resources/add:', err);
    return res.status(500).json({ success: false, error: err.message });
  }
});

// Manager: Assigned Resources page
// Manager: Update assigned schedule (PUT)
app.put('/dashboard/manager/assigned-resources/:id', isAuth, async (req, res) => {
  try {
    const scheduleId = req.params.id;
    const updateFields = {};
    // Project name (optional)
    let projectName = req.body['project[projectName]'] || (req.body.project && req.body.project.projectName);
    if (projectName) {
      const projectDoc = await ProjectMaster.findOne({ projectName: projectName });
      if (projectDoc) {
        updateFields['project'] = projectDoc._id;
      }
    }
    // Daily hours
    let dailyHoursObj = {};
    if (req.body.dailyHours) {
      Object.keys(req.body.dailyHours).forEach(dateKey => {
        dailyHoursObj[dateKey] = Number(req.body.dailyHours[dateKey]) || 0;
      });
      updateFields['dailyHours'] = dailyHoursObj;
    }
    const updated = await AssignedSchedule.findByIdAndUpdate(
      scheduleId,
      { $set: updateFields },
      { new: true }
    );
    if (updated) {
      res.json({ success: true, schedule: updated });
    } else {
      res.status(404).json({ success: false, error: 'Schedule not found' });
    }
  } catch (err) {
    console.error('Manager PUT error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// Manager: Delete assigned schedule (DELETE)
app.delete('/dashboard/manager/assigned-resources/:id', isAuth, async (req, res) => {
  try {
    const scheduleId = req.params.id;
    const result = await AssignedSchedule.deleteOne({ _id: scheduleId });
    if (result.deletedCount > 0) {
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: 'Schedule not found' });
    }
  } catch (err) {
    console.error('Manager DELETE error:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

app.get('/dashboard/manager/assigned-resources', isAuth, async (req, res) => {
  try {
    // Get filter params
    const employeeFilter = req.query.employee || '';
    const projectFilter = req.query.project || '';
    const monthFilter = req.query.month || '';

    // Fetch schedules with populated employee and project data
    const schedules = await AssignedSchedule.find()
      .populate('employee')
      .populate('project');

    // Build query for AssignedSchedule
    let scheduleQuery = {};
    if (employeeFilter) {
      const empDoc = await Employee.findOne({ empCode: employeeFilter });
      if (empDoc) scheduleQuery.employee = empDoc._id;
    }
    if (projectFilter) {
      const projDoc = await ProjectMaster.findOne({ projectName: projectFilter });
      if (projDoc) scheduleQuery.project = projDoc._id;
    }

    // Only show one schedule per employee/project (latest)
    const allSchedules = await AssignedSchedule.find(scheduleQuery)
      .populate('employee')
      .populate('project')
      .populate('practice');
    const latestSchedules = {};
    for (const s of allSchedules) {
      const empId = s.employee?._id ? s.employee._id.toString() : String(s.employee);
      const projId = s.project?._id ? s.project._id.toString() : String(s.project);
      const key = `${empId}-${projId}`;
      if (!latestSchedules[key] || (s._id > latestSchedules[key]._id)) {
        latestSchedules[key] = s;
      }
    }
    const uniqueSchedules = Object.values(latestSchedules);

    // Generate dateRange for the selected month (or current month if not selected)
    let year, month;
    if (monthFilter) {
      const parts = monthFilter.split('-');
      year = parseInt(parts[0], 10);
      month = parseInt(parts[1], 10) - 1;
    } else {
      const now = new Date();
      year = now.getFullYear();
      month = now.getMonth();
    }
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const dateRange = [];
    for (let d = 1; d <= daysInMonth; d++) {
      const dateObj = new Date(year, month, d);
      const day = dateObj.getDate();
      const monthName = dateObj.toLocaleString('default', { month: 'short' });
      dateRange.push(`${day}-${monthName}`);
    }

    // Generate all dates for current year (YYYY-MM-DD)
    const allYearDates = [];
    let minDate = new Date(year + '-01-01');
    let maxDate = new Date(year + '-12-31');
    for (let d = new Date(minDate); d <= maxDate; d.setDate(d.getDate() + 1)) {
      let dateStr = d.toISOString().slice(0,10);
      allYearDates.push(dateStr);
    }

    // Get all employees and projects for filter dropdowns
    const allEmployees = await Employee.find({}, 'empCode name division designation');
    const allProjects = await ProjectMaster.find({}, 'projectName projectManager cbslClient dihClient');

    res.render('manager-assigned-resources', {
      schedules: schedules,
      dateRange,
      allYearDates,
      allEmployees,
      allProjects,
      employeeFilter,
      projectFilter,
      monthFilter,
      errorMessage: req.query.error || '',
      layout: 'sidebar-layout',
      title: 'Manager Assigned Resources',
      manager: true
    });
  } catch (err) {
    console.error('Error loading manager assigned resources page:', err);
    res.status(500).send('Internal Server Error');
  }
});


app.post('/dashboard/manager/schedule', isAuth, async (req, res) => {
  try {
    const empCodes = Array.isArray(req.body.emp_ids) ? req.body.emp_ids : [req.body.emp_ids];
    const filteredEmpCodes = empCodes.filter(code => code?.trim());
    const startDate = new Date(req.body.start_date);
    const endDate = new Date(req.body.end_date);

    // Validate dates
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return res.status(400).send('Invalid start or end date. Please select valid dates.');
    }
    if (endDate < startDate) {
      return res.status(400).send('End date must be after start date.');
    }

    function getDateKeysSkipWeekends(start, end) {
      const keys = [];
      let d = new Date(start);
      while (d <= end) {
        const dayOfWeek = d.getDay();
        if (dayOfWeek !== 0 && dayOfWeek !== 6) {
          const dateStr = d.toISOString().slice(0,10);
          keys.push({ key: dateStr, dateObj: new Date(d) });
        }
        d.setDate(d.getDate() + 1);
      }
      return keys;
    }
    const dateKeys = getDateKeysSkipWeekends(startDate, endDate);

    function formatDateKey(dateStr) {
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const d = new Date(dateStr);
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        return `${day}-${monthName}`;
      }
      return dateStr;
    }

    if (filteredEmpCodes.length === 1 && req.body['project_ids[]']) {
      const empCode = filteredEmpCodes[0];
      const employee = await Employee.findOne({ empCode });
      if (!employee) {
        console.warn('Employee not found:', empCode);
        return res.redirect('/dashboard/manager/assigned-resources');
      }
      const projectIds = Array.isArray(req.body['project_ids[]']) ? req.body['project_ids[]'] : [req.body['project_ids[]']];
      const hoursList = Array.isArray(req.body['hours_list[]']) ? req.body['hours_list[]'] : [req.body['hours_list[]']];

      let overAllocated = false;
      let overAllocDetails = [];
      for (const { key: dateKey, dateObj } of dateKeys) {
        let newTotal = 0;
        for (let i = 0; i < projectIds.length; i++) {
          newTotal += Number(hoursList[i]) || 0;
        }
        let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
        let existingTotal = 0;
        for (const sched of existingSchedules) {
          let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
          existingTotal += Number(dh) || 0;
        }
        for (let i = 0; i < projectIds.length; i++) {
          let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectIds[i] });
          if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
            existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
          }
        }
        let totalHours = existingTotal + newTotal;
        if (totalHours > 8) {
          overAllocated = true;
          overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
        }
      }
      if (overAllocated) {
        return res.redirect(`/dashboard/manager/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
      }

      for (let i = 0; i < projectIds.length; i++) {
        const projectId = projectIds[i];
        const hours = Number(hoursList[i]) || 0;
        const query = { employee: employee._id, project: projectId };
        let existingSchedule = await AssignedSchedule.findOne(query);
        let dailyHoursObj = {};
        if (existingSchedule && existingSchedule.dailyHours) {
          dailyHoursObj = { ...existingSchedule.dailyHours };
        }
        for (const { key: dateKey, dateObj } of dateKeys) {
          dailyHoursObj[formatDateKey(dateKey)] = hours;
        }
        await AssignedSchedule.findOneAndUpdate(query, {
          $setOnInsert: { employee: employee._id, project: projectId },
          $set: { dailyHours: dailyHoursObj, startDate, endDate },
        }, { upsert: true, new: true });
      }
    } else {
      const projectId = req.body.project_id;
      const hours = Number(req.body.hours) || 0;
      for (const empCode of filteredEmpCodes) {
        const employee = await Employee.findOne({ empCode });
        if (!employee) {
          console.warn('Employee not found:', empCode);
          continue;
        }
        let overAllocated = false;
        let overAllocDetails = [];
        for (const { key: dateKey, dateObj } of dateKeys) {
          let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
          let existingTotal = 0;
          for (const sched of existingSchedules) {
            let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
            existingTotal += Number(dh) || 0;
          }
          let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectId });
          if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
            existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
          }
          let totalHours = existingTotal + hours;
          if (totalHours > 8) {
            overAllocated = true;
            overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
          }
        }
        if (overAllocated) {
          return res.redirect(`/dashboard/manager/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
        }
        const query = { employee: employee._id, project: projectId };
        let existingSchedule = await AssignedSchedule.findOne(query);
        let dailyHoursObj = {};
        if (existingSchedule && existingSchedule.dailyHours) {
          dailyHoursObj = { ...existingSchedule.dailyHours };
        }
        for (const { key: dateKey, dateObj } of dateKeys) {
          dailyHoursObj[formatDateKey(dateKey)] = hours;
        }
        await AssignedSchedule.findOneAndUpdate(query, {
          $setOnInsert: { employee: employee._id, project: projectId },
          $set: { dailyHours: dailyHoursObj, startDate, endDate },
        }, { upsert: true, new: true });
      }
    }
    res.redirect('/dashboard/manager/assigned-resources');
  } catch (error) {
    console.error('Error assigning manager schedule:', error);
    res.status(500).send('Something went wrong');
  }
});

app.get('/dashboard/admin', isAuth, isAdmin, csrfProtection, (req, res) => {
  res.render('admin-welcome', {
    csrfToken: req.csrfToken(),
    title: 'Welcome Admin',
    layout: 'sidebar-layout'
  });
});

// ✅ Updated View Employees Route
app.get('/dashboard/admin/view-employees', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const search = req.query.search || '';
    const limit = req.query.limit ? (req.query.limit === 'all' ? 'all' : parseInt(req.query.limit)) : 'all';


    const query = {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { empCode: { $regex: search, $options: 'i' } },
        { payrollCompany: { $regex: search, $options: 'i' } },
        { division: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } },
        { designation: { $regex: search, $options: 'i' } },
        { homePractice: { $regex: search, $options: 'i' } },
        { practiceManager: { $regex: search, $options: 'i' } }
      ]
    };

    const employeesQuery = Employee.find(query);
    if (limit !== 'all') {
      employeesQuery.limit(limit);
    }

    const employees = await employeesQuery;

    res.render('admin-dashboard', {
      employees,
      search,
      limit,
      csrfToken: req.csrfToken(),
      title: 'View Employees',
      layout: 'sidebar-layout'
    });
  } catch (err) {
    console.error('Error fetching employees:', err);
    res.status(500).send('Error loading employee list.');
  }
});
// 🔍 API for dynamic search
app.get('/api/employees/search', isAuth, isAdmin, async (req, res) => {
  try {
    const search = req.query.q || '';

    const query = {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { empCode: { $regex: search, $options: 'i' } },
        { payrollCompany: { $regex: search, $options: 'i' } },
        { division: { $regex: search, $options: 'i' } },
        { location: { $regex: search, $options: 'i' } },
        { designation: { $regex: search, $options: 'i' } },
        { homePractice: { $regex: search, $options: 'i' } },
        { practiceManager: { $regex: search, $options: 'i' } }
      ]
    };

    const employees = await Employee.find(query).limit(50); // limit for performance
    res.json({ employees });
  } catch (err) {
    console.error('API search error:', err);
    res.status(500).json({ error: 'Failed to fetch employees' });
  }
});


// View Project Master
app.get('/view-project-master', isAuth, isAdmin, async (req, res) => {
  try {
    const projects = await ProjectMaster.find().lean();

    // Format startDate & endDate to only 'YYYY-MM-DD'
    projects.forEach(p => {
      p.startDate = p.startDate?.toISOString().split('T')[0];
      p.endDate = p.endDate?.toISOString().split('T')[0];
    });

    res.render('view-project-master', {
      title: 'Project Master',
      projects,
      layout: 'sidebar-layout'
    });
  } catch (err) {
    console.error('Error loading project master:', err);
    res.status(500).send('Error loading project master records.');
  }
});

app.post('/project-master/add', isAuth, isAdmin, async (req, res) => {
  try {
    const {
      projectName,
      startDate,
      endDate,
      projectManager,
      cbslClient,
      dihClient
    } = req.body;

    // Only take date part
    const formattedStartDate = startDate.split('T')[0];
    const formattedEndDate = endDate.split('T')[0];

    await ProjectMaster.create({
      projectName,
      startDate: formattedStartDate,
      endDate: formattedEndDate,
      projectManager,
      cbslClient,
      dihClient
    });

    res.redirect('/view-project-master');
  } catch (err) {
    console.error('Error adding project:', err);
    res.status(500).send('Error adding project.');
  }
});

app.post('/project-master/edit', isAuth, isAdmin, async (req, res) => {
  try {
    const {
      _id,
      projectName,
      startDate,
      endDate,
      projectManager,
      cbslClient,
      dihClient
    } = req.body;

    const formattedStartDate = startDate.split('T')[0];
    const formattedEndDate = endDate.split('T')[0];

    await ProjectMaster.findByIdAndUpdate(_id, {
      projectName,
      startDate: formattedStartDate,
      endDate: formattedEndDate,
      projectManager,
      cbslClient,
      dihClient
    });

    res.redirect('/view-project-master');
  } catch (err) {
    console.error('Error editing project:', err);
    res.status(500).send('Error editing project.');
  }
});


app.post('/project-master/delete/:id', isAuth, isAdmin, async (req, res) => {
  try {
    await ProjectMaster.findByIdAndDelete(req.params.id);
    res.redirect('/view-project-master');
  } catch (err) {
    console.error('Error deleting project:', err);
    res.status(500).send('Error deleting project.');
  }
});




// Upload Employees Form
app.get('/upload-employees', isAuth, isAdmin, csrfProtection, (req, res) => {
  res.render('upload-employees', { csrfToken: req.csrfToken() });
});

// Upload Employees POST
app.post('/upload-employees',
  isAuth,
  isAdmin,
  upload.single('excelfile'),
  csrfProtection,
  async (req, res) => {
    const filePath = req.file.path;
    try {
      const workbook = xlsx.readFile(filePath);
      const sheetName = workbook.SheetNames[0];
      const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

      for (const emp of data) {
        if (emp['Emp. Code'] && emp['Resource Name']) {
          await Employee.findOneAndUpdate(
            { empCode: emp['Emp. Code'] },
            {
              empCode: emp['Emp. Code'],
              name: emp['Resource Name'],
              payrollCompany: emp['Payroll Company'],
              division: emp['Division'],
              location: emp['Location'],
              designation: emp['Designation'],
              homePractice: emp['Home Practice'],
              practiceManager: emp['Practice Manager'],
              project: ''
            },
            { upsert: true, new: true }
          );
        }
      }

      fs.unlinkSync(filePath);
      res.redirect('/dashboard/admin/view-employees');
    } catch (err) {
      console.error('Excel Parse Error:', err);
      res.status(500).send('Error processing file.');
    }
  }
);

// Upload Project Master GET
app.get('/upload-project-master', isAuth, isAdmin, csrfProtection, (req, res) => {
  res.render('upload-project-master', { csrfToken: req.csrfToken() });
});

// Upload Project Master POST
const parseDate = (value) => {
  const date = new Date(value);
  return isNaN(date.getTime()) ? null : date;
};





app.post('/upload-project-master', isAuth, isAdmin, upload.single('projectFile'), csrfProtection, async (req, res) => {
  const filePath = req.file.path;

  try {
    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

    for (const row of data) {
      if (row['Project Name']) {
        const startDate = parseDate(row['Start Date']);
        const endDate = parseDate(row['End Date']);

        await ProjectMaster.create({
          projectName: row['Project Name'],
          startDate,
          endDate,
          projectManager: row['Project Manager'],
          cbslClient: row['CBSL Client'],
          dihClient: row['DIH Division']
        });
      }
    }

    fs.unlinkSync(filePath);
    res.redirect('/view-project-master');
  } catch (err) {
    console.error('Error uploading project master:', err);
    res.status(500).send('Upload failed.');
  }
});

// --- Practice Master CRUD ---
// Add Practice
app.post('/practice-master/add', isAuth, isAdmin, async (req, res) => {
  try {
    const { practiceName, practiceManager } = req.body;
    await PracticeMaster.create({ practiceName, practiceManager });
    res.redirect('/view-practice-master');
  } catch (err) {
    console.error('Error adding practice:', err);
    res.status(500).send('Error adding practice.');
  }
});

// Edit Practice
app.post('/practice-master/edit', isAuth, isAdmin, async (req, res) => {
  try {
    const { _id, practiceName, practiceManager } = req.body;
    await PracticeMaster.findByIdAndUpdate(_id, { practiceName, practiceManager });
    res.redirect('/view-practice-master');
  } catch (err) {
    console.error('Error editing practice:', err);
    res.status(500).send('Error editing practice.');
  }
});

// Delete Practice
app.post('/practice-master/delete/:id', isAuth, isAdmin, async (req, res) => {
  try {
    await PracticeMaster.findByIdAndDelete(req.params.id);
    res.redirect('/view-practice-master');
  } catch (err) {
    console.error('Error deleting practice:', err);
    res.status(500).send('Error deleting practice.');
  }
});

// Upload Practice Master GET
app.get('/upload-practice-master', isAuth, isAdmin, csrfProtection, (req, res) => {
  res.render('upload-practice-master', { csrfToken: req.csrfToken() });
});

// Upload Practice Master POST
app.post('/upload-practice-master', isAuth, isAdmin, upload.single('practiceFile'), csrfProtection, async (req, res) => {
  const filePath = req.file.path;
  try {
    const workbook = xlsx.readFile(filePath);
    const sheetName = workbook.SheetNames[0];
    const data = xlsx.utils.sheet_to_json(workbook.Sheets[sheetName]);

    for (const row of data) {
      if (row['SW Practice']) {
        await PracticeMaster.create({
          practiceName: row['SW Practice'],
          practiceManager: row['Practice Manager']
        });
      }
    }

    fs.unlinkSync(filePath);
    res.redirect('/view-practice-master');
  } catch (err) {
    console.error('Error uploading practice master:', err);
    res.status(500).send('Upload failed.');
  }
});
// View Project Master
// app.get('/view-project-master', isAuth, isAdmin, async (req, res) => {
//   try {
//     const projects = await ProjectMaster.find();
//     res.render('view-project-master', { projects });
//   } catch (err) {
//     console.error("Error fetching project master:", err);
//     res.status(500).send('Error loading project master.');
//   }
// });

// View Practice Master
app.get('/view-practice-master', isAuth, isAdmin, async (req, res) => {
  try {
    const practices = await PracticeMaster.find();
    res.render('view-practice-master', { practices });
  } catch (err) {
    console.error("Error fetching practice master:", err);
    res.status(500).send('Error loading practice master.');
  }
});

// Assigned Resources Page


app.get('/assigned-resources', isAuth, isAdmin, async (req, res) => {
  try {
    // Get filter params
    const employeeFilter = req.query.employee || '';
    const projectFilter = req.query.project || '';
    const monthFilter = req.query.month || '';

    // Build query for AssignedSchedule
    let scheduleQuery = {};
    if (employeeFilter) {
      const empDoc = await Employee.findOne({ empCode: employeeFilter });
      if (empDoc) scheduleQuery.employee = empDoc._id;
    }
    if (projectFilter) {
      const projDoc = await ProjectMaster.findOne({ projectName: projectFilter });
      if (projDoc) scheduleQuery.project = projDoc._id;
    }

    // Only show one schedule per employee/project (latest)
    const allSchedules = await AssignedSchedule.find(scheduleQuery)
      .populate('employee')
      .populate('project')
      .populate('practice');
    // Deduplicate by employee+project using stringified ObjectIds
    const latestSchedules = {};
    for (const s of allSchedules) {
      const empId = s.employee?._id ? s.employee._id.toString() : String(s.employee);
      const projId = s.project?._id ? s.project._id.toString() : String(s.project);
      const key = `${empId}-${projId}`;
      // Always keep the latest schedule (by _id timestamp)
      if (!latestSchedules[key] || (s._id > latestSchedules[key]._id)) {
        latestSchedules[key] = s;
      }
    }
    const uniqueSchedules = Object.values(latestSchedules);

    // Debug: Log dailyHours for each schedule
    //console.log('Assigned Schedules dailyHours:');
    uniqueSchedules.forEach(s => {
      //console.log(`Emp: ${s.employee?.empCode}, Project: ${s.project?.projectName}, dailyHours:`, s.dailyHours);
    });

    // Generate dateRange for the selected month (or current month if not selected)
    let year, month;
    if (monthFilter) {
      // monthFilter format: 'YYYY-MM'
      const parts = monthFilter.split('-');
      year = parseInt(parts[0], 10);
      month = parseInt(parts[1], 10) - 1; // JS months are 0-indexed
    } else {
      const now = new Date();
      year = now.getFullYear();
      month = now.getMonth();
    }
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const dateRange = [];
    for (let d = 1; d <= daysInMonth; d++) {
      const dateObj = new Date(year, month, d);
      // Format as 'D-MMM' (e.g., '1-May')
      const day = dateObj.getDate();
      const monthName = dateObj.toLocaleString('default', { month: 'short' });
      dateRange.push(`${day}-${monthName}`);
    }

    // Generate all dates for current year (YYYY-MM-DD)
    const allYearDates = [];
    let minDate = new Date(year + '-01-01');
    let maxDate = new Date(year + '-12-31');
    for (let d = new Date(minDate); d <= maxDate; d.setDate(d.getDate() + 1)) {
      let dateStr = d.toISOString().slice(0,10);
      allYearDates.push(dateStr);
    }

    // Get all employees and projects for filter dropdowns
    const allEmployees = await Employee.find({}, 'empCode name division designation');
const allProjects = await ProjectMaster.find({}, 'projectName projectManager cbslClient dihClient');

    res.render('assigned-resources', {
      schedules: uniqueSchedules,
      dateRange,
      allYearDates,
      allEmployees,
      allProjects,
      employeeFilter,
      projectFilter,
      monthFilter,
      errorMessage: req.query.error || '',
      layout: 'sidebar-layout',
      title: 'Assigned Resources'
    });
  } catch (err) {
    console.error('Error loading assigned resources page:', err);
    res.status(500).send('Internal Server Error');
  }
});

// CREATE: Add a new schedule (Admin only)
app.post('/assigned-resources', isAuth, isAdmin, async (req, res) => {
  try {
    console.log('POST /assigned-resources', req.body);
    const { empCode, dailyHours, projectAssigned } = req.body;
    // Find employee and project references
    const employeeDoc = await Employee.findOne({ empCode });
    const projectDoc = await ProjectMaster.findOne({ projectName: projectAssigned });
    if (!employeeDoc || !projectDoc) {
      return res.status(400).json({ success: false, error: 'Employee or Project not found' });
    }
    // Parse dailyHours if sent as JSON string or object
    let dailyHoursObj = {};
    if (typeof dailyHours === 'string') {
      try { dailyHoursObj = JSON.parse(dailyHours); } catch { dailyHoursObj = {}; }
    } else if (typeof dailyHours === 'object') {
      dailyHoursObj = dailyHours;
    }
    // Convert all values to numbers and format keys to 'D-MMM'
    function formatDateKey(dateStr) {
      // Accepts 'YYYY-MM-DD' or 'D-MMM'
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const d = new Date(dateStr);
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        return `${day}-${monthName}`;
      }
      return dateStr;
    }
    let formattedDailyHours = {};
    Object.keys(dailyHoursObj).forEach(date => {
      formattedDailyHours[formatDateKey(date)] = Number(dailyHoursObj[date]) || 0;
    });
    // Check for existing schedule for this employee and project
    let existingSchedule = await AssignedSchedule.findOne({ employee: employeeDoc._id, project: projectDoc._id });
    if (existingSchedule) {
      // Update dailyHours if already exists
      existingSchedule.dailyHours = formattedDailyHours;
      await existingSchedule.save();
      res.status(200).json({ success: true, schedule: existingSchedule, updated: true });
    } else {
      const newSchedule = new AssignedSchedule({
        employee: employeeDoc._id,
        project: projectDoc._id,
        dailyHours: formattedDailyHours
      });
      await newSchedule.save();
      res.status(201).json({ success: true, schedule: newSchedule, created: true });
    }
  } catch (err) {
    console.error('Error in POST /assigned-resources:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// READ: Get a schedule by ID (for Edit) (Admin only)
app.get('/assigned-resources/:id', isAuth, async (req, res) => {
  try {
    console.log('GET /assigned-resources/:id', req.params.id);
    if (!req.params.id.match(/^[0-9a-fA-F]{24}$/)) {
      console.error('Invalid ObjectId format:', req.params.id);
      return res.status(400).json({ success: false, error: 'Invalid schedule ID format' });
    }
    const schedule = await AssignedSchedule.findById(req.params.id);
    if (!schedule) {
      console.error('Schedule not found for ID:', req.params.id);
      return res.status(404).json({ success: false, error: 'Schedule not found' });
    }
    res.json({ success: true, schedule });
  } catch (err) {
    console.error('Error in GET /assigned-resources/:id:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// UPDATE: Edit a schedule (Admin only)
app.put('/assigned-resources/:id', isAuth, async (req, res) => {
  try {
    //console.log('PUT /assigned-resources/:id', req.params.id);
    //console.log('Request body:', req.body);
    // Support both flat and nested project/dailyHours from AJAX
    const updateFields = {};
    // Parse flat fields into nested objects if needed
    // Project
    let projectName = req.body['project[projectName]'] || (req.body.project && req.body.project.projectName);
    if (projectName) {
      // Find ProjectMaster by name and use its ObjectId
      const projectDoc = await ProjectMaster.findOne({ projectName: projectName });
      if (projectDoc) {
        updateFields['project'] = projectDoc._id;
      } else {
        // If not found, do not update project and log warning
        console.warn('Project not found for name:', projectName);
      }
    }
    // Daily hours
    let dailyHoursObj = {};
    Object.keys(req.body).forEach(key => {
      const dhMatch = key.match(/^dailyHours\[(.+)\]$/);
      if (dhMatch) {
        // Accept both D-MMM and YYYY-MM-DD keys, always convert to D-MMM
        let rawKey = dhMatch[1];
        let formattedKey = formatDateKey(rawKey);
        dailyHoursObj[formattedKey] = Number(req.body[key]) || 0;
      }
    });
    // Format keys to 'D-MMM' for consistency with dateRange
    function formatDateKey(dateStr) {
      // Accepts 'YYYY-MM-DD', 'D-MMM', or other formats
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const d = new Date(dateStr);
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        return `${day}-${monthName}`;
      }
      // If already D-MMM, return as is
      if (/^\d{1,2}-[A-Za-z]{3}$/.test(dateStr)) {
        return dateStr;
      }
      // Try to parse other date formats
      const d = new Date(dateStr);
      if (!isNaN(d.getTime())) {
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        return `${day}-${monthName}`;
      }
      return dateStr;
    }
    // Over-allocation validation: for each day, sum all hours for this employee across all projects
    if (Object.keys(dailyHoursObj).length > 0) {
      // Find the schedule being updated
      const currentSchedule = await AssignedSchedule.findById(req.params.id);
      if (currentSchedule && currentSchedule.employee) {
        for (const dateKey of Object.keys(dailyHoursObj)) {
          // Sum all hours for this employee on this day across all projects except this one
          const otherSchedules = await AssignedSchedule.find({ employee: currentSchedule.employee, _id: { $ne: req.params.id } });
          let totalOther = 0;
          for (const sched of otherSchedules) {
            let dh = sched.dailyHours && sched.dailyHours[dateKey];
            totalOther += Number(dh) || 0;
          }
          let newTotal = totalOther + Number(dailyHoursObj[dateKey]) || 0;
          if (newTotal > 8) {
            return res.status(400).json({ success: false, error: `Over allocation: Total hours for employee exceed 8 on ${dateKey} (${newTotal} hours)` });
          }
        }
      }
      updateFields['dailyHours'] = dailyHoursObj;
    }

    //console.log('Update fields:', updateFields);
    const updated = await AssignedSchedule.findByIdAndUpdate(
      req.params.id,
      { $set: updateFields },
      { new: true }
    );
    if (updated) {
      // Fetch with project populated for frontend display
      const populated = await AssignedSchedule.findById(updated._id)
        .populate('employee')
        .populate('project')
        .populate('practice');
      //console.log('Update success:', populated);
      res.json({ success: true, schedule: populated });
    } else {
      console.warn('Schedule not found for update:', req.params.id);
      res.status(404).json({ success: false, error: 'Schedule not found' });
    }
  } catch (err) {
    console.error('Error in PUT /assigned-resources/:id:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});

// DELETE: Remove a schedule (Admin only)
app.delete('/assigned-resources/:id', isAuth, isAdmin, async (req, res) => {
  try {
    //console.log('DELETE /assigned-resources/:id', req.params.id);
    let result = await AssignedSchedule.deleteOne({ _id: req.params.id });
    if (result.deletedCount === 0) {
      result = await AssignedSchedule.deleteOne({ _id: req.params.id.toString() });
    }
    if (result.deletedCount > 0) {
      res.json({ success: true });
    } else {
      res.status(404).json({ success: false, error: 'Schedule not found' });
    }
  } catch (err) {
    console.error('Error in DELETE /assigned-resources/:id:', err);
    res.status(500).json({ success: false, error: err.message });
  }
});



app.get('/employees/add', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const divisions = await Employee.distinct('division');
    const designations = await Employee.distinct('designation');
    const payrollCompanies = await Employee.distinct('payrollCompany');
const locations = await Employee.distinct('location');
const practices = await PracticeMaster.find();


    res.render('add-employee', {
      csrfToken: req.csrfToken(),
      title: 'Add Employee',
      divisions,
      designations,
      payrollCompanies,  // ✅ add this
      locations,  
      practices,
      errors: []
    });
  } catch (err) {
    console.error('Error loading add-employee form:', err);
    res.status(500).send('Failed to load form');
  }
});

// Add Employee Submission
app.post('/employees/add', isAuth, isAdmin, csrfProtection, async (req, res) => {
  const { empCode, name, payrollCompany, division, location, designation, homePractice, practiceManager } = req.body;
  const errors = [];

  if (!empCode || !name || !division || !designation || !homePractice) {
    errors.push('All required fields must be filled');
  }

  const existing = await Employee.findOne({ empCode });
  if (existing) {
    errors.push('Employee code already exists');
  }

  if (errors.length > 0) {
    const divisions = await Employee.distinct('division');
    const designations = await Employee.distinct('designation');
    const payrollCompanies = await Employee.distinct('payrollCompany');
    const locations = await Employee.distinct('location');
    const practices = await PracticeMaster.find();


    return res.render('add-employee', {
      csrfToken: req.csrfToken(),
      title: 'Add Employee',
      divisions,
       payrollCompanies, // ✅ add this
       locations,
      designations,
      practices,
      errors
    });
  }

  try {
    await Employee.create({
      empCode,
      name,
      payrollCompany,
      division,
      location,
      designation,
      homePractice,
      practiceManager
    });

    res.redirect('/dashboard/admin/view-employees');
  } catch (err) {
    console.error('Error adding employee:', err);
    res.status(500).send('Failed to add employee');
  }
});

// Edit Employee GET
app.get('/employees/:id/edit', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const employee = await Employee.findOne({ empCode: req.params.id });
    if (!employee) return res.status(404).send('Employee not found');
    res.render('edit-employee', { employee, csrfToken: req.csrfToken() });
  } catch (err) {
    console.error('Edit GET Error:', err);
    res.status(500).send('Server error');
  }
});

// Edit Employee POST
app.post('/employees/:id/edit', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    await Employee.findOneAndUpdate(
      { empCode: req.params.id },
      {
        empCode: req.body.empCode,
        name: req.body.name,
        payrollCompany: req.body.payrollCompany,
        division: req.body.division,
        location: req.body.location,
        designation: req.body.designation,
        homePractice: req.body.homePractice,
        practiceManager: req.body.practiceManager
      }
    );
    res.redirect('/dashboard/admin/view-employees');
  } catch (err) {
    console.error('Edit POST Error:', err);
    res.status(500).send('Error updating employee');
  }
});

// Delete Employee POST
app.post('/employees/:id/delete', isAuth, isAdmin, csrfProtection, async (req, res) => {
  await Employee.deleteOne({ empCode: req.params.id });
  res.redirect('/dashboard/admin/view-employees');
});

// Assign Project GET
app.get('/employees/:id/assign-project', isAuth, isAdmin, csrfProtection, async (req, res) => {
  const employee = await Employee.findOne({ empCode: req.params.id });
  if (!employee) return res.status(404).send('Employee not found');
  res.render('assign-project', { employee, csrfToken: req.csrfToken() });
});

// Assign Project POST
app.post('/employees/:id/assign-project', isAuth, isAdmin, csrfProtection, async (req, res) => {
  await Employee.findOneAndUpdate(
    { empCode: req.params.id },
    { project: req.body.project }
  );
  res.redirect('/assigned-resources');
});

// ✅ New: Dismiss Project POST
app.post('/employees/:id/dismiss-project', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    await Employee.findOneAndUpdate(
      { empCode: req.params.id },
      { project: '' }
    );
    res.redirect('/dashboard/admin/view-employees');
  } catch (err) {
    console.error('Dismiss Project Error:', err);
    res.status(500).send('Error dismissing project');
  }
});
// === 📅 Schedule Routes ===

// Schedule Form Page
app.get('/schedule', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const employees = await Employee.find();
    const projects = await ProjectMaster.find();
    // Get unique home practices from employees
    const practices = [...new Set(employees.map(emp => emp.homePractice).filter(Boolean))];

    res.render('schedule', {
      employees,
      projects,
      practices,
      csrfToken: req.csrfToken(),
      title: 'Assign Schedule',
      layout: 'sidebar-layout'
    });
  } catch (err) {
    console.error('Error loading schedule page:', err);
    res.status(500).send('Internal Server Error');
  }
});

// API to fetch employee by EmpCode
app.get('/api/employee/:empCode', async (req, res) => {
  try {
    const emp = await Employee.findOne({ empCode: req.params.empCode });
    if (!emp) return res.status(404).json({ error: 'Employee not found' });

    res.json({
      name: emp.name,
      payrollCompany: emp.payrollCompany,
      division: emp.division,
      project: emp.project,
      practice: emp.homePractice,
      practiceHead: emp.practiceManager
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error' });
  }
});


// API to fetch project by name
app.get('/api/project/:projectName', async (req, res) => {
  try {
    const project = await ProjectMaster.findOne({ projectName: req.params.projectName });
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json(project);
  } catch (err) {
    res.status(500).json({ error: 'Internal error' });
  }
});

// API to fetch practice by name
app.get('/api/practice/:practiceName', async (req, res) => {
  try {
    const practice = await PracticeMaster.findOne({ practiceName: req.params.practiceName });
    if (!practice) return res.status(404).json({ error: 'Practice not found' });

    res.json({
      practiceName: practice.practiceName,
      practiceManager: practice.practiceManager
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: 'Internal error' });
  }
});


// For fetching a project by its ID
app.get('/api/project-by-id/:id', async (req, res) => {
  try {
    const project = await ProjectMaster.findById(req.params.id);
    if (!project) return res.status(404).json({ error: 'Project not found' });
    res.json(project);
  } catch (err) {
    console.error('Error fetching project by ID:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// Save assigned schedule

app.post('/schedule', async (req, res) => {
  
  try {
    const empCodes = Array.isArray(req.body.emp_ids) ? req.body.emp_ids : [req.body.emp_ids];
    const filteredEmpCodes = empCodes.filter(code => code?.trim());
    const startDate = new Date(req.body.start_date);
    const endDate = new Date(req.body.end_date);

    // Validate dates
    if (isNaN(startDate.getTime()) || isNaN(endDate.getTime())) {
      return res.status(400).send('Invalid start or end date. Please select valid dates.');
    }
    if (endDate < startDate) {
      return res.status(400).send('End date must be after start date.');
    }

    // Helper to get all dates in range, skipping weekends, in YYYY-MM-DD format
    function getDateKeysSkipWeekends(start, end) {
      const keys = [];
      let d = new Date(start);
      while (d <= end) {
        const dayOfWeek = d.getDay(); // 0=Sunday, 6=Saturday
        if (dayOfWeek !== 0 && dayOfWeek !== 6) {
          const dateStr = d.toISOString().slice(0,10); // YYYY-MM-DD
          keys.push({ key: dateStr, dateObj: new Date(d) });
        }
        d.setDate(d.getDate() + 1);
      }
      return keys;
    }
    const dateKeys = getDateKeysSkipWeekends(startDate, endDate);

    // Helper to format date keys
    function formatDateKey(dateStr) {
      if (/^\d{4}-\d{2}-\d{2}$/.test(dateStr)) {
        const d = new Date(dateStr);
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        return `${day}-${monthName}`;
      }
      return dateStr;
    }

    // Support: single employee + multiple projects, multiple employees + single project, and multiple employees + multiple projects
    const projectIds = req.body['project_ids[]'] ? (Array.isArray(req.body['project_ids[]']) ? req.body['project_ids[]'] : [req.body['project_ids[]']]) : [];
    const hoursList = req.body['hours_list[]'] ? (Array.isArray(req.body['hours_list[]']) ? req.body['hours_list[]'] : [req.body['hours_list[]']]) : [];
    // If both projectIds and hoursList are present, assign all selected employees to all selected projects
    if (projectIds.length && hoursList.length && projectIds.length === hoursList.length) {
      for (const empCode of filteredEmpCodes) {
        const employee = await Employee.findOne({ empCode });
        if (!employee) {
          console.warn('Employee not found:', empCode);
          continue;
        }
        // Over-allocation check for each day
        let overAllocated = false;
        let overAllocDetails = [];
        for (const { key: dateKey, dateObj } of dateKeys) {
          let newTotal = 0;
          for (let i = 0; i < projectIds.length; i++) {
            newTotal += Number(hoursList[i]) || 0;
          }
          let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
          let existingTotal = 0;
          for (const sched of existingSchedules) {
            let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
            existingTotal += Number(dh) || 0;
          }
          // Subtract hours for this employee/project for this day (if updating)
          for (let i = 0; i < projectIds.length; i++) {
            let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectIds[i] });
            if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
              existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
            }
          }
          let totalHours = existingTotal + newTotal;
          if (totalHours > 8) {
            overAllocated = true;
            overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
          }
        }
        if (overAllocated) {
          return res.redirect(`/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
        }
        // Save for each project
        for (let i = 0; i < projectIds.length; i++) {
          const projectId = projectIds[i];
          const hours = Number(hoursList[i]) || 0;
          const query = { employee: employee._id, project: projectId };
          let existingSchedule = await AssignedSchedule.findOne(query);
          let dailyHoursObj = {};
          if (existingSchedule && existingSchedule.dailyHours) {
            dailyHoursObj = { ...existingSchedule.dailyHours };
          }
          for (const { key: dateKey, dateObj } of dateKeys) {
            dailyHoursObj[formatDateKey(dateKey)] = hours;
          }
          await AssignedSchedule.findOneAndUpdate(query, {
            $setOnInsert: { employee: employee._id, project: projectId },
            $set: { dailyHours: dailyHoursObj, startDate, endDate },
          }, { upsert: true, new: true });
        }
      }
    } else if (req.body.project_id && req.body.hours) {
      // Multiple employees: single project
      const projectId = req.body.project_id;
      const hours = Number(req.body.hours) || 0;
      for (const empCode of filteredEmpCodes) {
        const employee = await Employee.findOne({ empCode });
        if (!employee) {
          console.warn('Employee not found:', empCode);
          continue;
        }
        let overAllocated = false;
        let overAllocDetails = [];
        for (const { key: dateKey, dateObj } of dateKeys) {
          let existingSchedules = await AssignedSchedule.find({ employee: employee._id });
          let existingTotal = 0;
          for (const sched of existingSchedules) {
            let dh = sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)];
            existingTotal += Number(dh) || 0;
          }
          let sched = await AssignedSchedule.findOne({ employee: employee._id, project: projectId });
          if (sched && sched.dailyHours && sched.dailyHours[formatDateKey(dateKey)]) {
            existingTotal -= Number(sched.dailyHours[formatDateKey(dateKey)]) || 0;
          }
          let totalHours = existingTotal + hours;
          if (totalHours > 8) {
            overAllocated = true;
            overAllocDetails.push(`${formatDateKey(dateKey)}: ${totalHours} hours`);
          }
        }
        if (overAllocated) {
          return res.redirect(`/assigned-resources?error=${encodeURIComponent('Over allocation: Total hours for ' + empCode + ' exceed 8 on ' + overAllocDetails.join(', '))}`);
        }
        const query = { employee: employee._id, project: projectId };
        let existingSchedule = await AssignedSchedule.findOne(query);
        let dailyHoursObj = {};
        if (existingSchedule && existingSchedule.dailyHours) {
          dailyHoursObj = { ...existingSchedule.dailyHours };
        }
        for (const { key: dateKey, dateObj } of dateKeys) {
          dailyHoursObj[formatDateKey(dateKey)] = hours;
        }
        await AssignedSchedule.findOneAndUpdate(query, {
          $setOnInsert: { employee: employee._id, project: projectId },
          $set: { dailyHours: dailyHoursObj, startDate, endDate },
        }, { upsert: true, new: true });
      }
    }
    res.redirect('/assigned-resources');
  } catch (error) {
    console.error('Error assigning schedule:', error);
    res.status(500).send('Something went wrong');
  }
});


// Calendar View Route
app.get('/calendar-view', isAuth, isAdmin, async (req, res) => {
  try {
    // Get filter params (optional, can extend for month/year selection)
    const monthFilter = req.query.month || '';

    // Build query for AssignedSchedule (all schedules)
    const allSchedules = await AssignedSchedule.find()
      .populate('employee')
      .populate('project');


    // Generate dateRange for the selected month (or current month if not selected), skipping weekends
    let year, month;
    if (monthFilter) {
      const parts = monthFilter.split('-');
      year = parseInt(parts[0], 10);
      month = parseInt(parts[1], 10) - 1;
    } else {
      const now = new Date();
      year = now.getFullYear();
      month = now.getMonth();
    }
    const daysInMonth = new Date(year, month + 1, 0).getDate();
    const dateRange = [];
    for (let d = 1; d <= daysInMonth; d++) {
      const dateObj = new Date(year, month, d);
      const dayOfWeek = dateObj.getDay();
      if (dayOfWeek === 0 || dayOfWeek === 6) continue; // skip Sunday/Saturday
      const day = dateObj.getDate();
      const monthName = dateObj.toLocaleString('default', { month: 'short' });
      dateRange.push(`${day}-${monthName}`);
    }

    // Get all employees
    const allEmployees = await Employee.find({}, 'empCode name division designation');


    // Build empDayProjects: { empCode: { date: [ { projectName, hours, projectId, assignmentId } ] } }
    const empDayProjects = {};
    allSchedules.forEach(s => {
      const empCode = s.employee?.empCode || 'N/A';
      if (!empDayProjects[empCode]) empDayProjects[empCode] = {};
      if (s.dailyHours && s.project && s.project.projectName) {
        Object.entries(s.dailyHours).forEach(([date, hours]) => {
          if (!empDayProjects[empCode][date]) empDayProjects[empCode][date] = [];
          empDayProjects[empCode][date].push({
            projectName: s.project.projectName,
            projectId: s.project._id,
            assignmentId: s._id,
            hours: Number(hours) || 0
          });
        });
      }
    });

    res.render('calendar-view', {
      year: year,
      month: month + 1, // for display
      dateRange,
      allEmployees,
      empDayProjects,
      layout: 'sidebar-layout',
      title: 'Resource Calendar View',
      user: req.session.user
    });
  } catch (err) {
    console.error('Error loading calendar view:', err);
    res.status(500).send('Internal Server Error');
  }
});


// (Place this at the end of the file, after all middleware and routes, but before app.listen)

// API endpoint for updating assignments via drag-and-drop
app.post('/api/update-assignment', isAuth, isAdmin, async (req, res) => {
  try {
    //console.log('Received assignment update request:', req.body);
    
    const { 
      assignmentId, 
      projectId, 
      oldEmpCode, 
      oldDate, 
      newEmpCode, 
      newDate, 
      hours, 
      projectName 
    } = req.body;

    // Find the source and target employees
    const oldEmployee = await Employee.findOne({ empCode: oldEmpCode });
    const newEmployee = await Employee.findOne({ empCode: newEmpCode });
    
    if (!oldEmployee) {
      return res.json({ success: false, message: `Source employee ${oldEmpCode} not found` });
    }
    if (!newEmployee) {
      return res.json({ success: false, message: `Target employee ${newEmpCode} not found` });
    }

    // Find the assignment schedule for the source employee
    let sourceSchedule = null;
    if (assignmentId) {
      sourceSchedule = await AssignedSchedule.findById(assignmentId).populate('project');
    }
    
    if (!sourceSchedule) {
      // Find by employee and check if has hours on the specific date
      const schedules = await AssignedSchedule.find({ employee: oldEmployee._id }).populate('project');
      for (let sched of schedules) {
        if (sched.dailyHours && sched.dailyHours[oldDate] && parseFloat(sched.dailyHours[oldDate]) > 0) {
          sourceSchedule = sched;
          break;
        }
      }
    }

    if (!sourceSchedule || !sourceSchedule.dailyHours[oldDate]) {
      return res.json({ success: false, message: `No assignment found for ${oldEmpCode} on ${oldDate}` });
    }

    // Remove hours from source date
    const originalHours = sourceSchedule.dailyHours[oldDate];
    delete sourceSchedule.dailyHours[oldDate];
    
    // Mark the field as modified for Mongoose
    sourceSchedule.markModified('dailyHours');
    
    // Find or create target schedule for the same project
    let targetSchedule = await AssignedSchedule.findOne({
      employee: newEmployee._id,
      project: sourceSchedule.project._id
    });

    if (!targetSchedule) {
      // Create new schedule for target employee
      targetSchedule = new AssignedSchedule({
        employee: newEmployee._id,
        project: sourceSchedule.project._id,
        practice: sourceSchedule.practice,
        dailyHours: {},
        role: sourceSchedule.role,
        startDate: sourceSchedule.startDate,
        endDate: sourceSchedule.endDate,
        scheduledBy: 'Drag-Drop System',
        scheduledAt: new Date()
      });
    }

    // Add hours to target date
    if (!targetSchedule.dailyHours) {
      targetSchedule.dailyHours = {};
    }
    targetSchedule.dailyHours[newDate] = parseFloat(hours);
    
    // Mark the field as modified for Mongoose
    targetSchedule.markModified('dailyHours');

    // Save both schedules
    await sourceSchedule.save();
    await targetSchedule.save();

    //console.log('Assignment updated successfully');
    res.json({ 
      success: true, 
      message: `Successfully moved ${hours}h from ${oldEmpCode} to ${newEmpCode}` 
    });

  } catch (error) {
    console.error('Error updating assignment:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for drag-fill feature
app.post('/api/drag-fill', isAuth, async (req, res) => {
  try {
    //console.log('Received drag-fill request:', req.body);
    
    const { 
      sourceEmpCode, 
      sourceDate, 
      projectId,
      targetCells, 
      hours,
      projectName 
    } = req.body;

    // Find source employee
    const sourceEmployee = await Employee.findOne({ empCode: sourceEmpCode });
    if (!sourceEmployee) {
      return res.json({ success: false, message: 'Source employee not found' });
    }

    // Find the project to assign
    let project;
    if (projectId) {
      project = await ProjectMaster.findById(projectId);
      if (!project) {
        return res.json({ success: false, message: 'Project not found' });
      }
    } else {
      // Fallback: find project by name
      project = await ProjectMaster.findOne({ projectName });
      if (!project) {
        return res.json({ success: false, message: 'Project not found' });
      }
    }

    let updatedCells = 0;
    let failedCells = [];

    // Process each target cell
    for (const cell of targetCells) {
      const { empCode, date } = cell;
      
      try {
        // Find target employee
        const targetEmployee = await Employee.findOne({ empCode });
        if (!targetEmployee) {
          failedCells.push(`${empCode} (employee not found)`);
          continue;
        }

        // Check if employee already has assignments for this date (8 hour limit)
        const existingSchedules = await AssignedSchedule.find({ employee: targetEmployee._id });
        let totalHoursOnDate = 0;
        
        existingSchedules.forEach(schedule => {
          if (schedule.dailyHours && schedule.dailyHours[date]) {
            totalHoursOnDate += parseFloat(schedule.dailyHours[date]);
          }
        });
        
        if (totalHoursOnDate + parseFloat(hours) > 8) {
          failedCells.push(`${empCode} on ${date} (would exceed 8h limit: ${totalHoursOnDate}h + ${hours}h)`);
          continue;
        }

        // Find or create target schedule for the project
        let targetSchedule = await AssignedSchedule.findOne({
          employee: targetEmployee._id,
          project: project._id
        });

        if (!targetSchedule) {
          // Create new schedule for target employee
          targetSchedule = new AssignedSchedule({
            employee: targetEmployee._id,
            project: project._id,
            dailyHours: {},
            scheduledBy: 'Drag-Fill System',
            scheduledAt: new Date()
          });
        }

        // Add hours to target date
        if (!targetSchedule.dailyHours) {
          targetSchedule.dailyHours = {};
        }
        
        // If date already exists, add to existing hours, otherwise set new hours
        if (targetSchedule.dailyHours[date]) {
          targetSchedule.dailyHours[date] = parseFloat(targetSchedule.dailyHours[date]) + parseFloat(hours);
        } else {
          targetSchedule.dailyHours[date] = parseFloat(hours);
        }
        
        // Mark the field as modified for Mongoose
        targetSchedule.markModified('dailyHours');
        await targetSchedule.save();
        
        updatedCells++;
      } catch (cellError) {
        console.error(`Error processing cell ${empCode} ${date}:`, cellError);
        failedCells.push(`${empCode} on ${date} (processing error)`);
      }
    }

    let message = `Successfully filled ${updatedCells} cells with ${hours}h of "${project.projectName}"`;
    if (failedCells.length > 0) {
      message += `. Failed: ${failedCells.join(', ')}`;
    }

    //console.log(`Drag-fill completed: ${updatedCells} cells updated, ${failedCells.length} failed`);
    res.json({ 
      success: true, 
      message: message,
      updatedCells: updatedCells,
      failedCells: failedCells
    });

  } catch (error) {
    console.error('Error in drag-fill:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for drag-fill calendar updates
app.post('/api/calendar-drag-fill', isAuth, async (req, res) => {
  try {
    const { updates } = req.body;
    if (!Array.isArray(updates) || updates.length === 0) {
      return res.status(400).json({ success: false, error: 'No updates provided.' });
    }
    // For each update: { empCode, date, hours }
    for (const upd of updates) {
      const { empCode, date, hours } = upd;
      if (!empCode || !date) continue;
      // Find employee by empCode
      const employee = await Employee.findOne({ empCode });
      if (!employee) continue;
      // Find all schedules for this employee on this date
      const schedules = await AssignedSchedule.find({ employee: employee._id });
      let found = false;
      for (const sched of schedules) {
        if (sched.dailyHours && sched.dailyHours[date] !== undefined) {
          sched.dailyHours[date] = parseFloat(hours);
          await sched.save();
          found = true;
        }
      }
      // If not found in any schedule, update the first schedule (or create one if none exist)
      if (!found && schedules.length > 0) {
        schedules[0].dailyHours[date] = parseFloat(hours);
        await schedules[0].save();
      }
      // If no schedule exists, skip (or optionally create a new one)
    }
    res.json({ success: true });
  } catch (err) {
    console.error('Error in /api/calendar-drag-fill:', err);
    res.status(500).json({ success: false, error: 'Server error' });
  }
});

// API endpoint for multi-project drag-fill feature
app.post('/api/multi-project-drag-fill', isAuth, async (req, res) => {
  try {
    //console.log('Received multi-project drag-fill request:', req.body);
    
    const { 
      sourceEmpCode, 
      sourceDate, 
      projects,
      targetCells
    } = req.body;

    // Find source employee
    const sourceEmployee = await Employee.findOne({ empCode: sourceEmpCode });
    if (!sourceEmployee) {
      return res.json({ success: false, message: 'Source employee not found' });
    }

    let updatedCells = 0;
    let failedCells = [];

    // Process each target cell
    for (const cell of targetCells) {
      const { empCode, date } = cell;
      
      try {
        // Find target employee
        const targetEmployee = await Employee.findOne({ empCode });
        if (!targetEmployee) {
          failedCells.push(`${empCode} (employee not found)`);
          continue;
        }

        // Check total hours for the date
        const existingSchedules = await AssignedSchedule.find({ employee: targetEmployee._id });
        let totalHoursOnDate = 0;
        
        existingSchedules.forEach(schedule => {
          if (schedule.dailyHours && schedule.dailyHours[date]) {
            totalHoursOnDate += parseFloat(schedule.dailyHours[date]);
          }
        });

        // Calculate total hours for all projects
        const totalProjectHours = projects.reduce((sum, proj) => sum + parseFloat(proj.hours), 0);
        
        if (totalHoursOnDate + totalProjectHours > 8) {
          failedCells.push(`${empCode} on ${date} (would exceed 8h limit: ${totalHoursOnDate}h + ${totalProjectHours}h)`);
          continue;
        }

        // Process each project
        for (const projectData of projects) {
          const project = await ProjectMaster.findById(projectData.projectId);
          if (!project) {
            continue;
          }

          // Find or create target schedule for the project
          let targetSchedule = await AssignedSchedule.findOne({
            employee: targetEmployee._id,
            project: project._id
          });

          if (!targetSchedule) {
            targetSchedule = new AssignedSchedule({
              employee: targetEmployee._id,
              project: project._id,
              dailyHours: {},
              scheduledBy: 'Multi-Project Drag-Fill System',
              scheduledAt: new Date()
            });
          }

          // Add hours to target date
          if (!targetSchedule.dailyHours) {
            targetSchedule.dailyHours = {};
          }
          
          if (targetSchedule.dailyHours[date]) {
            targetSchedule.dailyHours[date] = parseFloat(targetSchedule.dailyHours[date]) + parseFloat(projectData.hours);
          } else {
            targetSchedule.dailyHours[date] = parseFloat(projectData.hours);
          }
          
          targetSchedule.markModified('dailyHours');
          await targetSchedule.save();
        }
        
        updatedCells++;
      } catch (cellError) {
        console.error(`Error processing cell ${empCode} ${date}:`, cellError);
        failedCells.push(`${empCode} on ${date} (processing error)`);
      }
    }

    let message = `Successfully filled ${updatedCells} cells with ${projects.length} projects`;
    if (failedCells.length > 0) {
      message += `. Failed: ${failedCells.join(', ')}`;
    }

    //console.log(`Multi-project drag-fill completed: ${updatedCells} cells updated, ${failedCells.length} failed`);
    res.json({ 
      success: true, 
      message: message,
      updatedCells: updatedCells,
      failedCells: failedCells
    });

  } catch (error) {
    console.error('Error in multi-project drag-fill:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for row drag-fill feature
app.post('/api/row-drag-fill', isAuth, async (req, res) => {
  try {
    //console.log('Received row drag-fill request:', req.body);
    
    const { 
      sourceEmpCode, 
      rowProjects,
      targetEmployees
    } = req.body;

    // Find source employee
    const sourceEmployee = await Employee.findOne({ empCode: sourceEmpCode });
    if (!sourceEmployee) {
      return res.json({ success: false, message: 'Source employee not found' });
    }

    let updatedEmployees = 0;
    let failedEmployees = [];

    // Process each target employee
    for (const targetEmpCode of targetEmployees) {
      try {
        // Find target employee
        const targetEmployee = await Employee.findOne({ empCode: targetEmpCode });
        if (!targetEmployee) {
          failedEmployees.push(`${targetEmpCode} (employee not found)`);
          continue;
        }

        let employeeUpdated = false;

        // Process each project and its dates from the source row
        for (const projectData of rowProjects) {
          const project = await ProjectMaster.findById(projectData.projectId);
          if (!project) {
            continue;
          }

          // Find or create target schedule for the project
          let targetSchedule = await AssignedSchedule.findOne({
            employee: targetEmployee._id,
            project: project._id
          });

          if (!targetSchedule) {
            targetSchedule = new AssignedSchedule({
              employee: targetEmployee._id,
              project: project._id,
              dailyHours: {},
              scheduledBy: 'Row Drag-Fill System',
              scheduledAt: new Date()
            });
          }

          // Copy all dates and hours for this project
          for (const [date, hours] of Object.entries(projectData.dates)) {
            // Check if adding these hours would exceed 8h limit for this date
            const existingSchedules = await AssignedSchedule.find({ employee: targetEmployee._id });
            let totalHoursOnDate = 0;
            
            existingSchedules.forEach(schedule => {
              if (schedule.dailyHours && schedule.dailyHours[date] && schedule._id.toString() !== targetSchedule._id.toString()) {
                totalHoursOnDate += parseFloat(schedule.dailyHours[date]);
              }
            });

            if (totalHoursOnDate + parseFloat(hours) <= 8) {
              if (!targetSchedule.dailyHours) {
                targetSchedule.dailyHours = {};
              }
              targetSchedule.dailyHours[date] = parseFloat(hours);
              employeeUpdated = true;
            }
          }

          if (employeeUpdated) {
            targetSchedule.markModified('dailyHours');
            await targetSchedule.save();
          }
        }
        
        if (employeeUpdated) {
          updatedEmployees++;
        }
      } catch (empError) {
        console.error(`Error processing employee ${targetEmpCode}:`, empError);
        failedEmployees.push(`${targetEmpCode} (processing error)`);
      }
    }

    let message = `Successfully copied row data to ${updatedEmployees} employees`;
    if (failedEmployees.length > 0) {
      message += `. Failed: ${failedEmployees.join(', ')}`;
    }

    //console.log(`Row drag-fill completed: ${updatedEmployees} employees updated, ${failedEmployees.length} failed`);
    res.json({ 
      success: true, 
      message: message,
      updatedEmployees: updatedEmployees,
      failedEmployees: failedEmployees
    });

  } catch (error) {
    console.error('Error in row drag-fill:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint for cell replace drag-fill - replaces entire cell content
app.post('/api/cell-replace-drag-fill', isAuth, async (req, res) => {
  try {
    //console.log('Received cell-replace-drag-fill request:', req.body);
    
    const { 
      sourceEmpCode, 
      sourceDate, 
      sourceProjects,
      targetCells
    } = req.body;

    // Find source employee
    const sourceEmployee = await Employee.findOne({ empCode: sourceEmpCode });
    if (!sourceEmployee) {
      return res.json({ success: false, message: 'Source employee not found' });
    }

    // Validate source projects
    if (!sourceProjects || sourceProjects.length === 0) {
      return res.json({ success: false, message: 'No source projects provided' });
    }

    // Calculate total hours from source projects
    const totalSourceHours = sourceProjects.reduce((sum, project) => sum + parseFloat(project.hours || 0), 0);
    
    if (totalSourceHours > 8) {
      return res.json({ success: false, message: `Source projects total ${totalSourceHours}h which exceeds 8-hour limit` });
    }

    let updatedCells = 0;
    let failedCells = [];

    // Process each target cell
    for (const cell of targetCells) {
      const { empCode, date } = cell;
      
      try {
        // Find target employee
        const targetEmployee = await Employee.findOne({ empCode });
        if (!targetEmployee) {
          failedCells.push(`${empCode} (employee not found)`);
          continue;
        }

        // Step 1: Delete all existing assignments for this employee on this date
        const existingSchedules = await AssignedSchedule.find({ employee: targetEmployee._id });
        
        for (const schedule of existingSchedules) {
          if (schedule.dailyHours && schedule.dailyHours[date]) {
            // Remove this date from the schedule
            delete schedule.dailyHours[date];
            schedule.markModified('dailyHours');
            
            // If no dates left in this schedule, delete the entire schedule
            const remainingDates = Object.keys(schedule.dailyHours);
            if (remainingDates.length === 0) {
              await AssignedSchedule.findByIdAndDelete(schedule._id);
            } else {
              await schedule.save();
            }
          }
        }

        // Step 2: Create new assignments for each source project
        for (const sourceProject of sourceProjects) {
          // Find the project
          const project = await ProjectMaster.findById(sourceProject.projectId);
          if (!project) {
            console.warn(`Project not found: ${sourceProject.projectId}`);
            continue;
          }

          // Create or find schedule for this project
          let targetSchedule = await AssignedSchedule.findOne({
            employee: targetEmployee._id,
            project: project._id
          });

          if (!targetSchedule) {
            // Create new schedule
            targetSchedule = new AssignedSchedule({
              employee: targetEmployee._id,
              project: project._id,
              dailyHours: {},
              scheduledBy: 'Cell Replace Drag-Fill System',
              scheduledAt: new Date()
            });
          }

          // Set hours for the target date
          if (!targetSchedule.dailyHours) {
            targetSchedule.dailyHours = {};
          }
          
          targetSchedule.dailyHours[date] = parseFloat(sourceProject.hours);
          targetSchedule.markModified('dailyHours');
          await targetSchedule.save();
        }
        
        updatedCells++;
      } catch (cellError) {
        console.error(`Error processing cell ${empCode} ${date}:`, cellError);
        failedCells.push(`${empCode} on ${date} (processing error)`);
      }
    }

    let message = `Successfully replaced ${updatedCells} cells with source cell content (${sourceProjects.length} projects, ${totalSourceHours}h total)`;
    if (failedCells.length > 0) {
      message += `. Failed: ${failedCells.join(', ')}`;
    }

    //console.log(`Cell replace drag-fill completed: ${updatedCells} cells updated, ${failedCells.length} failed`);
    res.json({ 
      success: true, 
      message: message,
      updatedCells: updatedCells,
      failedCells: failedCells
    });

  } catch (error) {
    console.error('Error in cell-replace-drag-fill:', error);
    res.json({ 
      success: false, 
      message: `Internal server error: ${error.message}` 
    });
  }
});

// API endpoint to get all projects for dropdown
app.get('/api/projects', isAuth, async (req, res) => {
  try {
    const projects = await ProjectMaster.find({}, 'projectName projectManager cbslClient dihClient').sort({ projectName: 1 });
    res.json(projects);
  } catch (error) {
    console.error('Error fetching projects:', error);
    res.status(500).json({ error: 'Failed to fetch projects' });
  }
});

// API endpoint to get current assignments for an employee on a specific date
app.get('/api/assignments/:empCode/:date', isAuth, async (req, res) => {
  try {
    const { empCode, date } = req.params;
    
    const employee = await Employee.findOne({ empCode });
    if (!employee) {
      return res.json([]);
    }
    
    const schedules = await AssignedSchedule.find({ employee: employee._id }).populate('project');
    const assignments = [];
    
    schedules.forEach(schedule => {
      if (schedule.dailyHours && schedule.dailyHours[date] && schedule.project) {
        assignments.push({
          assignmentId: schedule._id,
          projectId: schedule.project._id,
          projectName: schedule.project.projectName,
          hours: schedule.dailyHours[date]
        });
      }
    });
    
    res.json(assignments);
  } catch (error) {
    console.error('Error fetching assignments:', error);
    res.status(500).json({ error: 'Failed to fetch assignments' });
  }
});

// API endpoint to check existing assignments for multiple employees across a date range
app.post('/api/check-assignments', isAuth, async (req, res) => {
  try {
    const { empCodes, startDate, endDate } = req.body;
    
    if (!empCodes || !Array.isArray(empCodes) || !startDate || !endDate) {
      return res.status(400).json({ error: 'Missing required parameters' });
    }

    // Find all employees
    const employees = await Employee.find({ empCode: { $in: empCodes } });
    const employeeMap = {};
    employees.forEach(emp => {
      employeeMap[emp.empCode] = emp._id;
    });

    // Find all schedules for these employees
    const employeeIds = employees.map(emp => emp._id);
    const schedules = await AssignedSchedule.find({ 
      employee: { $in: employeeIds } 
    }).populate('project employee');

    // Generate date range with correct format, skipping weekends (same as schedule system)
    const start = new Date(startDate);
    const end = new Date(endDate);
    const dateRange = [];
    for (let d = new Date(start); d <= end; d.setDate(d.getDate() + 1)) {
      const dayOfWeek = d.getDay(); // 0=Sunday, 6=Saturday
      if (dayOfWeek !== 0 && dayOfWeek !== 6) { // Skip weekends
        const day = d.getDate();
        const monthName = d.toLocaleString('default', { month: 'short' });
        const dateStr = `${day}-${monthName}`;
        dateRange.push(dateStr);
      }
    }

    // Calculate existing allocations
    const allocations = {};
    empCodes.forEach(empCode => {
      allocations[empCode] = {};
      dateRange.forEach(date => {
        allocations[empCode][date] = { totalHours: 0, assignments: [] };
      });
    });

    schedules.forEach(schedule => {
      if (schedule.employee && schedule.dailyHours) {
        const empCode = schedule.employee.empCode;
        if (allocations[empCode]) {
          Object.keys(schedule.dailyHours).forEach(date => {
            if (allocations[empCode][date]) {
              const hours = schedule.dailyHours[date] || 0;
              allocations[empCode][date].totalHours += hours;
              allocations[empCode][date].assignments.push({
                projectName: schedule.project ? schedule.project.projectName : 'Unknown',
                hours: hours
              });
            }
          });
        }
      }
    });

    // Debug logging (remove in production)
    //console.log('Date range:', dateRange);
    //console.log('Allocations for first employee:', allocations[empCodes[0]]);

    res.json(allocations);
  } catch (error) {
    console.error('Error checking assignments:', error);
    res.status(500).json({ error: 'Failed to check assignments' });
  }
});

// API endpoint to create new assignment (Admin only)
app.post('/api/assignments', isAuth, async (req, res) => {
  try {
    const { empCode, date, projectId, hours } = req.body;
    
    if (!empCode || !date || !projectId || !hours) {
      return res.json({ success: false, message: 'Missing required fields' });
    }
    
    if (hours <= 0 || hours > 8) {
      return res.json({ success: false, message: 'Hours must be between 0.5 and 8' });
    }
    
    // Find employee
    const employee = await Employee.findOne({ empCode });
    if (!employee) {
      return res.json({ success: false, message: 'Employee not found' });
    }
    
    // Find project
    const project = await ProjectMaster.findById(projectId);
    if (!project) {
      return res.json({ success: false, message: 'Project not found' });
    }
    
    // Check if employee already has assignments for this date (8 hour limit)
    const existingSchedules = await AssignedSchedule.find({ employee: employee._id });
    let totalHoursOnDate = 0;
    
    existingSchedules.forEach(schedule => {
      if (schedule.dailyHours && schedule.dailyHours[date]) {
        totalHoursOnDate += parseFloat(schedule.dailyHours[date]);
      }
    });
    
    if (totalHoursOnDate + parseFloat(hours) > 8) {
      return res.json({ 
        success: false, 
        message: `Cannot exceed 8 hours per day. Current allocation: ${totalHoursOnDate}h. Available: ${8 - totalHoursOnDate}h` 
      });
    }
    
    // Find existing schedule for this employee and project, or create new one
    let schedule = await AssignedSchedule.findOne({
      employee: employee._id,
      project: project._id
    });
    
    if (!schedule) {
      schedule = new AssignedSchedule({
        employee: employee._id,
        project: project._id,
        dailyHours: {},
        scheduledBy: 'Calendar System',
        scheduledAt: new Date()
      });
    }
    
    // Add or update hours for the specific date
    if (!schedule.dailyHours) {
      schedule.dailyHours = {};
    }
    
    if (schedule.dailyHours[date]) {
      // Update existing hours
      schedule.dailyHours[date] = parseFloat(hours);
    } else {
      // Add new hours
      schedule.dailyHours[date] = parseFloat(hours);
    }
    
    schedule.markModified('dailyHours');
    await schedule.save();
    
    res.json({ 
      success: true, 
      message: `Successfully assigned ${hours}h of ${project.projectName} to ${employee.name} on ${date}` 
    });
    
  } catch (error) {
    console.error('Error creating assignment:', error);
    res.json({ success: false, message: 'Internal server error' });
  }
});

// API endpoint to update assignment (Admin only)
app.put('/api/assignments/:assignmentId', isAuth, async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const { hours, date } = req.body;
    
    if (!hours || hours <= 0 || hours > 8) {
      return res.json({ success: false, message: 'Hours must be between 0.5 and 8' });
    }
    if (!date) {
      return res.json({ success: false, message: 'Date is required to update assignment.' });
    }
    
    const schedule = await AssignedSchedule.findById(assignmentId).populate('employee project');
    if (!schedule) {
      return res.json({ success: false, message: 'Assignment not found' });
    }
    
    if (!schedule.dailyHours) {
      schedule.dailyHours = {};
    }
    
    // Check total hours constraint for the specified date
    const employee = schedule.employee;
    const allSchedules = await AssignedSchedule.find({ employee: employee._id });
    let totalHoursOnDate = 0;
    
    allSchedules.forEach(sched => {
      if (sched.dailyHours && sched.dailyHours[date]) {
        if (sched._id.toString() !== assignmentId) {
          totalHoursOnDate += parseFloat(sched.dailyHours[date]);
        }
      }
    });
    
    if (totalHoursOnDate + parseFloat(hours) > 8) {
      return res.json({ 
        success: false, 
        message: `Cannot exceed 8 hours per day. Other assignments: ${totalHoursOnDate}h. Available: ${8 - totalHoursOnDate}h` 
      });
    }
    
    schedule.dailyHours[date] = parseFloat(hours);
    schedule.markModified('dailyHours');
    await schedule.save();
    
    res.json({ 
      success: true, 
      message: `Successfully updated assignment to ${hours}h on ${date}` 
    });
    
  } catch (error) {
    console.error('Error updating assignment:', error);
    res.json({ success: false, message: 'Internal server error' });
  }
});

// API endpoint to delete assignment (Admin only)
app.delete('/api/assignments/:assignmentId', isAuth, async (req, res) => {
  try {
    const { assignmentId } = req.params;
    const { empCode, date } = req.body;
    
    const schedule = await AssignedSchedule.findById(assignmentId).populate('employee project');
    if (!schedule) {
      return res.json({ success: false, message: 'Assignment not found' });
    }
    
    // Remove the specific date from dailyHours
    if (schedule.dailyHours && schedule.dailyHours[date]) {
      delete schedule.dailyHours[date];
      schedule.markModified('dailyHours');
      
      // If no more dates are scheduled, delete the entire schedule
      if (Object.keys(schedule.dailyHours).length === 0) {
        await AssignedSchedule.findByIdAndDelete(assignmentId);
        res.json({ 
          success: true, 
          message: `Successfully deleted assignment and removed empty schedule` 
        });
      } else {
        await schedule.save();
        res.json({ 
          success: true, 
          message: `Successfully removed assignment for ${date}` 
        });
      }
    } else {
      res.json({ success: false, message: 'Assignment for specified date not found' });
    }
    
  } catch (error) {
    console.error('Error deleting assignment:', error);
    res.json({ success: false, message: 'Internal server error' });
  }
});


// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});
  // end of the file 
  
// Start server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});