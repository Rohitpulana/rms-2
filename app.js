require('dotenv').config();
console.log('MONGODB_URI:', process.env.MONGODB_URI);
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

//model

const Employee = require('./models/Employee'); // employee model
const ProjectMaster = require('./models/ProjectMaster');
const PracticeMaster = require('./models/PracticeMaster');
const AssignedSchedule = require('./models/AssignedSchedule');


// mongoose.connect('mongodb://127.0.0.1:27017/hrms-app', {
//   useNewUrlParser: true,
//   useUnifiedTopology: true
// })
// .then(() => console.log('✅ MongoDB connected'))
// .catch(err => console.error('❌ MongoDB error:', err));

 const mongoURI = process.env.MONGODB_URI;

mongoose.connect(process.env.MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true
}).then(() => {
  console.log('Connected to MongoDB');
}).catch(err => {
  console.error('MongoDB connection error:', err);
});

const app = express();
const port = 3000;

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

// Multer setup for file uploads
const upload = multer({ dest: 'uploads/' });

// EJS setup
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
    secure: false, // change to true in production with HTTPS
    httpOnly: true,
    sameSite: 'strict'
  }
}));

// CSRF protection
const csrfProtection = csrf({ cookie: false });

// CSRF error handler
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

// Auth middleware
function isAuth(req, res, next) {
  if (req.session.user) return next();
  res.redirect('/login');
}

function isAdmin(req, res, next) {
  if (req.session.user && req.session.user.role === 'admin') return next();
  res.status(403).send('Access Denied');
}

// Routes
app.get('/', (req, res) => {
  res.redirect('/login');
});


// Login GET
app.get('/login', csrfProtection, (req, res) => {
  res.render('login', {
    title: 'Login',
    messages: [],
    hasErrors: false,
    csrfToken: req.csrfToken(),
    layout: false
  });
});

// Login POST
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
  return res.status(403).send('Unauthorized role');
});

// Manager Dashboard
app.get('/dashboard/manager', isAuth, (req, res) => {
  res.send('Project Manager Dashboard 📋');
});

// Admin Dashboard
app.get('/dashboard/admin', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    //const employees = await Employee.find();
    res.render('admin-welcome', {
    // employees: employees,
      csrfToken: req.csrfToken(),
      title: 'Welcome Admin',
      layout: 'sidebar-layout'  // ✅ This is valid
    });
  } catch (err) {
    console.error('Error fetching employees:', err);
    res.status(500).send('Error loading dashboard.');
  }
});


// View Employees Page
app.get('/dashboard/admin/view-employees', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const search = req.query.search || '';
    const limit = parseInt(req.query.limit) || 10;

    const query = {
      $or: [
        { name: { $regex: search, $options: 'i' } },
        { empCode: { $regex: search, $options: 'i' } }
      ]
    };

    const employees = await Employee.find(query).limit(limit);

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

// View Project Master
app.get('/view-project-master', isAuth, isAdmin, async (req, res) => {
  try {
    const projects = await ProjectMaster.find(); // Make sure you have this model
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
          dihClient: row['DIH Client']
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
    const { date, project } = req.query;
    const filter = {};

    if (date) {
      const selectedDate = new Date(date);
      selectedDate.setHours(0, 0, 0, 0);
      const nextDay = new Date(selectedDate);
      nextDay.setDate(selectedDate.getDate() + 1);
      filter.date = { $gte: selectedDate, $lt: nextDay };
    }

    if (project) {
      filter.project = project; // project is now an _id from the dropdown
    }

    const projects = await ProjectMaster.find().sort({ projectName: 1 });

    const assignedEmployees = await AssignedSchedule.find(filter)
      .populate('employee')
      .populate('project')
      .populate('practice')
      .sort({ date: -1 });

    res.render('assigned-resources', {
      title: 'Assigned Resources',
      assignedEmployees,
      projects,
      filterDate: date,
      filterProject: project
    });
  } catch (err) {
    console.error('Error fetching assigned resources:', err);
    res.status(500).send('Internal Server Error');
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
    const practices = await PracticeMaster.find();

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
    res.json(practice);
  } catch (err) {
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


app.post('/schedule', isAuth, isAdmin, csrfProtection, async (req, res) => {
  try {
    const empCode = req.body.emp_id;
    const employee = await Employee.findOne({ empCode });

    if (!employee) return res.status(404).send('Employee not found');

    // FIX HERE: Use project_id instead of project_name
    const projectId = req.body.project_id;
    const project = await ProjectMaster.findById(projectId); // fetch by ID

    const practice = await PracticeMaster.findOne({ practiceName: req.body.practice });

    const newSchedule = new AssignedSchedule({
      employee: employee._id,
      project: project?._id || null,  // ObjectId reference
      practice: practice?._id || null,
      date: req.body.date,
      hours: req.body.hours,
      scheduledBy: req.session.user?.email || 'System',
      scheduledAt: new Date()
    });

    await newSchedule.save();
    res.redirect('/assigned-resources');
  } catch (err) {
    console.error('Schedule Save Error:', err);
    res.status(500).send('Failed to assign schedule');
  }
});

// Logout
app.get('/logout', (req, res) => {
  req.session.destroy(() => {
    res.redirect('/login');
  });
});

// Start server
app.listen(port, () => {
  console.log(`🚀 Server running at http://localhost:${port}`);
});
