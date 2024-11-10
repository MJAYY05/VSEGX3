const path = require('path');
const express = require('express');
const mssql = require('mssql');
const bcrypt = require('bcryptjs');
const app = express();
const port = 436;
const jwt = require('jsonwebtoken');

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(express.static(path.join(__dirname, 'wwwroot')));
app.use('/images', express.static(path.join(__dirname,'images'))); 
// เสิร์ฟรูปภาพจากโฟลเดอร์ images

// การตั้งค่าการเชื่อมต่อกับฐานข้อมูล Azure SQL
const config = {
  user: 'cs436_023',
  password: 'cs43P@55',
  server: 'cs436-server.database.windows.net',
  database: 'VSEGChatDatabase',
  options: {
    encrypt: true, 
    trustServerCertificate: true
  }
};

// การตั้งค่าการเชื่อมต่อ pool
let poolPromise;

async function initDB() {
  try {
    poolPromise = await mssql.connect(config);
    console.log("Database connected successfully.");
  } catch (err) {
    console.error("Database connection failed:", err);
    process.exit(1); 
  }
}

// เริ่มต้นเชื่อมต่อฐานข้อมูล
initDB();

// ฟังก์ชันตรวจสอบชื่อผู้ใช้ (username)
function validateUsername(username) {
  // ชื่อผู้ใช้ต้องมีทั้งตัวอักษรและตัวเลข แต่ไม่สามารถใช้เฉพาะตัวเลขได้
  const regex = /^(?=.*[a-zA-Z])[a-zA-Z0-9]{1,20}$/;
  return regex.test(username);
}

// ตรวจสอบรหัสผ่าน
function validatePassword(password) {
  const regex = /^[a-zA-Z0-9]{1,20}$/;
  return regex.test(password);
}

// ฟังก์ชัน Register
// ฟังก์ชัน Register
// ฟังก์ชัน Register
app.post('/Register', async (req, res) => {
  const { username, email, password, confirm_password, firstname, lastname, phone } = req.body;

  // ตรวจสอบชื่อผู้ใช้ (username)
  const usernamePattern = /^[a-zA-Z0-9]{1,20}$/;
  if (!usernamePattern.test(username)) {
    return res.status(400).json({ message: 'Username must be alphanumeric and no longer than 20 characters.' });
  }

  // ตรวจสอบรหัสผ่าน
  const passwordPattern = /^[a-zA-Z0-9]{1,20}$/;
  if (!passwordPattern.test(password)) {
    return res.status(400).json({ message: 'Password must be alphanumeric and no longer than 20 characters.' });
  }

  // ตรวจสอบว่า password และ confirm_password ตรงกันหรือไม่
  if (password !== confirm_password) {
    return res.status(400).json({ message: 'Passwords do not match.' });
  }

  // ตรวจสอบ firstname
  const firstnamePattern = /^[a-zA-Z]+$/;  // ตรวจสอบเฉพาะตัวอักษรภาษาอังกฤษ
  if (!firstname || typeof firstname !== 'string' || firstname.trim() === '') {
    return res.status(400).json({ message: 'First name is required and must not be empty.' });
  }

  // ตรวจสอบ lastname (เฉพาะตัวอักษรภาษาอังกฤษ)
  const lastnamePattern = /^[a-zA-Z]+$/;  // ตรวจสอบเฉพาะตัวอักษรภาษาอังกฤษ
  if (!lastname || typeof lastname !== 'string' || lastname.trim() === '') {
    return res.status(400).json({ message: 'Last name is required and must only contain English letters.' });
  }

  // ตรวจสอบหมายเลขโทรศัพท์ (เบอร์โทรศัพท์ 10 หลัก)
  const phonePattern = /^[0-9]{10}$/;
  if (!phone || !phonePattern.test(phone)) {
    return res.status(400).json({ message: 'Phone number must start with 0 and be followed by 9 digits.' });
  }

  try {
    const pool = await poolPromise;

    // ตรวจสอบว่าอีเมลมีในฐานข้อมูลแล้วหรือไม่

    // ตรวจสอบชื่อผู้ใช้งาน (username) ว่ามีอยู่แล้วในฐานข้อมูลหรือไม่
    const usernameCheckResult = await pool.request()
      .input('username', mssql.NVarChar, username)
      .query('SELECT * FROM Users WHERE username = @username');
    
    if (usernameCheckResult.recordset.length > 0) {
      return res.status(400).json({ message: 'Username is already taken. Please choose another one.' });
    }

    // ตรวจสอบชื่อและนามสกุลว่ามีผู้ใช้อยู่แล้วในฐานข้อมูลหรือไม่
    const nameCheckResult = await pool.request()
      .input('firstname', mssql.NVarChar, firstname)
      .input('lastname', mssql.NVarChar, lastname)
      .query('SELECT * FROM Users WHERE firstname = @firstname AND lastname = @lastname');
    
    if (nameCheckResult.recordset.length > 0) {
      return res.status(400).json({ message: 'This full name is already taken by another user.' });
    }

    // ตรวจสอบหมายเลขโทรศัพท์ว่ามีอยู่ในระบบแล้วหรือไม่
    const phoneCheckResult = await pool.request()
      .input('phone', mssql.NVarChar, phone)
      .query('SELECT * FROM Users WHERE phone = @phone');
    
    if (phoneCheckResult.recordset.length > 0) {
      return res.status(400).json({ message: 'This phone number is already registered. Please use another one.' });
    }

    const emailCheckResult = await pool.request()
      .input('email', mssql.NVarChar, email)
      .query('SELECT * FROM Users WHERE email = @email');
    
    if (emailCheckResult.recordset.length > 0) {
      return res.status(400).json({ message: 'This email is already in use. Please choose another email.' });
    }

    // แฮชพาสเวิร์ดก่อนที่จะเก็บลงในฐานข้อมูล
    const hashedPassword = await bcrypt.hash(password, 10);

    // เพิ่มผู้ใช้ใหม่ในฐานข้อมูล
    await pool.request()
      .input('username', mssql.NVarChar, username)
      .input('firstname', mssql.NVarChar, firstname)
      .input('lastname', mssql.NVarChar, lastname)
      .input('phone', mssql.Char, phone) // ใส่ข้อมูลเบอร์โทรศัพท์
      .input('email', mssql.NVarChar, email)
      .input('password', mssql.NVarChar, hashedPassword)
      .query('INSERT INTO Users (username, firstname, lastname, phone, email, password) VALUES (@username, @firstname, @lastname, @phone, @email, @password)');

    // ส่งข้อความสำเร็จ
    res.status(201).json({ message: 'User registered successfully.' });

  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});
// API สำหรับเข้าสู่ระบบ (Login)
app.post('/login', async (req, res) => {
  const { username, password } = req.body;

  // ตรวจสอบรหัสผ่านก่อนทำการเปรียบเทียบกับฐานข้อมูล
  if (!validatePassword(password)) {
    return res.status(400).json({ message: 'Please check your password again.' });
  }

  try {
    const pool = await poolPromise;

    // ตรวจสอบว่าเป็น email หรือ username
    const isEmail = /^[a-zA-Z0-9]+@[a-zA-Z0-9]+\.[a-zA-Z]{2,}$/.test(username);

    let query;
    let result;

    // ถ้าเป็น email
    if (isEmail) {
      // ใช้ LOWER() สำหรับการตรวจสอบอีเมลเพื่อให้ไม่สนใจตัวพิมพ์ใหญ่-เล็ก
      query = `SELECT * FROM Users WHERE email = @username`;
    } else {
      // ถ้าเป็น username
      query = 'SELECT * FROM Users WHERE username = @username';
    }

    // ค้นหาผู้ใช้จากฐานข้อมูล
    result = await pool.request()
      .input('username', mssql.NVarChar(255), username)  // กำหนด length เป็น 255 หรือความยาวที่เหมาะสม
      .query(query);

    if (result.recordset.length === 0) {
      return res.status(400).json({ message: 'Invalid username/email or password.' });
    }

    // เปรียบเทียบรหัสผ่านที่ผู้ใช้กรอกกับรหัสผ่านที่แฮชไว้ในฐานข้อมูล
    const user = result.recordset[0];
    const isMatch = await bcrypt.compare(password, user.password);

    if (!isMatch) {
      return res.status(400).json({ message: 'Invalid username/email or password.' });
    }

    // สร้าง token เพื่อใช้ในการเข้าสู่ระบบ
    const token = jwt.sign({ userId: user.id }, 'your_secret_key', { expiresIn: '1h' });

    // ส่ง token กลับไปยังฝั่งไคลเอนต์
    res.status(200).json({ message: 'Login successful', token: token });

  } catch (err) {
    console.error('Error:', err);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// การตั้งค่าเส้นทางสำหรับหน้าเว็บ
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'Index.html'));
});

app.get('/Home', (req, res) => {
  res.sendFile(path.join(__dirname, 'Index.html'));
});

// หน้า Register
app.get('/Register', (req, res) => {
  res.sendFile(path.join(__dirname, 'register.html'));
});

app.get('/Signin', (req, res) => {
  res.sendFile(path.join(__dirname, 'signin.html'));
});

app.use(express.static(path.join(__dirname, 'public')));

// เสิร์ฟไฟล์ chat.html
app.get('/Chat', (req, res) => {
  res.sendFile(path.join(__dirname,'chat.html'));
});

app.get('/Email', (req, res) => {
  res.sendFile(path.join(__dirname, 'email.html'));
});

app.get('/style', (req, res) => {
  res.sendFile(path.join(__dirname, 'style.css'));
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'wwwroot', 'Index.html')); // เส้นทางที่ตรงกับ wwwroot
});

app.get('/Home', (req, res) => {
  res.sendFile(path.join(__dirname, 'wwwroot', 'Index.html')); // เส้นทางที่ตรงกับ wwwroot
});

app.get('/Register', (req, res) => {
  res.sendFile(path.join(__dirname, 'wwwroot', 'Register.html')); // เส้นทางที่ตรงกับ wwwroot
});

app.get('/Signin', (req, res) => {
  res.sendFile(path.join(__dirname, 'wwwroot', 'signin.html')); // เส้นทางที่ตรงกับ wwwroot
});

app.get('/Chat', (req, res) => {
  res.sendFile(path.join(__dirname, 'wwwroot', 'chat.html')); // เส้นทางที่ตรงกับ wwwroot
});

app.get('/Email', (req, res) => {
  res.sendFile(path.join(__dirname, 'wwwroot', 'Email.html')); // เส้นทางที่ตรงกับ wwwroot
});

app.get('/style', (req, res) => {
  res.sendFile(path.join(__dirname, 'wwwroot', 'style.html')); // เส้นทางที่ตรงกับ wwwroot
});


// เริ่มต้นเซิร์ฟเวอร์
app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});