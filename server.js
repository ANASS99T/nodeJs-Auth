if (process.env.NODE_ENV !== 'production') {
  require('dotenv').config();
}

const express = require('express');
const app = express();
const bcrypt = require('bcrypt');
const mysql = require('mysql');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');

const database = mysql.createConnection({
  host: process.env.db_host,
  user: process.env.db_user,
  password: process.env.db_password,
  database: process.env.db_database,
});

database.connect((err) => {
  if (err) {
    console.log(err);
  } else {
    console.log('MySql is connected');
  }
});



// const users = [];
var loggedin = false;
var message = null
app.set('view-engine', 'ejs');
app.use(express.static(__dirname + '/views'));
app.use(express.urlencoded({ extended: false }));

app.use(cookieParser());
app.get('/', validateCookie, (req, res) => {
  res.render('home.ejs', { loggedin: loggedin });
});

app.get('/home', validateCookie, (req, res) => {
  res.render('home.ejs', { loggedin: loggedin });
});

app.get('/profile', validateCookie, (req, res) => {
  if(!loggedin)
    res.redirect('/')
  else
    res.render('profile.ejs', {
      name: req.cookies.name,
      email: req.cookies.email,
      loggedin: true,
    });
});

app.get('/login', validateCookie, (req, res) => {
  if(!loggedin)
    res.render('login.ejs', { loggedin: false, message: message });
  else
    res.redirect('/');
    
  
});

app.post('/login', validateCookie, async (req, res) => {
  if(loggedin){
    res.redirect('/')
  }
  try {
    const { email, password } = req.body;
    if (!email || !password) {
      return res.render('login.ejs', {
        message: 'Email or password is required',
        loggedin: false
      });
    }
    database.query(
      'SELECT * FROM user WHERE email = ?',
      [email],
      async (error, results) => {
        if (!results.length > 0  || !results[0]['email']|| !(await bcrypt.compare(password, results[0].password))) {
          res.render('login.ejs', { message: 'Email or password incorrect', loggedin: false });
        } else {
          const id = results[0].id;
          const name = results[0]['name'];
          // const email = results[0]['email'];
          const token = jwt.sign({ id }, process.env.JWT_TOKEN, {
            expiresIn: process.env.JWT_EXPIRES_IN,
          });

          const cookiesOptions = {
            expires: new Date(
              Date.now() + process.env.JWT_COOKIE_EXPIRES * 24 * 3600000
            ),
            httpOnly: true,
          };

          res.cookie('sessionToken', token, cookiesOptions);
          res.cookie('name', name, cookiesOptions);
          res.cookie('email', email, cookiesOptions);          
          loggedin = true;
          res.redirect('/');
        }
      }
    );
  } catch (error) {
    console.log(error);
  }
});


app.get('/register', validateCookie, (req, res) => {
  if(!loggedin)
    res.render('register.ejs', { loggedin: loggedin, message:message });
  else
    res.redirect('/');
});

app.post('/register', validateCookie, async (req, res) => {
  if(loggedin){
      return res.redirect('/');
  }
  const { name, email, password, conf_password } = req.body;

  //Verify if email already exist and passwords match
  database.query(
    'SELECT email from user WHERE email = ?',
    [email],
    async (error, result) => {
      if (error) {
        console.log(error);
      }
      if (result.length > 0) {
        return res.render('register.ejs', { message: 'Email already exists', loggedin:false });
      } else if (password !== conf_password) {
        return res.render('register.ejs', { message: "Passwords don't match", loggedin: false });
      } else {
        const hashedPassword = await bcrypt.hash(password, 10);
        database.query(
          'INSERT INTO user SET ?',
          { name: name, email: email, password: hashedPassword },
          (err, resu) => {
            if (err) {
              console.log(err);
              return res.render('register.ejs', {
                message: "Couldn't create the user, please try again",
                loggin: false
              });
            }
          }
        );
        return res.redirect('/login');
      }
    }
  );

});

app.post('/logout', (req, res) => {
  // req.logOut();

  res.cookie('sessionToken', '', { maxAge: 0 });
  res.cookie('name', '', { maxAge: 0 });
  res.cookie('email', '', { maxAge: 0 });

  loggedin = false
  message = null
  res.redirect('/');
});

function validateCookie(req, res, next){
  const { cookies } = req
  if ('sessionToken' in cookies){
    loggedin = true;
    next();
  } 
  else{
    loggedin = false;
    next();
  }
  
}

app.listen(3030);
console.log('server is running on port: 3030');
