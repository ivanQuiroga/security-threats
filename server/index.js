const express = require('express');
const sqlite3 = require('sqlite3').verbose();
const csurf = require('csurf');
const app = express();
const PORT = 8080;
const exec = require('child_process').exec;

const session = require('express-session');
app.use(session({
  secret: 'tu_secreto',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: true }
}));
// Protección CSRF
app.use(csurf());
// Añadir el token CSRF a las vistas locales

const rateLimit = require('express-rate-limit');

const { query } = require('express-validator');
const escape = require('escape-html');

const fs = require('fs');
const path = require('path');

const allowedOrigins = ['http://localhost:8100', 'http://localhost:8080'];
const corsMiddleware = (req, res, next) => {
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.set('Access-Control-Allow-Origin', origin);
  }
  next();
};


/*app.get('/check-updates', (req, res) => {
  res.set('Access-Control-Allow-Origin', '*');
  const appVersionFile= req.query.versionFile;
  const command = `cat ${appVersionFile}.txt`;
  console.log(command);
  exec(command, (err, output) => {
    if (err) {
      res.status(500).send(err);
      return;
    }
    res.send({version: output.trim()});
  });
});*/

app.get('/check-updates', corsMiddleware, (req, res) => {
  const versionFile = req.query.versionFile;

  // Validar que versionFile es un nombre de archivo seguro, por ejemplo, sólo letras y números.
  if (!/^[a-z0-9]+$/i.test(versionFile)) {
    return res.status(400).send('Invalid version file format.');
  }

  // Construir el path del archivo de forma segura
  const safePath = path.join(__dirname, 'versions', `${versionFile}.txt`);

  // Leer el contenido del archivo de manera segura
  fs.readFile(safePath, 'utf8', (err, output) => {
    if (err) {
      // Manejar el error de manera apropiada, no devolver detalles del error al cliente
      console.error(err);
      return res.status(500).send('An error occurred while reading the version file.');
    }
    res.send({ version: output.trim() });
  });
});


const db = new sqlite3.Database('server.db');

app.get('/login',  query('username').escape(),  query('password').escape(),
  corsMiddleware, (req, res) => {

    const myUser = req.query.username;
    const myPassword = req.query.password;
    if (!myUser || !myPassword) {
      res.status(500).send({error: 'username and password are required'});
      return;
    }

    //const sql = `SELECT * FROM users WHERE username='${myUser}' AND password='${myPassword}'`;
    const sql = `SELECT * FROM users WHERE username=? AND password=?`;
    console.log(sql);
    //db.get(sql, (err, row) => {
    db.get(sql, [myUser, myPassword], (err, row) => {
      if (err) {
        res.status(500).send({error: 'error in login'});
      } else if (!row) {
        res.status(500).send({error: 'user not found'});
      } else {
        // Escapar la salida
        const escapedRow = {
          id: row.id,
          username: escape(row.username)
        };
        res.send(escapedRow);
      }
    });
  });

app.get('/messages', query('userId').escape(), corsMiddleware, (req, res) => {
  const myUser = req.query.userId;
  if (!myUser) {
    res.status(500).send({error: 'user id not provided'});
    return;
  }

  //const sql = `SELECT * FROM messages WHERE user_id='${myUser}'`;
  const sql = `SELECT * FROM messages WHERE user_id=?`;
  console.log(sql);
  //db.all(sql, (err, rows) => {
  db.all(sql, [myUser], (err, rows) => {
    if (err) {
      res.status(500).send({error: 'Error al obtener los mensajes del usuario'});
    } else {
      // Escapar la salida
      const escapedRows = rows.map(row => ({
        id: escape(row.id.toString()),
        user_id: escape(row.user_id.toString()),
        title: escape(row.title),
        contents: escape(row.contents),
        date: escape(row.date),
        message: row.message ? escape(row.message) : ''
      }));
      res.send(escapedRows);
    }
  });
});

app.listen(PORT,()=>console.log(`Server started on port ${PORT}`));

//PREVENCION DDoS
// Aplicar limitación de tasa a todas las solicitudes
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100 // limitar cada IP a 100 solicitudes por ventana de tiempo
});

// Aplicar la limitación de tasa al middleware de la aplicación
app.use(limiter);
