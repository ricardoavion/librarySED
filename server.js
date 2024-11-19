require('dotenv').config();
const http = require('http');
const mysql = require('mysql2');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Crear la conexión a la base de datos
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
});

// Función para analizar el cuerpo de una solicitud
function parseBody(req, callback) {
  let body = '';
  req.on('data', (chunk) => {
    body += chunk.toString();
  });
  req.on('end', () => {
    try {
      callback(JSON.parse(body));
    } catch (error) {
      console.error('Error procesando el cuerpo:', error);
      callback({});
    }
  });
}

// Crear el servidor HTTP
const server = http.createServer((req, res) => {
  console.log(`Solicitud recibida: ${req.method} ${req.url}`);

  if (req.method === 'GET' && req.url === '/') {
    const filePath = path.join(__dirname, 'public', 'index.html');
    fs.readFile(filePath, (err, content) => {
      if (err) {
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 Not Found</h1>');
      } else {
        res.writeHead(200, { 'Content-Type': 'text/html' });
        res.end(content);
      }
    });
  } else if (req.method === 'POST' && req.url === '/login') {
    parseBody(req, (body) => {
      const { email, password } = body;

      console.log('Datos recibidos para login:', body);

      if (!email || !password) {
        res.writeHead(400, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Email y contraseña son requeridos.' }));
        return;
      }

      const query = 'SELECT * FROM users WHERE user_email = ?';
      db.query(query, [email], (err, results) => {
        if (err) {
          console.error('Error en la consulta:', err);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Error interno del servidor.' }));
          return;
        }

        if (results.length === 0) {
          console.log('Usuario no encontrado.');
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Credenciales inválidas.' }));
          return;
        }

        const user = results[0];
        console.log('Usuario encontrado:', user);

        const [hashedPassword, salt] = user.user_password.split(':');
        const hash = crypto.createHash('sha256').update(password + salt).digest('hex');

        if (hash !== hashedPassword) {
          console.log('Contraseña incorrecta.');
          res.writeHead(401, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Credenciales inválidas.' }));
          return;
        }

        const token = jwt.sign(
          { id: user.user_id, name: user.user_full_name, role: user.role },
          process.env.JWT_SECRET,
          { expiresIn: '1h' }
        );

        console.log('Inicio de sesión exitoso. Token generado:', token);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({
          message: 'Inicio de sesión exitoso.',
          token,
          user: { id: user.user_id, name: user.user_full_name, role: user.role }
        }));
      });
    });
  } else if (req.method === 'GET' && req.url.startsWith('/admin/users')) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'No autorizado' }));
      return;
    }

    const token = authHeader.split(' ')[1];
    let userId;

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      if (payload.role !== 'admin') {
        res.writeHead(403, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Acceso denegado' }));
        return;
      }
    } catch (err) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Token inválido' }));
      return;
    }

    const role = new URL(req.url, `http://${req.headers.host}`).searchParams.get('role') || 'moderator';

    const query = 'SELECT user_id, user_full_name, user_email, role FROM users WHERE role = ?';
    db.query(query, [role], (err, results) => {
      if (err) {
        console.error('Error al obtener usuarios:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Error al obtener usuarios.' }));
        return;
      }

      res.writeHead(200, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify(results));
    });
  } else if (req.method === 'GET' && req.url.startsWith('/user/reservations')) {
    const authHeader = req.headers['authorization'];
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'No autorizado' }));
      return;
    }

    const token = authHeader.split(' ')[1];
    let userId;

    try {
      const payload = jwt.verify(token, process.env.JWT_SECRET);
      userId = payload.id;
    } catch (err) {
      res.writeHead(401, { 'Content-Type': 'application/json' });
      res.end(JSON.stringify({ error: 'Token inválido' }));
      return;
    }

    const url = new URL(req.url, `http://${req.headers.host}`);
    const date = url.searchParams.get('date') || new Date().toISOString().split('T')[0];

    const queryRooms = 'SELECT room_name FROM rooms';
    const queryReservations = `
      SELECT 
        r.reservation_room AS room_name, 
        TIME_FORMAT(r.reservation_from, '%H:%i') AS time_start, 
        TIME_FORMAT(r.reservation_to, '%H:%i') AS time_end, 
        r.reservation_id,
        u.user_full_name AS user_name
      FROM reservations r
      JOIN users u ON r.reservation_user_id = u.user_id
      WHERE r.reservation_day = ?
    `;

    db.query(queryRooms, (err, rooms) => {
      if (err) {
        console.error('Error al obtener salas:', err);
        res.writeHead(500, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ error: 'Error al obtener salas.' }));
        return;
      }

      db.query(queryReservations, [date], (err, reservations) => {
        if (err) {
          console.error('Error al obtener reservas:', err);
          res.writeHead(500, { 'Content-Type': 'application/json' });
          res.end(JSON.stringify({ error: 'Error al obtener reservas.' }));
          return;
        }

        console.log('Reservas obtenidas:', reservations);

        res.writeHead(200, { 'Content-Type': 'application/json' });
        res.end(JSON.stringify({ rooms, reservations }));
      });
    });
  } else if (req.method === 'GET') {
    const filePath = path.join(__dirname, 'public', req.url === '/' ? 'index.html' : req.url);

    fs.readFile(filePath, (err, content) => {
      if (err) {
        console.error('Error al servir archivo:', err);
        res.writeHead(404, { 'Content-Type': 'text/html' });
        res.end('<h1>404 Not Found</h1>');
      } else {
        const ext = path.extname(filePath);
        let contentType = 'text/html';
        if (ext === '.css') contentType = 'text/css';
        else if (ext === '.js') contentType = 'application/javascript';

        res.writeHead(200, { 'Content-Type': contentType });
        res.end(content);
      }
    });
  } else {
    res.writeHead(404, { 'Content-Type': 'text/html' });
    res.end('<h1>404 Not Found</h1>');
  }
});

// Definir el puerto del servidor
const PORT = process.env.PORT || 3000;

// Iniciar el servidor
server.listen(PORT, () => {
  console.log(`Servidor corriendo en http://localhost:${PORT}`);
});
