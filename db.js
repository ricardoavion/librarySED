
const mysql = require('mysql');

const connection = mysql.createConnection({
    host: 'localhost',
    user: 'root',
    password: '', // Cambiar si aplica
    database: 'library'
});

connection.connect(err => {
    if (err) throw err;
    console.log('Conexión exitosa a MySQL');
});

module.exports = connection;
