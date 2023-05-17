const mysql = require('mysql');

const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'xander007',
  database: 'cybersecurity'
});

const username = 'cyberx';
const password = 'xander';

pool.query('INSERT INTO users (username, password) VALUES (?, ?)', [username, password], function (error, results, fields) {
  if (error) throw error;
  console.log('User inserted successfully');


pool.end();
});
