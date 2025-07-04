require('dotenv').config()
const mysql = require('mysql2')

const connection = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  port: process.env.DB_PORT
})

connection.connect(error => {
  if (error) {
    console.error('❌ El error de conexión es:', error.message)
    return
  }
  console.log('✅ Conectado correctamente a la base de datos.')
})

module.exports = connection
