// 📦 Importación de librerías y controladores
const express = require('express')
const router = express.Router()

const authController = require('../controllers/authController')
console.log('authController:', authController)  // Verifica si se importa correctamente

// =============================
// 🧭 Rutas de vistas públicas y protegidas
// =============================

// Página principal (dashboard) protegida por middleware JWT
router.get('/', authController.isAuthenticated, (req, res) => {    
    res.render('index', { user: req.user })  // Renderiza index con datos del usuario autenticado
})

// Vista del formulario de login
router.get('/login', (req, res) => {
    res.render('login', { alert: false })  // Muestra formulario sin alertas por defecto
})

// Vista del formulario de registro
router.get('/register', (req, res) => {
    res.render('register')  // Muestra formulario de registro
})

// Vista de productos protegida con autenticación JWT
router.get('/productos', authController.isAuthenticated, (req, res) => {
    res.render('productos', { user: req.user })  // Muestra productos al usuario autenticado
})


// Procesa datos del registro de usuario
router.post('/register', authController.register)

// Procesa datos del login de usuario
router.post('/login', authController.login)

// Cierra la sesión y elimina la cookie con el token
router.get('/logout', authController.logout)

module.exports = router
