const express = require('express');
const mongoose = require('mongoose');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const User = require('./user');

const app = express();
const port = 3000;

const JWT_SECRET = '_clave_secreta_jwt';

app.use(cors());
app.use(bodyParser.json());

// Conexión a MongoDB
mongoose.connect('mongodb://127.0.0.1:27017/pc02')
  .then(() => console.log('Conexión exitosa a MongoDB'))
  .catch(err => console.error('Error al conectar a MongoDB:', err));

// Middleware para autenticar el token
function authenticateToken(req, res, next) {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
}

// Ruta para registrar un nuevo usuario
app.post('/api/register', async (req, res) => {
  const { username, email, password } = req.body;

  try {
    // Verificar si el usuario o el correo electrónico ya existen
    const existingUser = await User.findOne({ $or: [{ email }, { username }] });
    if (existingUser) {
      return res.status(400).json({ message: 'El usuario o correo electrónico ya está en uso' });
    }

    // Hashear la contraseña
    const hashedPassword = await bcrypt.hash(password, 10);

    // Crear un nuevo usuario
    const newUser = new User({ username, email, password: hashedPassword });
    await newUser.save();

    res.status(201).json({ message: 'Usuario registrado con éxito', newUser });
  } catch (error) {
    res.status(500).json({ message: 'Error al registrar el usuario', error });
  }
});

// Ruta para iniciar sesión
app.post('/api/login', async (req, res) => {
  const { emailOUsuario, password } = req.body;

  try {
    const user = await User.findOne({
      $or: [
        { email: emailOUsuario },
        { username: emailOUsuario }
      ]
    });

    // Agregamos logs para depuración
    console.log('Usuario encontrado:', user);
    console.log('Contraseña proporcionada:', password);

    if (!user) {
      // Si no se encuentra el usuario, devolver un error de credenciales incorrectas
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }

    // Comparamos la contraseña en texto plano con la contraseña hasheada
    const isMatch = await bcrypt.compare(password, user.password);
    console.log('Resultado de la comparación:', isMatch);

    if (!isMatch) {
      // Si no coinciden, devolver un error de credenciales incorrectas
      return res.status(401).json({ message: 'Credenciales incorrectas' });
    }

    // Si la contraseña coincide, firmamos el token
    const token = jwt.sign({ userId: user._id }, JWT_SECRET, { expiresIn: '1h' });
    res.status(200).json({ message: 'Inicio de sesión exitoso', token });

  } catch (error) {
    // Log del error
    console.error('Error durante el inicio de sesión:', error);
    res.status(500).json({ message: 'Error al iniciar sesión', error });
  }
});

// Ruta para obtener todos los usuarios
app.get('/api/users', authenticateToken, async (req, res) => {
  try {
    const users = await User.find({});
    res.status(200).json(users);
  } catch (error) {
    res.status(500).json({ message: 'Error al recuperar usuarios', error });
  }
});

app.listen(port, () => {
  console.log(`Servidor corriendo en el puerto ${port}`);
});
