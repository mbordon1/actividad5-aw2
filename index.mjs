import express from 'express';
import bcrypt from 'bcryptjs';
import cookieParser from 'cookie-parser';
import { nanoid } from 'nanoid';
import pool from './conexion.bd.mjs';

const PUERTO = 3000;
const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cookieParser()); // para leer req.cookies

// ── Middleware: proteger /admin 
async function verificarSesion(req, res, next) {
    const cookieRecibida = req.cookies.sesion;

    // Si no hay cookie → redirigir al login
    if (!cookieRecibida) {
        return res.redirect('/login');
    }

    // Buscar en BD si existe un usuario con ese session_id
    const resultado = await pool.query(
        'SELECT id FROM usuarios WHERE session_id = $1',
        [cookieRecibida]
    );

    if (resultado.rowCount === 0) {
        return res.redirect('/login');
    }

    next(); // todo ok → dejar pasar
}

// ── Rutas estáticas 
app.use('/login', express.static('./fronts/front-login'));

// /admin protegido con el middleware
app.use('/admin', verificarSesion, express.static('./fronts/front-admin'));

// ── POST /registrar 
app.post('/registrar', async (req, res) => {
    const { usuario, pass } = req.body;

    if (!usuario || !pass) {
        return res.status(400).json({ mensaje: 'Datos incompletos' });
    }

    const salt = await bcrypt.genSalt(10);
    const hash = await bcrypt.hash(pass, salt);

    const resultado = await pool.query(
        `INSERT INTO usuarios (username, password_hash)
         VALUES ($1, $2)
         RETURNING id, username`,
        [usuario, hash]
    );

   if (resultado.rowCount > 0) {
    return res.redirect('/login')
}

    res.status(500).json({ mensaje: 'No se pudo realizar el registro' });
});

//  POST /autenticar 
app.post('/autenticar', async (req, res) => {
    const { usuario, pass } = req.body;

    if (!usuario || !pass) {
        return res.status(400).json({ mensaje: 'Datos incompletos' });
    }

    // 1 — Buscar usuario en BD
    const resultado = await pool.query(
        'SELECT * FROM usuarios WHERE username = $1',
        [usuario]
    );

    if (resultado.rowCount === 0) {
        return res.status(401).json({ mensaje: 'Usuario o contraseña incorrectos' });
    }

    const usuarioBD = resultado.rows[0];

    // 2 — Comparar contraseña con el hash guardado
    const coincide = await bcrypt.compare(pass, usuarioBD.password_hash);

    if (!coincide) {
        return res.status(401).json({ mensaje: 'Usuario o contraseña incorrectos' });
    }

    // 3 — Generar ID de sesión con nanoid y guardarlo en BD
    const idSesion = nanoid();

    await pool.query(
        'UPDATE usuarios SET session_id = $1 WHERE id = $2',
        [idSesion, usuarioBD.id]
    );

    // 4 — Enviar cookie al navegador y redirigir al admin
    res.cookie('sesion', idSesion, {
        httpOnly: true,  // no accesible desde JS del navegador
        secure: false,   // true en producción con HTTPS
        maxAge: 1000 * 60 * 60  // 1 hora
    });

    res.redirect('/admin');
});

// ── POST /logout 
app.post('/logout', async (req, res) => {
    const cookieRecibida = req.cookies.sesion;

    if (cookieRecibida) {
        // Borrar session_id de la BD
        await pool.query(
            'UPDATE usuarios SET session_id = NULL WHERE session_id = $1',
            [cookieRecibida]
        );
    }

    res.clearCookie('sesion');
    res.redirect('/login');
});

app.listen(PUERTO, () => {
    console.log(`Servidor escuchando en el puerto ${PUERTO}`);
});