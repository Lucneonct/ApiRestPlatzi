const express = require('express');
const axios = require('axios');
const jwt = require('jsonwebtoken');
const app = express();
const bodyParser = require('body-parser');
const crypto = require('crypto');

// Middlewares para recibir JSON a traves del API en express
app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());

const path = require('path');
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'))
})

// Parametros permitidos para "resource_type"
const allowedResources = [
  'books',
  'authors',
  'genres'
];

// Array de objetos que contienen los libros
const books = [
  { title: 'Lo que el viento se llevo', id_author: 2, id_genre: 2 },
  { title: 'La Iliada', id_author: 1, id_genre: 1 },
  { title: 'La odisea', id_author: 1, id_genre: 1 }
];

// Creamos nuestro secret
const secret = 'Sh!! No se lo cuentes a nadie!';

// -----------------------  TOKEN AUTH SERVER -------------------------

app.post('/register', (req, res) => {  
  const uid = req.headers['x-client-id'] || '1';

  // Creamos el token con JsonWebToken
  const token = jwt.sign(uid, secret);

  // Retornamos el token
  res.json({ token });  
})

app.get('/login', (req, res) => {
  // Obtiene el token de los headers
  const token = req.headers['x-token'] || '';

  // De esta forma evitamos errores de verificación
  try {
    // Obtenemos el id verificando que el hash coincida con el secret
    const uid = jwt.verify(token, secret);

    // Verificamos si el id obtenido es igual a 1
    if(uid === "1") {
      // Devuelve verdadero si coincide
      res.send({ auth: true })      
    } else {
      // Devuelve falso si no coincide
      res.send({ auth: false })    
    }
  } catch(e) {
    // Devuelve falso si hay un error
    res.send({ auth: false })
  }
})

// ---------------------  END TOKEN AUTH SERVER -----------------------

// Middleware de autenticación
const bookAuthenticator = async (req, res, next) => {  
  // Obtiene la autenticación como "username:password" 
  // Y lo convierte en un array como ["username", "password"]
  let authorization = [];

  // Verificamos si se envian headers de autenticación HTTP
  if(req.headers['authorization']) {
    // req.headers.authorization es encodeado en base64, tal como: "Basic bHVjbmVvbmN0OjEyMzQ="
    // Con un Buffer lo decodeamos: Buffer.from('string','base64')
    authorization = Buffer
      // Separamos en dos arreglos, para usar solo el string encodeado
      // ["Basic", "bHVjbmVvbmN0OjEyMzQ="]
      .from(req.headers.authorization.split(" ")[1], 'base64')
      // Lo transformamos en utf-8
      // "lucneonct:1234"
      .toString('utf-8')
      // Lo separamos por el ":" en un array
      // ["lucneonct", "1234"]
      .split(':');
  } 
  // Verificamos si se envian headers de autenticación HMAC
  else if(req.headers['x-hash']) {
    // Recibe los parametros enviados en req.headers
    // Si no hay se lo deja en blanco
    const hash = req.headers['x-hash'] || '';
    const uid = req.headers['x-uid'] || '';
    const timestamp = req.headers['x-timestamp'] || '';

    // Usamos el paquete de crypto que viene con NodeJS para crear el SHA1
    const hmac = crypto.createHmac('sha1', secret);
    // Pasamos nuestro UID y TIMESTAMP al método update
    hmac.update( uid + timestamp );

    // Comparamos que el hash enviado y el creado sean iguales
    // Usamos hmac.digest('hex') para que nos muestre el hash en hexadecimal
    if(hash === hmac.digest('hex')) {
      // Rellenamos nuestro arreglo de autorización para pasar la validación posterior
      authorization = ['lucneonct', '1234'];
    }
  }
  // Verificamos si se envian headers de autenticación TOKEN
  else if(req.headers['x-token']) {
    await axios({
      method: 'GET',
      // Modificado para http://localhost:5000/login
      // Esto para poder desplegarlo en heroku sin problemas
      url: `http://${
        process.env.HOST || 'localhost'
      }:${
        process.env.PORT || '5000'
      }/login`,
      headers: {
        "x-token": req.headers['x-token']
      }
    })
      .then(response => {
        if(response.data.auth) {
          authorization = ['lucneonct','1234'];
        }
      });
  }

  // Obtiene username del primer indice del arreglo y la contraseña del segundo
  const authUser = authorization[0];
  const authPassword = authorization[1];

  // Verificamos si los datos no coinciden con nuestro usuario hardcodeado
  if( authUser !== "lucneonct" || authPassword !== "1234") {
    // Rompe la cadena y retorna un 403 Forbidden
    return res.status(403).json({ status: 'Forbidden: missing or invalid auth' });
  }

  next()
}

app.get('/books', bookAuthenticator, (req, res) => {
  // Si sale todo bien, devuelve un ok junto a los libros
  res.json({ status: 'ok', books });
});

app.post('/books', bookAuthenticator, (req, res) => {
  // Verifica si se envian datos por formulario
  if(req.body) {
    // Verifica si falta "title", "id_author" o "id_genre"
    if(!req.body.title || !req.body.id_author || !req.body.id_genre) {
      // Devuelve error si falta alguno
      return res.status(400).json({ status: 'Failed', error: 'missing or invalid: data' });
    }

    // Inserta un nuevo objeto al array, y devuelve el id insertado 
    // (característica javascript)
    const insertCount = books.push({
      title: req.body.title,
      id_author: req.body.id_author,
      id_genre: req.body.id_genre
    })

    // Devuelve ok y el id insertado si todo salió bien
    res.json({ status: 'ok', insert_id: insertCount - 1, books })
  } else {
    // Devuelve un error si no se envian datos por formulario
    res.status(400).json({ status: 'Failed', error: 'error no data' });
  }
})

app.get('/books/:id', bookAuthenticator, (req, res) => {
  // Si no pasa la validación devuelve un 403 forbidden

  // Verificamos si el libro no existe
  if(!books[req.params.id]) {
    // Devolvemos un error 404 si no existe
    return res.status(404).json({ status: 'Not found' })
  } else {
    // Devolvemos el libro y estado 200 automáticamente
    res.json(books[req.params.id])
  }
})

app.put('/books/:id', bookAuthenticator, (req, res) => {
  const paramId = req.params.id
  // Verifica si se ha puesto un id y que este exista
  if(paramId && books[paramId]) {
    const book = books[paramId];

    // Modificar solo los datos que se hayan enviado
    book.title = req.body.title || book.title;
    book.id_author = req.body.id_author || book.id_author;
    book.id_genre = req.body.id_genre || book.id_genre;
    // Esta sintaxis dice: 
    // "Es igual al dato enviado (req.body.title), 
    // Y si está vacío (||) dejar el valor por defecto (book.title)"

    // Guardar el libro modificado
    books[paramId] = book;

    // Envia un ok, el libro modificado y la colección de libros
    res.send({ status: 'ok', book, books })
  } else {
    // En caso de no encontrar, devuelve error
    res.status(400).json({ status: 'Failed', error: 'missing or invalid param: id' });
  }
})

app.delete('/books/:id', bookAuthenticator, (req, res) => {
  const paramId = parseInt(req.params.id)
  // Verifica si se ha puesto un id y que este exista
  if(books[paramId]) {
    // Remueve el indice enviado y lo guarda en "deleted_book"
    const deleted_book = books.splice(paramId, 1);

    // Envia un ok, el libro eliminado y la colección de libros
    res.send({ status: 'ok', deleted_book, books })
  } else {
    // En caso de no encontrar, devuelve error
    res.status(400).json({ status: 'Failed', error: 'missing or invalid param: id' });
  }
})

// Iniciador del servidor, en el puerto 5000
app.listen(process.env.PORT || 5000, () => {
  console.log(`Server on port ${process.env.PORT || 5000}`);
});