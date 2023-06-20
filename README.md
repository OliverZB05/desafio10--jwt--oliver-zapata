# desafio10--authentication--oliver-zapata

## Pasos para ejecutarlo

- Seleccionar el archivo app.js y abrir en terminal integrada (Es decir abrir la consola)
- Instalar las dependencias ingresando en la consola: npm i
- Colocar el comando: node app.js estándo en la caperta src, si no se está en el carpeta src entonces colocar: node src/app.js
- Abrir en el navegador las rutas http://localhost:8080 para abrir la página de registro

## Guía de rutas

### http://localhost:8080 o http://localhost:8080/login
En esta ruta se iniciará sesión en la página

### http://localhost:8080/register
En esta ruta se registrarán los datos del usuario

### http://localhost:8080/products
En esta ruta se verán todos los productos con paginación con la opción de poder pasar algún producto al carrito, también se pueden ejecutar métodos post y put mediante alguna herramienta como postman y en el navegador se verán los cambios automáticamente mediante la implementación de sockets al método get que muestra la vista de esta ruta

### http://localhost:8080/carts/646b7bbcb035a38e23da5ad8
En esta ruta se pueden ver los productos del carrito en tiempo real al establecerse el id del carrito al final de la ruta, en este caso muestro los productos
dentro del carrito con el id: 646b7bbcb035a38e23da5ad8



## Guía de métodos
En el archivo principal app.js usa 3 routers:

app.use("/", viewsProductRouter);            (views.products.js)
app.use("/api/products", productsRouter);    (products.router.js)
app.use("/api/carts", cartsRouter);          (carts.router.js)
app.use("/api/sessions", sessionsRouter);    (session.router.js)
app.use("/", viewsLoginRouter);              (views.login.js)

### Métodos del router products.router.js
### (Los métodos este router solo se pueden ejecutar mediante postman)

- Método GET<br>
http://localhost:8080/api/products<br>
Ahora con la implementación de la paginación se puede colocar al final de la ruta un límite y una pagina específica que se quiera ver, como por ejemplo de esta forma: http://localhost:8080/api/products?page=2&limit=3, también se puede especificar un orden añadiendo sort (De forma descendente: http://localhost:8080/api/products?sort=desc) (De forma ascendente: http://localhost:8080/api/products?sort=asc)

- Método GET por id<br>
http://localhost:8080/api/products/:pid <br>
Una vez creado un producto se coloca su id como valor en el parámetro :pid

- Método POST<br>
http://localhost:8080/api/products <br>

- Método PUT<br>
http://localhost:8080/api/products/:pid <br>
Se actualizará el producto con el id específicado

- Método DELETE<br>
http://localhost:8080/api/products/:pid <br>
Se borrará el producto con el id específicado


### Métodos del router carts.router.js
### (Los métodos este router solo se pueden ejecutar mediante postman)
- Método GETAll<br>
http://localhost:8080/api/carts/getAll<br>
Mediante este método el usuario puede darse cuenta de todos los carritos que se han creado

- Método GET por ID<br>
http://localhost:8080/api/carts/:pid<br>
Una vez creado un carrito se coloca su id como valor en el parámetro :pid

- Método POST<br>
http://localhost:8080/api/carts

- Método POST (para pasar un producto al carrito)<br>
http://localhost:8080/api/carts/:cid/product/:pid<br>
Aquí se usa el id del carrito en el parámetro :cid para especificar en que carrito quiero poner el producto, y se usa el id del producto en el parámetro :pid para especificar que producto a poner en el carrito

- Método PUT (para añadir paginación)<br>
http://localhost:8080/api/carts/:cid<br>
En este método se puede agregar también un sort, limit o page para hacer especificaciones en la página

- Método PUT (para actualizar un producto en el array de productos)<br>
http://localhost:8080/api/carts/:cid/product/:pid<br>
En este método se puede alterar la cantidad de un producto especifico de un carrito especifico según su id pasándole un objeto se esta manera por ejemplo: <br>
{             
  "quantity": 8<br>
}<br>

- Método DELETE (para quitar un producto del carrito)<br>
http://localhost:8080/api/carts/:cid/product/:pid<br>
Al igual que el método anterior se usa el id del carrito en el parámetro :cid para especificar de que carrito eliminar el producto, y se usa el id del producto en el parámetro :pid para especificar que producto eliminar del carrito.<br>
Cuando se elimina un producto con cierta cantidad (por ejemplo 8) esta va disminuyendo, pero si la cantidad es 1 y se ejecuta este método lo borrará al no quedar ninguna cantidad de ese producto

- Método DELETE (para eliminar carrito)<br>
http://localhost:8080/api/carts/deleteCart/:cid<br>
Se borrará el carrito con el id específicado


- Método DELETE (para eliminar todos los productos de un carrito)<br>
http://localhost:8080/api/carts/:cid<br>
Este método eliminará todos los productos de un carrito según su id


### Métodos del router views.products.js<br>
### (Los métodos este router solo se pueden en la web usando el navegador del lado del cliente)<br>
Este router usa las rutas http://localhost:8080/products y http://localhost:8080/carts/646b7bbcb035a38e23da5ad8 específicadas en la guía de rutas

### Métodos de passport.config.js<br>

- Método register de passport
Contiene la lógica del método POST de registro de sessions.router.js

- Método login de passport
Contiene la lógica del método POST de login de sessions.router.js

- Método de registro con github
Permite registrarse con github

### Métodos de sessions.config.js<br>

- Metódo POST (para registrarse)<br>
http://localhost:8080/register (esta ruta es de la vista el método post de registro se encuentra en session.router.js como router.post '/register')<br>
Con este método se envían los datos del usuario a la base de datos 

- Metódo POST (para iniciar sesión)<br>
http://localhost:8080 o http://localhost:8080/login (esta ruta es de la vista el método post de registro se encuentra en session.router.js como router.post '/login')<br>
Para ingresar los datos de registro y redirigirte luego a la vista de productos (ahora con la opción de registrarse con github)

- Método POST (para cerrar sesión) <br>
http://localhost:8080/api/sessions/logout <br>
Para destruir la sesión (salirse de la sesión)

- Método POST (para reset) <br>
http://localhost:8080/api/sessions/reset <br>
Para cambiar la contraseña de un usuario especificado

- Métodos GET de github <br>
Se añadieron nuevos métodos para poder ver los cambios que se hacen al registrarse con github, estos métodos son:<br>
http://localhost:8080/api/sessions/github<br>
http://localhost:8080/api/sessions/github-callback

### Métodos del router views.router.js<br>

En este router se renderizan las vistas de registro y de login mostradas en las rutas anotadas del router session.router.js, solo que en sessions.router.js se encuentra la lógica para que el funcionamiento de esas vistas funcione

### Nuevas implementaciones

- Ahora se maneja jwt en conjunto con passport<br>
- Se añadió una nueva ruta http://localhost:8080/api/sessions/current donde se ve el usuario
- Ahora los métodos get del carrito de compras está asociado a los usuarios por lo que solo se verán los carritos que haya creado el usuario registrado
