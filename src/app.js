//========={ Dependencias }=========
import express from 'express';
import mongoose from 'mongoose';
import exphbs from 'express-handlebars';
import cookieParser from 'cookie-parser';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import initializePassport from './config/passport.config.js';
import passport from 'passport';
import flash from 'connect-flash';
import bodyParser from 'body-parser';
//========={ Dependencias }=========

//========={ Dirname }=========
import __dirname from './utils.js';
//========={ Dirname }=========

//========={ Routers }=========
import cartsRouter from './routes/api/carts.router.js';
import productsRouter from './routes/api/products.router.js';
import viewsProductRouter from './routes/web/views.products.js';
import sessionsRouter from './routes/api/sessions.router.js';
import viewsRouter from './routes/web/views.router.js';
//========={ Routers }=========

import { Server } from "socket.io";
import { getProducts } from './routes/web/views.products.js';
import { getCart } from './routes/web/views.products.js';

const app = express();

app.use(express.json());  
app.use(express.urlencoded({ extended: true }));

app.use(bodyParser.urlencoded({ extended: false }));
app.use(bodyParser.json());
app.use(cookieParser());
app.use(flash());

const hbs = exphbs.create({
helpers: {
debug: function (value) {
console.log("Current Context");
console.log("====================");
console.log(this);

if (value) {
console.log("Value");
console.log("====================");
console.log(value);
}
},
},
});

app.engine("handlebars", hbs.engine);
app.set("view engine", "handlebars");

app.set("view engine", "handlebars");
app.use(express.static(__dirname+"/public"));
app.set('views', `${__dirname}/views`);


let mongooseConnection;

const environment = async () => {
try {
mongooseConnection = await mongoose.connect('mongodb+srv://oliverzapata_arg:bxhp_bVE7c_DebEeSfFDÑñC_r@ecommerce.qe4ogkk.mongodb.net/?retryWrites=true&w=majority');
} catch (error) {
console.log(error);
}
}


async function main() {
await environment();
}

main();

app.use(session({
store: MongoStore.create({
client: mongoose.connection.getClient(),
ttl: 3600
}),
secret: 'Coder39760',
resave: true,
saveUninitialized: true
}))

//PASSPORT
initializePassport();
app.use(passport.initialize());
app.use(passport.session());

app.use("/", viewsProductRouter);
app.use("/api/products", productsRouter);

app.use("/api/carts", cartsRouter);

app.use("/api/sessions", sessionsRouter);
app.use("/", viewsRouter);

const server = app.listen(8080);
const io = new Server(server);

app.on('cartUpdated', async cartId => {
const productsData = await getProducts();
io.emit('products', productsData.products);

const cartData = await getCart(cartId);
io.emit('cart', cartData.products);
});

app.set('socketio', io);
io.sockets.setMaxListeners(20);