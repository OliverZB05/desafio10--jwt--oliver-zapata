import { Router } from 'express';
import Cart from "../../dao/dbManagers/cartsManagerModel.js";
import Product from "../../dao/dbManagers/productsManagerModel.js";
import { cartsModel } from '../../dao/models/carts.js';
import { productModel } from '../../dao/models/products.js';
import passport from 'passport';

const router = Router();
const cartManager = new Cart();
const productManager = new Product();

/* router.get('/getAll', async (req, res) => {z

    try {
    const carts = await cartsModel.find();
    // transforma la respuesta
    const transformedCarts = carts.map(cart => {
    const transformedCart = cart.toObject();
    transformedCart.products = transformedCart.products.map(p => ({
    id: p.product,
    quantity: p.quantity
    }));
    return transformedCart;
    });

    res.send({ status: 'success', payload: transformedCarts });
    } catch (error) {
    console.error(error);
    res.status(500).send({ error: error.message });
    }
});


router.get('/:cid', async (req, res) => {
    const { cid } = req.params; 

    try {
    const cart = await cartsModel.findById(cid);
    if (!cart) {
    return res.status(404).send({ error: 'Cart not found' });
    }

    // transforma la respuesta
    const transformedCart = cart.toObject();
    transformedCart.products = transformedCart.products.map(p => ({
    id: p.product,
    quantity: p.quantity
    }));

    res.send({ status: "success", payload: transformedCart });
    }
    catch (error){
    console.error(error);
    res.status(500).send({ status: "error", error});
    }
}); */


router.get('/getAll', passport.authenticate('jwt', { session: false }), async (req, res) => {
    try {
    // Get only the carts associated with the current user
    const cartIds = req.user.carts.map(c => c.cart);
    const carts = await cartsModel.find({ _id: { $in: cartIds } });

    // Transform the response
    const transformedCarts = carts.map(cart => {
        const transformedCart = cart.toObject();
        transformedCart.products = transformedCart.products.map(p => ({
        id: p.product,
        quantity: p.quantity
        }));
        return transformedCart;
    });

    res.send({ status: 'success', payload: transformedCarts });
    } catch (error) {
    console.error(error);
    res.status(500).send({ error: error.message });
    }
});

/* router.get('/:cid', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const { cid } = req.params;

    try {
    // Check if the cart belongs to the current user
    const cartIds = req.user.carts.map(c => c.cart);
    if (!cartIds.includes(cid)) {
        return res.status(404).send({ error: 'Cart not found' });
    }

    // Get the cart
    const cart = await cartsModel.findById(cid);
    if (!cart) {
        return res.status(404).send({ error: 'Cart not found' });
    }

    // Transform the response
    const transformedCart = cart.toObject();
    transformedCart.products = transformedCart.products.map(p => ({
        id: p.product,
        quantity: p.quantity
    }));

    res.send({ status: "success", payload: transformedCart });
    } catch (error) {
    console.error(error);
    res.status(500).send({ status: "error", error });
    }
}); */

/* router.get('/:cid', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const { cid } = req.params;
    console.log('Cart ID:', cid);

    try {
    // Check if the cart belongs to the current user
    const cartIds = req.user.carts.map(c => c.cart);
    if (!cartIds.includes(cid)) {
        return res.status(404).send({ error: 'Cart not found' });
    }

    // Get the cart
    const cart = await cartsModel.findById(cid);
    console.log('Cart:', cart);
    if (!cart) {
        return res.status(404).send({ error: 'Cart not found' });
    }

    // Transform the response
    const transformedCart = cart.toObject();
    transformedCart.products = transformedCart.products.map(p => ({
        id: p.product,
        quantity: p.quantity
    }));

    res.send({ status: "success", payload: transformedCart });
    } catch (error) {
    console.error(error);
    res.status(500).send({ status: "error", error });
    }
}); */




router.get('/:cid', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const { cid } = req.params;
    /* console.log('Cart ID:', cid); */

    try {
        // Check if the cart belongs to the current user
        const cartIds = req.user.carts.map(c => c.cart.toString());
        /* console.log('User cart IDs:', cartIds) */;
        if (!cartIds.includes(cid)) {
            return res.status(404).send({ error: 'Cart not found' });
        }

        // Get the cart
        const cart = await cartsModel.findById(cid);
        /* console.log('Cart:', cart); */
        if (!cart) {
            return res.status(404).send({ error: 'Cart not found' });
        }

        // Transform the response
        const transformedCart = cart.toObject();
        transformedCart.products = transformedCart.products.map(p => ({
            id: p.product,
            quantity: p.quantity
        }));


        res.send({ status: "success", payload: transformedCart });
    } catch (error) {
        console.error(error);
        res.status(500).send({ status: "error", error });
    }
});





/* router.post('/', async (req, res) => {

    //console.log('Prueba#2 ' + JSON.stringify(req));

    const { products } = req.body;

    try {

        const result = await cartManager.create({
            products
        });

        res.send({ status: "success", payload: result })
    } catch (error) {
        res.status(500).send({ status: "error", error });
    }
}); */

router.post('/', passport.authenticate('jwt', { session: false }), async (req, res) => {
    const { cart } = req.body;

    try {
    // Create the cart
    const result = await cartManager.create({ cart });

    // Associate the cart with the current user
    req.user.carts.push({ cart: result._id });
    await req.user.save();

    res.send({ status: "success", payload: result });
    } catch (error) {
    res.status(500).send({ status: "error", error });
    }
});





router.post('/:cid/product/:pid', async (req, res) => {
    const cartId = req.params.cid;
    const prodId = req.params.pid;
    const quantity = req.body.quantity || 1;

    try {
    const cartData = await cartsModel.findById(cartId);
    if (!cartData) {
        return res.status(404).send({ error: 'Cart not found' });
    }

    const product = await productModel.findById(prodId);
    if (!product) {
        return res.status(404).send({ error: 'Product not found' });
    }

    // verifica si el campo products está definido
    if (!cartData.products) {
        cartData.products = [];
    }

    // busca si el producto ya está en el carrito
    const cartProductIndex = cartData.products.findIndex(p => p.product.equals(prodId));

    let updatedQuantity = quantity;

    // si el producto ya está en el carrito, actualiza su cantidad
    if (cartProductIndex !== -1) {
        cartData.products[cartProductIndex].quantity += quantity;
        updatedQuantity = cartData.products[cartProductIndex].quantity;
    }
    // si el producto no está en el carrito, agrégalo con la cantidad especificada
    else {
        cartData.products.push({ product: prodId, quantity });
    }

    await cartData.save();
    res.send({ status: 'success', payload: { id: prodId, quantity: updatedQuantity } });
    }
    catch (error) {
    console.error(error);
    res.status(500).send({ error: error.message });
    }
});


router.put('/:cid', async (req, res) => {
    const cartId = req.params.cid;
    const sort = req.query.sort;

    try {
    const cartData = await cartsModel.findById(cartId).populate('products.product');
    if (!cartData) {
        return res.status(404).send({ error: 'Cart not found' });
    }

    // Ordenar los productos según la dirección especificada
    if (sort === 'asc') {
        // Ordenar los productos en orden ascendente según su cantidad
        cartData.products.sort((a, b) => a.quantity - b.quantity);
    } else if (sort === 'desc') {
        // Ordenar los productos en orden descendente según su cantidad
        cartData.products.sort((a, b) => b.quantity - a.quantity);
    }

    // Paginación
    const page = parseInt(req.query.page) || 1; // Número de página actual
    const limit = parseInt(req.query.limit) || 3; // Número de documentos por página
    const skip = (page - 1) * limit; // Número de documentos a omitir

    const products = cartData.products.map(p => ({
        id: p.product.id,
        quantity: p.quantity
    }));
    const paginatedProducts = products.slice(skip, skip + limit);
    const totalProducts = products.length;
    const totalPages = Math.ceil(totalProducts / limit);

    const hasPrevPage = page > 1;
    const hasNextPage = page < totalPages;

    const prevPage = hasPrevPage ? page - 1 : null;
    const nextPage = hasNextPage ? page + 1 : null;

    const prevLink =
        hasPrevPage
        ? `${req.protocol}://${req.get('host')}${req.baseUrl}?page=${prevPage}&limit=${limit}`
        : null;
    const nextLink =
        hasNextPage
        ? `${req.protocol}://${req.get('host')}${req.baseUrl}?page=${nextPage}&limit=${limit}`
        : null;

    // Enviar respuesta al cliente
    res.send({
        status: 'success',
        payload: paginatedProducts,
        totalPages,
        prevPage,
        nextPage,
        page,
        hasPrevPage,
        hasNextPage,
        prevLink,
        nextLink,
    });
    } catch (error) {
    console.error(error);
    res.status(500).send({ error: error.message });
    }
});



router.put('/:cid/product/:pid', async (req, res) => {
    const cartId = req.params.cid;
    const prodId = req.params.pid;
    const quantity = req.body.quantity || 1;

    try {
    const cartData = await cartsModel.findById(cartId);
    if (!cartData) {
        return res.status(404).send({ error: 'Cart not found' });
    }

    const product = await productModel.findById(prodId);
    if (!product) {
        return res.status(404).send({ error: 'Product not found' });
    }

    // verifica si el campo products está definido
    if (!cartData.products) {
        cartData.products = [];
    }

    // busca si el producto ya está en el carrito
    const cartProductIndex = cartData.products.findIndex(p => p.product.equals(prodId));

    let updatedQuantity = quantity;

    // si el producto ya está en el carrito, actualiza su cantidad
    if (cartProductIndex !== -1) {
        cartData.products[cartProductIndex].quantity = quantity;
        updatedQuantity = cartData.products[cartProductIndex].quantity;
    }
    // si el producto no está en el carrito, agrégalo con la cantidad especificada
    else {
        cartData.products.push({ product: prodId, quantity });
    }

    await cartData.save();
    res.send({ status: 'success', payload: { id: prodId, quantity: updatedQuantity } });
    }
    catch (error) {
    console.error(error);
    res.status(500).send({ error: error.message });
    }
});


router.delete('/:cid/product/:pid', async (req, res) => {
    const cartId = req.params.cid;
    const prodId = req.params.pid;
    const quantity = req.body.quantity || 1;

    try {
    const cartData = await cartsModel.findById(cartId);
    if (!cartData) {
        return res.status(404).send({ error: 'Cart not found' });
    }

    const product = await productModel.findById(prodId);
    if (!product) {
        return res.status(404).send({ error: 'Product not found' });
    }

    // verifica si el campo products está definido
    if (!cartData.products) {
        cartData.products = [];
    }

    // busca si el producto ya está en el carrito
    const cartProductIndex = cartData.products.findIndex(p => p.product.equals(prodId));

    let remainingQuantity = 0;

    // si el producto ya está en el carrito, reduce su cantidad
    if (cartProductIndex !== -1) {
        cartData.products[cartProductIndex].quantity -= quantity;
        remainingQuantity = cartData.products[cartProductIndex].quantity;

        // si la cantidad es menor o igual a cero, elimina el producto del carrito
        if (cartData.products[cartProductIndex].quantity <= 0) {
        cartData.products.splice(cartProductIndex, 1);
        remainingQuantity = 0;
        }
    }
    else {
        return res.status(404).send({ error: 'Product not found in cart' });
    }

    await cartData.save();
    res.send({ status: 'success', payload: { id: prodId, quantity: remainingQuantity } });
    }
    catch (error) {
    console.error(error);
    res.status(500).send({ error: error.message });
    }
});


router.delete('/deleteCart/:cid', async (req, res) => {
    const { cid } = req.params; 

    try {
        const carts = await cartManager.delete(cid);
        res.send({ status: "success", payload: carts });
    }
    catch (error){
        res.status(500).send({ status: "error", error});
    }
});


router.delete('/:cid', async (req, res) => {
    const cartId = req.params.cid;

    try {
    const cartData = await cartsModel.findById(cartId);
    if (!cartData) {
        return res.status(404).send({ error: 'Cart not found' });
    }

    // Vaciar el arreglo de productos del carrito
    cartData.products = [];

    // Actualizar el carrito en la base de datos
    await cartData.save();

    // Enviar respuesta al cliente
    res.send({ status: 'success', payload: { products: [] } });
    } catch (error) {
    console.error(error);
    res.status(500).send({ error: error.message });
    }
});



export default router;