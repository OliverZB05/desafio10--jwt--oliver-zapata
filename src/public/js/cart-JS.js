const socket = io();

socket.on('cart', products => {
// Actualiza la lista de productos en el carrito en tiempo real
const cartList = document.getElementById("cart-list");
cartList.innerHTML = products.map(product => `
    <li>${product.title} - ${product.price} x ${product.quantity}</li>
`).join('');
});
