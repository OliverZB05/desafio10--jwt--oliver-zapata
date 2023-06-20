import mongoose from 'mongoose';

const cartsCollection = 'carts';

//========={ Esquema de carts }=========
const cartSchema = new mongoose.Schema({
    products: [
        {
            product: {
            type: mongoose.Schema.Types.ObjectId,
            ref: 'products'
            },
            quantity: {
            type: Number,
            default: 1
            }
        }
    ]
});
//========={ Esquema de carts }=========

export const cartsModel = mongoose.model(cartsCollection, cartSchema);