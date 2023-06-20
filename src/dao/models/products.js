import mongoose from 'mongoose';

const productsCollection = 'products';

//========={ Esquema de products }=========
const productSchema = new mongoose.Schema({
    title: {
        type: String,
        required: true
    },
    description: {
        type: String,
        required: true
    },
    price: {
        type: Number,
        required: true
    },
    thumbnail: {
        type: Array,
        default: []
    },
    stock: {
        type: Number,
        required: true
    },
    category: {
        type: String,
        required: true
    },
    status: {
        type: Boolean,
        default: true
    },
    code: {
        type: Boolean,
        default: true
    }
});
//========={ Esquema de products }=========

export const productModel = mongoose.model(productsCollection, productSchema);