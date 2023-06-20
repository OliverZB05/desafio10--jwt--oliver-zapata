import { cartsModel } from '../models/carts.js';

export default class Cart {
    constructor() {
        console.log('Working users with DB')
    }

    create = async (crt) => {
        const result = await cartsModel.create(crt);
        return result;
    }

    getId = async (cid) => {
        const products = await cartsModel.find({ _id: cid });
        return products.map(prod => prod.toObject());
    }

    delete = async (cid) => {
        const result = await cartsModel.deleteOne({ _id: cid });
        return result;
    }

    update = async (cid, prod) => {
        const result = await cartsModel.updateOne({ _id: cid }, prod);
        return result;
    }

    getAll = async () => {
        const carts = await cartsModel.find();
        return carts.map(cart => cart.toObject());
    }

    getAllPaginated = async (limit, page) => {
        const carts = await cartsModel.paginate({}, { limit, page, lean: true });
        return carts; 
    }
}