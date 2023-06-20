import { Router } from 'express';
import Product from "../../dao/dbManagers/productsManagerModel.js";
import { productModel } from '../../dao/models/products.js';

const router = Router();
const productManager = new Product();


router.get('/', async (req, res) => {
    try {
    const page = parseInt(req.query.page) || 1; // Número de página actual
    const limit = parseInt(req.query.limit) || 3; // Número de documentos por página
    const skip = (page - 1) * limit; // Número de documentos a omitir

    // Agregar parámetros de consulta adicionales
    const category = req.query.category;
    const availability = req.query.availability;
    const sort = req.query.sort;

    // Construir objeto de filtro
    let filter = {};
    if (category) {
    filter.category = category;
    }
    if (availability) {
    filter.stock = availability === 'available' ? { $gt: 0 } : { $eq: 0 };
    }


    // Construir objeto de opciones
    let options = { skip, limit };
    if (sort) {
    options.sort = { price: sort === 'asc' ? 1 : -1 };
    }

    // Obtener productos filtrados y ordenados
    const products = await productModel.find(filter, null, options);
    const totalProducts = await productModel.countDocuments(filter);
    const totalPages = Math.ceil(totalProducts / limit);

    const hasPrevPage = page > 1;
    const hasNextPage = page < totalPages;

    const prevPage = hasPrevPage ? page - 1 : null;
    const nextPage = hasNextPage ? page + 1 : null;

    const prevLink = hasPrevPage ? `${req.protocol}://${req.get('host')}${req.baseUrl}?page=${prevPage}&limit=${limit}` : null;
    const nextLink = hasNextPage ? `${req.protocol}://${req.get('host')}${req.baseUrl}?page=${nextPage}&limit=${limit}` : null;

    res.send({
    status: "success",
    payload: products,
    totalPages,
    prevPage,
    nextPage,
    page,
    hasPrevPage,
    hasNextPage,
    prevLink,
    nextLink
    });
    }
    catch (error){
        console.error(error);
    res.status(500).send({ status: "error", error});
    }
});


router.get('/:pid', async (req, res) => { 
    const { pid } = req.params; 

    try {
        const products = await productManager.getId(pid);
        res.send({ status: "success", payload: products });
    }
    catch (error){
        res.status(500).send({ status: "error", error});
    }
});


router.post("/", async (req, res) => {
    const { title, description, price, thumbnail, stock, category } = req.body;

    if(!title || !description || !price || !thumbnail || !stock || !category){
    return res.status(400).send({ status: "error", error: "incomplete values"})
    }

    try{
    const existingProduct = await productModel.findOne({ title, description });
    if (existingProduct) {
        res.status(400).send({ status: "error", error: `El producto con título "${title}" y descripción "${description}" ya existe en la base de datos.` });
    } else {
        const result = await productManager.create({
        title,
        description,
        price,
        thumbnail,
        stock,
        category
        });

        res.send({status: "success", payload: result})
    }
    }
    catch (error){
    res.status(500).send({ status: "error", error});
    }
});


router.put('/:pid', async (req, res) => {
    const { title, description, price, thumbnail, stock, category } = req.body;
    const { pid } = req.params; 

    if(!title || !description || !price || !thumbnail || !stock || !category){
    return res.status(400).send({ status: "error", error: "incomplete values"})
    }

    try{
    const existingProduct = await productModel.findOne({ _id: { $ne: pid }, title, description });
    if (existingProduct) {
        res.status(400).send({ status: "error", error: `El producto con título "${title}" y descripción "${description}" ya existe en la base de datos.` });
    } else {
        const result = await productManager.update(pid, {
        title,
        description,
        price,
        thumbnail,
        stock,
        category
        });

        res.send({status: "success", payload: result})
    }
    }
    catch (error){
    console.error(error);
    res.status(500).send({ status: "error", error});
    }
});


router.delete('/:pid', async (req, res) => {

    const { pid } = req.params; 

    try {
        const products = await productManager.delete(pid);
        res.send({ status: "success", payload: products });
    }
    catch (error){
        res.status(500).send({ status: "error", error});
    }
});


export default router;
