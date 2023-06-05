const express = require('express');
const libraryRouter = express.Router();

// siquelize models
const { Library } = require('../models') 
const { Book } = require('../models');

const passport = require('passport');
const { json } = require('sequelize');
const auth = passport.authenticate('jwt', { session: false })

// error handling
const { Error } = require('../utils')

// GET
// all
libraryRouter.get('/', async (req, res) => {
    try{
        await Library.findAll({
            include: Book
        })
        .then(libraries => {
            if(libraries.length === 0){
                // message, code, status, data
                const errorObj = new Error('There are not librarires here yet, try posting some', 418, 'EMPTY', null)
                res.status(418).json(errorObj).end();
                return
            } else{
                res.status(200).json(libraries).end();
                return
            }
        })
    } catch(error){
        console.log(error);
        // message, code, status, data
        const errorObj = new Error('Something went wrong', 500, 'ERROR', error)
        res.status(500).json(errorObj).end();
        return
    }
});

// by id
libraryRouter.get('/:id', async (req, res) => {
    let id = req.params.id;

    try{
        await Library.findByPk(id, {
            include: Book
        })
        .then(library => {
            if(library === null){
                // message, code, status, data
                const erroObj = new Error('library not found', 404, 'ERROR', null)
                res.status(404).json(erroObj).end();
                return
            } else{
                res.status(200).json(library).end()
            }
        })

    } catch(error){
        // message, code, status, data
        const erroObj = new Error('Something went wrong', 500, 'ERROR', error)
        res.status(500).json(erroObj).end();
        return
    }
})

// library books by id
libraryRouter.get('/:id/books', async (req, res) => {
    const { id } = req.params;

    try{
        await Library.findByPk(id, {
            include: Book
        })
        .then(library => {
            if(!library){
                // message, code, status, data
                const errorObj = new Error('library not found', 404, 'ERROR', null)
                res.status(404).json(errorObj).end();
                return
            } else {
                res.status(200).json(library.Books).end()
            }
        })
    } catch (error){
        // message, code, status, data
        const errorObj = new Error('Something went wrong', 500, 'ERROR', error)
        res.status(500).json(errorObj).end();
        return
    }
})
// POST
// creando new library
libraryRouter.post('/', auth, async (req, res) => {
    const { name, location, landline } = req.body;
    const params = { name, location, landline };
    // comprobamos si se envían todos los parámetros
    if(!name || !location || !landline){
        // message, code, status, data
        const errorObj = new Error('missing body parameters', 400, 'ERROR', null)
        res.status(400).json(errorObj).end();
        return
    }
    // verificamos lod datos body
    if(typeof name !== 'string' || typeof location !== 'string' || typeof landline !== 'string'){
        // message, code, status, data
        const errorObj = new Error('body parameters must be strings', 400, 'ERROR', null)
        res.status(400).json(errorObj).end();
        return
    }

    try{
        // creamos una instancia ,the object and then save it in a var
        const newLibrary = Library.build(params);


        // Validando
        await newLibrary.validate();

        try{
            
            await newLibrary.save();
            res.status(201).json(newLibrary).end()
        } catch(error){
            if(error.name === 'SequelizeValidationError' || error.name === 'SequelizeUniqueConstraintError'){
                // message, code, status, data
                const errorObj = new Error('validation error',400 , 'ERROR', error)
                res.status(400).json(errorObj).end();
                return
            } else{
                // message, code, status, data
                const errorObj = new Error('internal server error', 500, 'ERROR', error)
                res.status(500).json(errorObj).end();
            }
        }
    } catch (error){
        // message, code, status, data
        const errorObj = new Error('internal server error', 500, 'ERROR', error)
        res.status(500).json(errorObj).end();
    }
})

// PUT
// by id(pk) // modificamos la (library)
libraryRouter.put('/:id', auth, async (req, res) => {
    let { id } = req.params;
    const { name, location, landline } = req.body;
    const params = { name, location, landline };
    const paramsValues = Object.values(params)
    const paramsUndefined = paramsValues.every(param => param === undefined)

    if(paramsUndefined){
        // message, code, status, data
        const errorObj = new Error('missing body parameters', 400, 'ERROR', null)
        res.status(400).json(errorObj).end();
        return
    }

    if(name){
        if(typeof name !== 'string'){
            // message, code, status, data
            const errorObj = new Error('body parameters must be strings', 400, 'ERROR', null)
            res.status(400).json(errorObj).end();
            return
        }
    }

    if(location){
        if(typeof location !== 'string'){
            const errorObj = new Error('body parameters must be strings', 400, 'ERROR', null)
            res.status(400).json(errorObj).end();
            return
        }
    }

    if(landline){
        if(typeof landline !== 'string'){
            const errorObj = new Error('body parameters must be strings', 400, 'ERROR', null)
            res.status(400).json(errorObj).end();
            return
        }
    }

    if(params.length <= 0){
        // message, code, status, data
        const errorObj = new Error('missing body parameters', 400, 'ERROR', null)
        res.status(400).json(errorObj).end();
        return;
    }
    

    await Library.findByPk(id)
    .then(async findLibrary => {
        if(!findLibrary){
            // message, code, status, data
            const errorObj = new Error('library not found', 404, 'ERROR', null)       
            res.status(404).json(errorObj).end();
            return;
        }
    
        try {
            await findLibrary.update({ name, location, landline })

            res.status(201).end()
        } catch(error){
            // message, code, status, data
            const errorObj = new Error('internal server error', 500, 'ERROR', error)
            res.status(500).json(errorObj).end();
            return;
        }
    })
})

// DELETE
libraryRouter.delete('/:id', auth, async (req, res) => {
    let { id } = req.params;

    // verificamos si la library exist:
    const libraryExist = await Library.findByPk(id)
    .then(library => {
        if(!library){
            return false
        } else{
            return true
        }
    })
    if(!libraryExist){
        // message, code, status, data
        const errorObj = new Error('library not found', 404, 'ERROR', null)
        res.status(404).json(errorObj).end();
        return;
    }

    // delete 
    try{
        await Library.update({ 
            isDeleted: true, deletedAt: new Date() 
        }, 
        {
            where: {
                id: id
            }
        })
        .then(updatedRows => {
            if(updatedRows === 0 || updatedRows === null){
                // message, code, status, data
                const errorObj = new Error('internal server error', 500, 'ERROR', null)
                res.status(500).json(errorObj).end();
                return;
            } else {
                res.status(201).end()
            }
        })
    } catch (err){
        // message, code, status, data
        const errorObj = new Error('internal server error', 500, 'ERROR', err)
        res.status(500).json(errorObj).end()
    }
})

module.exports = { libraryRouter };