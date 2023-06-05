const express = require('express')

const bookRouter = express.Router()

const { Book, Library } = require('../models')

const passport = require('passport')
const auth = passport.authenticate('jwt', { session: false })

// error handling
const { Error } = require('../utils')

// GET
bookRouter.get('/', async (req, res) => {
    try{
        await Book.findAll()
        .then(books => {
            if(books.length === 0){
                // message, code, status, data
                const errorObj = new Error('todavía no hay libros aquí, intente publicar algunos. Te espero', 418, 'ERROR', nulo)
                res.status(418).json(errorObj).end()
                return;
            } else {
                res.status(200).json(books).end()
            }
        })
    } catch (error){
        // message, code, status, data
        const errorObj = new Error('internal server error', 418, 'ERROR', error)
        res.status(418).json(errorObj).end()
    }
})
// by id
bookRouter.get('/:id', async (req, res) => {
    try{
        const { id } = req.params;
        await Book.findByPk(id)
        .then(book => {
            if(book === null){
                // message, code, status, data
                const errorObj = new Error('book not found', 404, 'ERROR', null)
                res.status(404).json(errorObj).end()
                return;
            } else{
                res.status(200).json(book).end()
            }
        })
    } catch(error){
        // message, code, status, data
        const errorObj = new Error('internal server error', 418, 'ERROR', error)
        res.status(418).json(errorObj).end()
    }
})

// POST
bookRouter.post('/', auth, async (req, res) => {
    let { isbn, title, author, year, LibraryId } = req.body;
    console.log(LibraryId);
    // si no envían un identificador de biblioteca, se establece en null
    if(LibraryId === undefined){
        LibraryId = null;
    } else{
        let libraryExist = await Library.findByPk(LibraryId)
        .then(library => {
            if(!library) {
                return false;
            } else{
                return true;
            }
        })
        if(!libraryExist){
            // message, code, status, data
            const errorObj = new Error(`la biblioteca con el id ${LibraryId} no existe, intente vincularla a una biblioteca existente o establecerla en null.`, 404, 'ERROR', null)
            res.status(404).json(errorObj).end()
        }
    }

    // verificamos si hemos recibido todos los parámetros (library id can be null or undefined, its not obligatory)
    if(!isbn || !title || !author || !year){
        // message, code, status, data
        const errorObj = new Error('there are missing params in your request. ', 400, 'ERROR', null)
        res.status(400).json(errorObj).end()
        return;
    }
    // we check the data types
    if(typeof isbn !== 'number' || typeof title !== 'string' || typeof author !== 'string' || typeof year !== 'number'){
        console.log({idbn: typeof isbn, title: typeof title, author: typeof author, year: typeof year});
        // message, code, status, data
        const errorObj = new Error(`the params recieved are not the correct data types. Params_expected: isbn: "number", title: "string", author: "string", year: "number", params_received: idbn: typeof isbn, title: typeof title, author: typeof author, year: typeof year`, 400, 'ERROR', null)
        res.status(400).json(errorObj).end()
        return
    }


    try{
        const newBook = await Book.build({ isbn, title, author, year, LibraryId})

        try{
            await newBook.validate()    
        } catch(error){
            // message, code, status, data
            const errorObj = new Error('error while validating the data', 400, 'ERROR', error)
            res.status(400).json(errorObj).end()
            return
        }
        // if the json contains libraryId null
        if(LibraryId === null){
            // we save it
            try{
                await newBook.save()
            } catch(error){
                const errorObj = new Error('error while saving the data', 400, 'ERROR', error)
                res.status(400).json(errorObj).end()
                return
            }

            const newBookFromDb = await Book.findByPk(newBook.id)
            res.status(201).json(newBookFromDb).end()
            return;
        } else {
            // we check if it exist
            let libraryExist = await Library.findByPk(LibraryId)
            .then(library => {
                if(!library) {
                    return false;
                } else{
                    return true;
                }
            })

            if(libraryExist){
                const library = await Library.findByPk(LibraryId);
                
                try{
                    await newBook.save()
                } catch(error){
                    if(error.name === 'SequelizeValidationError' || error.name === 'SequelizeUniqueConstraintError'){
                        // message, code, status, data
                        const errorObj = new Error('error while saving the data', 400, 'ERROR', error)
                        res.status(400).json(errorObj).end()
                        return
                    } else {
                        // message, code, status, data
                        const errorObj = new Error('error while saving the data', 400, 'ERROR', error)
                        res.status(400).json(errorObj).end()
                        return
                    }
                }
                await newBook.setLibrary(library)
                const newBookFromDb = await Book.findByPk(newBook.id, {
                    include: [Library],
                });
    
                res.status(201).json(newBookFromDb).end()
                return
            } else {
                // message, code, status, data
                const errorObj = new Error(`the library with the id ${LibraryId} doesnt exist`, 404, 'ERROR', null)
                res.status(404).json(errorObj).end()
                return;
            }
        }
    } catch (err){
        // message, code, status, data
        const errorObj = new Error('error while saving the data', 400, 'ERROR', err)
        res.status(400).json(errorObj).end()
        return
    }
})

// PUT
bookRouter.put('/:id', auth, async (req, res) => {
    try{
        const { id } = req.params;
        const { isbn, title, author, year } = req.body;
        const params = { isbn, title, author, year };

        const paramsValues = Object.values(params)
        const paramsAreUndefinded = paramsValues.every(param => param === undefined)
        console.log(paramsValues);
        
        if(paramsAreUndefinded){
            // message, code, status, data
            const errorObj = new Error('there are missing params in your request. ', 400, 'ERROR', null)
            res.status(400).json(errorObj).end()
            return
        }
    
        await Book.findByPk(id)
        .then(async book => {
            if(!book){
                // message, code, status, data
                const errorObj = new Error('book not found', 404, 'ERROR', null)
                res.status(404).json(errorObj).end()
                return;
            }
            try{
                await book.update(params)
                res.status(201).json(book).end()
            } catch (err){
                // message, code, status, data
                const errorObj = new Error('error while updating the book', 400, 'ERROR', err)
                res.status(400).json(errorObj).end()
                return;
            }
        })
    } catch (error){
        // message, code, status, data
        const errorObj = new Error('internal server error', 418, 'ERROR', error)
        res.status(500).json(errorObj).end()
    }
})

// DELETE
bookRouter.delete('/:id', auth, async (req, res) => {
    const { id } = req.params;
    
    // we look for the book to check if it exist
    await Book.findByPk(id)
    .then(async book => {
        if(!book){
            // message, code, status, data
            const errorObj = new Error('book not found', 404, 'ERROR', null)
            res.status(404).json(errorObj).end()
            return;
        }
        // then if it exist, we delete it.
        await book.update({deletedAt: new Date(), isDeleted: true})
        .then( numberOfDestroyedRows => {
            if(numberOfDestroyedRows <= 0 ){
                // message, code, status, data
                const errorObj = new Error('error while deleting the book', 400, 'ERROR', null)
                res.status(400).json(errorObj).end
                return;
            } else{
                res.status(201).end()
            }
        })
    })
})

module.exports = { bookRouter }