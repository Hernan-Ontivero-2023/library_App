const express = require('express')

const { User } =  require('../models')

const userRouter = express.Router()

// middeware
const passport = require('passport')
const auth = passport.authenticate('jwt', { session: false })

// error handling
const { Error } = require('../utils')
// GET
// all
userRouter.get('/', async(req, res) => {
    // we find all users(this contains sensitive information(passwd))
    const allUsers = await User.findAll({attributes: {exclude: ['password']}})
    if(allUsers.length === 0){
        // message, code, status, data
        const errorObj = new Error('There are not users here yet, try posting some', 418, 'ERROR', null)
        res.status(418).json(errorObj).end()
        return
    }
    // we filter them to return only the username, name and email
    const filteredUsers = allUsers.map(user => {
        delete user.password
        return user
    })
    res.status(200).json(filteredUsers).end()
})
// by id(pk)
userRouter.get('/:id', async (req, res) => {
    const { id } = req.params
    await User.findByPk(id, {attributes: {exclude: ['password']}})
    .then(user => {
        if(user === null){
            const errorObj = new Error('User not found', 404, 'ERROR', null)
            res.status(404).json(errorObj).end()
            return
        } else{
            res.status(200).json(user).end()
            return
        }
    })

})

// POST
userRouter.post('/', auth, async (req, res) => {
    // userName, name, email, password
    const { username, name, email, password } = req.body
    
    try{
        // we verify if the obligatory params are being passed.
        if(!username || !email || !password){
            const errorObj = new Error('there is been an error receiving the params. the params expected are some of these: username, email, password.', 400, 'ERROR', null)
            res.status(400).json(errorObj).end()
            return
        }
        if(typeof username !== 'string' || typeof email !== 'string' || typeof password !== 'string' || typeof name !== 'string'){
            const errorObj = new Error('the params must be strings', 400, 'ERROR', null)
            res.status(400).json(errorObj).end()
            return
        }
        const newUser = User.build({ username, name, email, password })

        try {
            await newUser.validate()
        } catch (error) {
            const errorObj = new Error('there its been an error while validating the user params, check your json.', 400, 'ERROR', error)
            res.status(500).json(errorObj).end()
            return;
        }

        try {
            await newUser.save()
            const newUserFromDb = await User.findByPk(newUser.id, {attributes: {exclude: ['password']}})

            res
            .status(201)
            .json(newUserFromDb)
            .end()
        } catch(error){
            console.log(error);

            if (error.name === 'SequelizeUniqueConstraintError') {
                const errorObj = new Error('the email and the username must be unique', 400, 'ERROR', error) 
                res.status(400).json(errorObj).end()
                return;
            } else{
                const errorObj = new Error('Internal server error while saving user', 500, 'ERROR', error)
                res.status(500).json(errorObj).end()
                return;
            }
        }
    } catch(err){
        console.log(err);
        res
        .status(500)
        .json(err)
        .end()
    }
})

// PUT
userRouter.put('/:id', auth, async (req, res) => {
    try{
        const { id } = req.params;
        const { username, name, email, password } = req.body;
        let bodyParams = { username, name, email, password };

        let ifNoParams = Object.values(bodyParams).every(param => param === undefined)
        if(ifNoParams){
            const errorObj = new Error('there is been an error receiving the params. the params expected are some of these: id, username, name, email, password.', 400, 'ERROR', null)
            res.status(400).json(errorObj).end()
            return
        }

        ifParamsAreNotString = Object.values(bodyParams).some(param => typeof param !== 'string')
        if(ifParamsAreNotString){
            const errorObj = new Error('the params must be strings', 400, 'ERROR', null)
            res.status(400).json(errorObj).end()
            return
        }
        const thisUser =  await User.findByPk(id)
        if(thisUser === null){
            const errorObj = new Error('User not found', 404, 'ERROR', null)
            res.status(404).json(errorObj).end()
            return
        }
        await thisUser.update(bodyParams, {
            where:{
            id: id
            }
        })
        .then(rowsUpdated => {
            if(rowsUpdated <= 0){
                const errorObj = new Error('error updating, there have no rows been updated', 500, 'ERROR', null)
                res
                .status(500)
                .json(errorObj)
                .end()
                return
            } else{
                res
                .status(201)
                .end()
                return;
            }
        })
    } catch(error){
        console.log(error);
        const errorObj = new Error('internal server error', 500, 'ERROR', error)
        res
        .status(500)
        .json(errorObj)
        .end()
    }
})

// DELETE
userRouter.delete('/:id', auth, async (req, res) => {
    const { id } = req.params
    await User.findByPk(id)
    .then(user => {
        if(user === null){
            const errorObj = new Error('User not found', 404, 'ERROR', null)
            res.status(404).json({error: 'User not found'}).end()
            return;
        }
    })

    try{
        await User.update({deletedAt: new Date(), isDeleted: true}, {where: {id : id}})
        .then(rowsDeleted => {
            if(rowsDeleted <= 0){
                // message, code, status, data
                const errorObj = new Error('internal server error', 500, 'ERROR', null)
                res.status(500).json(errorObj).end()
                return;
            } else{
                res.status(201).json({message: 'User deleted'}).end()
            }
        })
    } catch(error){
        console.log(error);

        // message, code, status, data
        const errorObj = new Error('internal server error', 500, 'ERROR', error)
        res.status(500).json(errorObj).end();
    }

})
module.exports = { userRouter }