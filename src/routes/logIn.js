const express = require('express')
const jwt = require('jsonwebtoken')
const bcrypt = require('bcrypt')
const logInRouter = express.Router()

const {User} = require('../models')

const { secret } = require('../middlewares')

// error handling
const { Error } = require('../utils')

logInRouter.post('/', async (req, res) => {
    const { username, password } = req.body
    if(!username || !password) {
        const errorObj = new Error('Please provide username and password', 400, null)
        res.status(400).json(errorObj)
        return
    }
    console.log({typeofPassword: typeof password, typeofUsername: typeof username});
    if(typeof username !== 'string' || typeof password !== 'string') {
        const errorObj = new Error('Please provide username and password as a string', 400, null)
        res.status(400).json(errorObj)
        return
    }

    const findUser = await User.findOne(
        {
            where: {
                username: username
            }
        }
    )
    if(!findUser){
        // message, code, status, data
        const errorObj = new Error('User not found', 404, 'ERROR', null)
        res.status(404).json(errorObj)
        return;
    }
    const doesPasswordMatch = await bcrypt.compare(password, findUser.password)
    if(!doesPasswordMatch){
        // message, code, status, data
        const errorObj = new Error('Password is not correct', 400, 'ERROR', null)
        res.status(400).json(errorObj)
        return;
    }
    const token = jwt.sign({username, password}, secret)
    res.json({ token }).status(201).end()
})

module.exports = { logInRouter }