//const { userRouter, authRouter } = require("./src/routes");


const express = require('express');

const app = express();

const listeningPort = 8080;

// sequelize
const { db } = require('./src/db');


// routers:
const { libraryRouter } = require('./src/routes')
const { bookRouter } = require('./src/routes')
const { userRouter } = require('./src/routes')
// auth
const { logInRouter } = require('./src/routes')

//middwares
const { consoleLoggingMIDWW } = require('./src/middlewares');

// models
const { Library } = require('./src/models/');
const { Book } = require('./src/models')
const { User } =  require('./src/models')

//middw
// el order es importante, todos los middw deben estar antes que cualquier otro middw que intente enviar una respuesta al cliente.
app.use(consoleLoggingMIDWW)
app.use(express.json());

// CRUD routes
app.use('/library', libraryRouter);
app.use('/book', bookRouter);
app.use('/user', userRouter);

// get token api routes
app.use('/login', logInRouter);

// i'm a teapot
app.use('/coffe-break',(req, res) => {
    res.status(418).json({error: 'The server refuses the attempt to brew coffee with a teapot.'}).end();
})

//initializateDB
async function initializateDB(){
    try {
        // initializate the db from 0
        await db.sync();
        await db.authenticate()
        
        Library.hasMany(Book);
        Book.belongsTo(Library)
        // snycing the Library & Book tables
        await Library.sync();
        console.log('Library table synchronized');
        
        await Book.sync();
        console.log('Book table synchronized');
        
        await User.sync();
        // we define the admin user here
        const existAdmin = await User.findOne({where: {
            username: 'admin'
        }})
        if(!existAdmin){
            let adminUser = await User.build({username: 'admin', name: null, email: 'myexampleofmygmail@gmail.com', password: 'admin'})
            await adminUser.save()
        }
        console.log('User table synchronized');
        
    } catch(err) {
        console.log(err);
    }
}

//listening
app.listen(listeningPort, async () => {
    await initializateDB()
    console.log(`Server started on port ${listeningPort}`);
})

