const { libraryRouter } = require('./library')

const { bookRouter }  = require('./book')

const { userRouter } = require('./user')

const { logInRouter } = require('./logIn')

module.exports = { libraryRouter, bookRouter, userRouter, logInRouter }