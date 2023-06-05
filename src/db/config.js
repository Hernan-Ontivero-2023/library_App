const Sequelize = require('sequelize')

const db = new Sequelize({
    dialect: 'sqlite',
    storage: 'src/db/db.sqlite'
});

module.exports = { db };