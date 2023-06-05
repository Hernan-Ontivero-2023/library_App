const { DataTypes } = require('sequelize');
const { db } = require('../db/index');
const { Library } = require('./library');

const Book = db.define('Book', {
    id: {
        type: DataTypes.INTEGER,
        allowNull: false,
        primaryKey: true,
        autoIncrement: true,
    },
    isbn: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
            len: [0, 18]
        }
    },
    title: {
        type: DataTypes.STRING,
        allowNull: false,
        validate: {
            notEmpty: true, // notEmplty only works for strings
            len: [1, 100]
        }
    },
    author: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    year: {
        type: DataTypes.INTEGER,
        allowNull: false,
        validate: {
            isInt: true,
            min: 0,
            max: new Date().getFullYear()
        }
    }, 
    isDeleted: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        validate: {
            isBoolean: true,
        }
    },
    deletedAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null,
        validate: {
            isDate: true,
        }
    }
})

Book.belongsTo(Library, { foreignKey: 'LibraryId' })

module.exports = { Book };