const { DataTypes } = require('sequelize');
const { db } = require('../db/index');

const Library = db.define('Library', {
    id: {
        type: DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true,
    },
    name: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    location: {
        type: DataTypes.STRING,
        allowNull: false,
    },
    landline: {
        // we set it to string to let people put '/()+' characters and spaces.
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
    },
    isDeleted: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        validator: {
            isBoolean: true,
        }
    },
    deletedAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null,
        validator: {
            isDate: true,
        }
    }
});

module.exports =  { Library };