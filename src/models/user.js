const { DataTypes } = require('sequelize');
const { db } = require('../db')

const bcrypt = require('bcrypt');

const User = db.define('User', {
    id: {
        type:DataTypes.INTEGER,
        primaryKey: true,
        autoIncrement: true
    },
    username: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate: {
            len: [1, 20],
        }
    },
    name: {
        type: DataTypes.STRING,
        allowNull: true,
    },
    email: {
        type: DataTypes.STRING,
        allowNull: false,
        unique: true,
        validate:{
            isEmail: true,
        }
    },
    password: {
        type: DataTypes.STRING,
        allowNull: false,
        validator: {
            len: [5, 20]
        }
    },
    role: {
        type: DataTypes.STRING,
        allowNull: true,
        defaultValue: 'user',
        validate: {
            isIn: ['user', 'admin']
        }
    },
    isDeleted: {
        type: DataTypes.BOOLEAN,
        defaultValue: false,
        allowNull: true,
        validate:{
            isIn: [[true, false]],
        }
    },
    deletedAt: {
        type: DataTypes.DATE,
        allowNull: true,
        defaultValue: null,
        validate:{
            isDate: true,
        }
    }
})


async function HashPassword(user){
    try {
        const hash = await bcrypt.hash(user.password, 10);
        user.password = hash;
        console.log(hash);
    } catch (error) {
        console.log(error);
    }
}
User.beforeCreate(async (user) => {
    if(user.username === 'admin' && user.password === 'admin'){
        user.role = 'admin';
    }
    await HashPassword(user);
});
User.beforeUpdate(async (user) => {
    await HashPassword(user);
});
module.exports = { User }