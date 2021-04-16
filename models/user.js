const mongoose = require('mongoose');
const { createHmac } = require('crypto');
const { v1 } = require('uuid');

const userSchema = new mongoose.Schema({
    name: {
        type: String,
        trim: true,
        required: true,
        maxlength: 32
    },
    email: {
        type: String,
        trim: true,
        required: true,
        unique: true
    },
    hashed_password: {
        type: String,
        required: true
    },
    salt: String,
    role: {
        type: String,
        default: 'user'
    }
}, { timestamps: true });


// vitrual field
userSchema.virtual('password')
    .set(function (password) {
        this._password = password
        this.salt = v1()
        this.hashed_password = this.encryptPassword(password)
    })

    .get(function () {
        return this._password
    });

userSchema.methods = {
    authenticate: function (plainText) {
        return this.encryptPassword(plainText) === this.hashed_password;
    },

    encryptPassword: function (password) {
        if (!password) return '';
        try {
            return createHmac('sha256', this.salt)
                .update(password)
                .digest('hex');
        } catch (err) {
            return '';
        }
    }
};

module.exports = mongoose.model("User", userSchema);