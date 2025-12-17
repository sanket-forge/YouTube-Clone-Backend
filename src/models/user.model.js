import mongoose, {Schema} from "mongoose";
import { JsonWebTokenError } from "jsonwebtoken";
import bcrypt from "bcrypt";

const userSchema = new Schema({

    userName: {

        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true,
        index: true
    },

    email: {

        type: String,
        required: true,
        unique: true,
        lowercase: true,
        trim: true
    },

    fullName: {

        type: String,
        required: true,
        trim: true,
        index: true
    },

    avatar: {

        type: String,
        required: true
    },

    coverImage: {

        type: String
    },

    watchHistory: [{

        type: Schema.Types.ObjectId,
        ref: 'Video'
    }],

    password: {

        type: String,
        required: [true, 'Password is required.']
    },

    refreshToken: {

        type: String
    } 
}, {timestamps: true})

// Password encryption:

userSchema.pre('save', async function(next) {
    
    if(!this.isModified('password')) return next() // Negative checking: if password is not modified then just return after this line.

    this.password = bcrypt.hash(this.password, 10)
    next()
})

// Checks that the password is correct or not by compairing it to the encrypted password(returns true or false)

userSchema.methods.isPasswordCorrect = async function(password) {
    
    return await bcrypt.compare(password, this.password)
}

export const User = mongoose.model('User', userSchema)