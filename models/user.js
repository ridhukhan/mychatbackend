import mongoose, { Schema } from "mongoose";

const schema = new Schema({




    fullname:{
        type:String,
        required:true
    },
    email:{
        type:String,
        required:true,
        unique:true
    },
    password:{
        type:String,
        required:true
    },
    role:{
        type:String,
        default:"user"
    },
},{timestamps:true})

export const User =mongoose.model("User",schema)