import mongoose from "mongoose";
const connectDB = async()=>{
try {
    await mongoose.connect(process.env.MONGO_DB_URL)
    console.log("Db is connected")
} catch (error) {
    console.log(error.message,"db not connect")
}
}

export default connectDB;