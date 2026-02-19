import { loginSchema, registerSchema } from "../config/zod.js";
import {redisClint} from "../index.js"
import TryCatch from "../middlewares/trycatch.js";
import sanitize from "mongo-sanitize"
import { User } from "../models/user.js";
import bcrypt from "bcryptjs";
import crypto from "crypto"
import sendMail from "../config/sendMail.js";
import { getOtpHtml, getVerifyEmailHtml } from "../config/html.js";

import { genarateToken,
     generateAccessToken, 
     revokeRefreshToken, 
     verifyRefreshToken } 
     from "../config/genarateToken.js";
import { genarateCSRFToken } from "../config/csrfMiddleware.js";

export const registerUser = TryCatch(async(req,res)=>{
    const sanitizeBody =sanitize(req.body)
    const validation = registerSchema.safeParse(sanitizeBody)
    if(!validation.success){
        const zodError = validation.error
        return res.status(400).json({ message:zodError });
    };
    const {fullname,email,password}=validation.data;
    const retLimitKey=`register-rate-limit:${req.ip}:${email}`;

    if (await redisClint.get(retLimitKey)){
        return res.status(429).json({ message:"too many requests, try again leter" })
    }
    const existingUser = await User.findOne({email});
    if(existingUser){
        return res.status(400).json({ message:"User Already Exists" })
    }
    const hashpassword = await bcrypt.hash(password,10);
    const verifyToken=crypto.randomBytes(32).toString("hex");
    const verifyKey =`verify:${verifyToken}`;
    const datatoStore=JSON.stringify({ fullname, email, password:hashpassword })
    await redisClint.set(verifyKey,datatoStore,{EX:300})
    const subject = "verify your email for account creation"
    const html =getVerifyEmailHtml({email,token:verifyToken});
    await sendMail({email,subject,html})
    await redisClint.set(retLimitKey,"true",{EX:60})
    res.json({ message:"if your email is valid ,a varification like has been sent. it will expired in 5 min" })
})

export const verifyUser = TryCatch(async (req, res) => {
  const { token } = req.params;
  if(!token){
    return res.status(400).json({ message:"verification token is required" })
  }
  const verifykey = `verify:${token}`;
  const userDataJson=await redisClint.get(verifykey)
  if(!userDataJson){
      return res.status(400).json({ message:"verification Link is expired" })
  }
  await redisClint.del(verifykey)
  const userData = JSON.parse(userDataJson)
  const existingUser = await User.findOne({email:userData.email});
  if(existingUser){
      return res.status(400).json({ message:"User Already Exists" })
  }
  const newUser = await User.create({
      fullname:userData.fullname,
      email:userData.email,
      password:userData.password,
  })
  res.status(201).json({message:"email verification successfully",
      user:{_id:newUser._id,fullname:newUser.fullname,email:newUser.email}
  })
});

export const loginUser = TryCatch(async(req,res)=>{
   const sanitizeBody =sanitize(req.body)
    const validation = loginSchema.safeParse(sanitizeBody)
    if(!validation.success){
        const zodError = validation.error
        return res.status(400).json({ message:zodError });
    };
    const {email,password}=validation.data;
    const retLimitKey=`rate-limit:${req.ip}:${email}`
    if (await redisClint.get(retLimitKey)){
        return res.status(429).json({ message:"too many requests, try again leter" })
    }
    const user =await User.findOne({email})
    if(!user){
        return res.status(400).json({ message:"invalid email" })
    }
    const comparepass=await bcrypt.compare(password,user.password);
    if(!comparepass){
        return res.status(400).json({ message:"wrong pass" })
    }
    const otp=Math.floor(100000+Math.random()*900000).toString();
    const otpkey=`otp:${email}`
    await redisClint.set(otpkey,JSON.stringify(otp),{ EX:300 });
    const subject ="your login otp";
    const html = getOtpHtml({email,otp});
    await sendMail({email,subject,html});
    await redisClint.set(retLimitKey,"true",{EX:60});
    res.json({ message:"otp is sended for 5 minite" })
})

export const verifyOtp = TryCatch(async(req,res)=>{
    const {email,otp}=req.body;
    if(!email || !otp){
        return res.status(400).json({ message:"please give me correct data" })
    }
    const otpkey =`otp:${email}`;
    const storedotpstring=await redisClint.get(otpkey)
    if(!storedotpstring){
        return res.status(400).json({ message:"expired otp" })
    }
    const storedotp = JSON.parse(storedotpstring)
    if(storedotp !== otp){
        return res.status(400).json({ message:"invalid otp" })
    }
    await redisClint.del(otpkey);
    let user = await User.findOne({email});
    const TokenData= await genarateToken(user._id,res);
    res.status(200).json({
        message:`WELCOM MR: ${user.fullname}`,
        accessToken: TokenData.accessToken,
        refreshToken: TokenData.refreshToken,
        user,
        sessionInfo: {
            sessionId: TokenData.sessionId,
            loginTime:new Date().toISOString(),
        }
    })
})

export const myprofile = TryCatch(async(req,res)=>{
    const user = req.user;
    const sessionId = req.sessionId;
    const sessionData=await redisClint.get(`session:${sessionId}`)
    let sessionInfo=null;
    if(sessionData){
        const parsedSession=JSON.parse(sessionData)
        sessionInfo={
            sessionId,
            loginTime:parsedSession.createdAt,
            lastActivity:parsedSession.lastActivity
        }
    }
    res.json({user,sessionInfo})
})

export const refreshToken = TryCatch(async (req,res)=>{
    // Cookie theke na paile header theke nao
    const token = req.cookies.refreshToken || req.headers["x-refresh-token"];

    if(!token){
        return res.status(401).json({ message:"refresh token missing" })
    }
    const decode=await verifyRefreshToken(token)
    if(!decode){
        return res.status(401).json({ message:"session expired, please login" })
    }

    const newAccessToken = generateAccessToken(decode.id, decode.sessionId);
    res.status(200).json({
        message:"token refreshed",
        accessToken: newAccessToken,
    })
})

export const logoutUser =TryCatch(async(req,res)=>{
    const userId =req.user._id;
    await revokeRefreshToken(userId)
    await redisClint.del(`user:${userId}`)
    res.json({ message:"logout successfully" })
})

export const refreshCSRF=TryCatch(async(req,res)=>{
    const userId=req.user._id
    const newCSRFToken=await genarateCSRFToken(userId,res)
    res.json({
        message:"csrf token refresh successfully",
        csrfToken:newCSRFToken,
    })
});

export const adminController =TryCatch(async (req,res)=>{
    res.json({ message:"Hello Admin" });
});

export const frogotPassword = async(req,res)=>{
   try {
     const {email}=req.body;
    if(!email) return res.status(400).json({message:"emil is requaired"})
    const user = await User.findOne({email})
    if(!user) return res.status(400).json({message:"email not match"})
    const resetToken = crypto.randomBytes(32).toString("hex")
    const key=`reset:${resetToken}`
    await redisClint.set(key,user._id.toString(),{EX:600})
    const resetLink=`https://spaytimes.xyz/reset-password/${resetToken}`;
    const html=`<p>click here to to reset password: <a>${resetLink}</a> expire in 10 min</p>`;
    await sendMail({email,subject:"reset ur password",html})
    res.status(200).json({message:"send a reset link in ur email"})
   } catch (error) {
    console.log(error.message)
    res.status(500).json({message:"forgot server error"})
   }
}

export const resetPassword = async(req,res)=>{
    try {
       const {token}=req.params;
       const {password}=req.body;
       if(!password) return res.status(400).json({message:"password reqired"})
       const key = `reset:${token}`;
       const userId= await redisClint.get(key);
       if(!userId) return res.status(400).json({message:"resetLink Expired"})
       const hash =await bcrypt.hash(password,10);
       await User.findByIdAndUpdate(userId,{password: hash})
       await redisClint.del(key)
       res.status(200).json({message:"password reset successfully"})
    } catch (error) {
        console.log(error.message)
        res.status(500).json({message:"password reset controller problem"})
    }
}

export const getAllUsers = TryCatch(async(req,res)=>{
    const users = await User.find({
      _id:{ $ne:req.user._id }
    }).select("fullname _id")
    res.json(users)
})

export const getUserById = async (req, res) => {
  try {
    const { id } = req.params;
    if (!id.match(/^[0-9a-fA-F]{24}$/)) {
      return res.status(400).json({ error: "Invalid user ID" });
    }
    const user = await User.findById(id).select("-password -__v");
    if (!user) {
      return res.status(404).json({ error: "User not found" });
    }
    res.status(200).json(user);
  } catch (error) {
    console.log("Error in getUserById:", error.message);
    res.status(500).json({ error: "Internal server error" });
  }
};