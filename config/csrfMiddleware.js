import crypto from "crypto"
import { redisClint } from "../index.js";

export const genarateCSRFToken = async(userId,res)=>{
    const csrfToken=crypto.randomBytes(32).toString("hex");
    const csrfKey =`csrf:${userId}`;

    await redisClint.setEx(csrfKey,3600,csrfToken)
    res.cookie("csrfToken",csrfToken,{
        httpOnly:false,
        secure:true,
        sameSite:"None",
        maxAge:60*60*1000
    })
    return csrfToken
}

export const verifyCSRFToken=async(req,res,next)=>{
    try {
        if(req.method==="GET"){
            return next()
        }

        const userId = req.user?._id;
        if(!userId){
            return res.status(401).json({
                message:"User not authenticated",
            })

        }
        const clientToken =
        req.headers["x-csrf-token"] || 
        req.headers["x-xsrf-token"] || 
        req.headers["csrf-token"];
        if(!clientToken){
        return res.status(403).json({
                message:"CSRF Token missing. please refresh the page",
            code:"CSRF_TOKEN_MISSING",
            
            })
        }
        const csrfKey=`csrf:${userId}`;

        const storedToken=await redisClint.get(csrfKey)
        if(!storedToken){
      return  res.status(403).json({
                message:"CSRF Token Expired. please try again",
            code:"CSRF_TOKEN_EXPIRED",
            
            })
        }

        if(storedToken !== clientToken){
           return res.status(403).json({
                message:"Invalid csrf  Token . please refresh the page",
            code:"CSRF_TOKEN_INVALID",
            
            })
        }

        next()

    } catch (error) {
   
    res.status(500).json({
                message:"CSRF VERIFICATION FAILD.",
            code:"CSRF_VERIFICATION_ERROR",
            
            })
    }
};

export const revokeCSRFTOKEN=async(userId)=>{
    const csrfKey=`csrf:${userId}`;
    await redisClint.del(csrfKey)
};

export const refreshCSRFToken=async(userId,res)=>{
    await revokeCSRFTOKEN(userId)

  return await genarateCSRFToken(userId,res);
}