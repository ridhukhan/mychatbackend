import jwt from "jsonwebtoken"
import { redisClint } from "../index.js";
import { User } from "../models/user.js";
import { isSessionActive } from "../config/genarateToken.js";

export const isAuth = async (req, res, next) => {
    try {
        const token = req.cookies.accessToken ||  req.headers["authorization"]?.split(" ")[1];;
        
        if (!token) {
            // 403 pathachhi jate frontend interceptor automatic refresh call kore
            return res.status(403).json({
                message: "No token, authorization denied",
                code: "AUTH_TOKEN_MISSING" 
            });
        }

        const decodedData = jwt.verify(token, process.env.JWT_SECRET);
        
        const sessionActive = await isSessionActive(decodedData.id, decodedData.sessionId);
        if (!sessionActive) {
            res.clearCookie("refreshToken", { sameSite: "none", secure: true });
            res.clearCookie("accessToken", { sameSite: "none", secure: true });
            res.clearCookie("csrfToken", { sameSite: "none", secure: true });
            return res.status(403).json({
                message: "Session Expired, logged in elsewhere",
                code: "SESSION_EXPIRED"
            });
        }

        const cacheuser = await redisClint.get(`user:${decodedData.id}`);
        if (cacheuser) {
            req.user = JSON.parse(cacheuser);
            req.sessionId = decodedData.sessionId;
            return next();
        }

        const user = await User.findById(decodedData.id).select("-password");
        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        await redisClint.setEx(`user:${user._id}`, 3600, JSON.stringify(user));
        req.user = user;
        req.sessionId = decodedData.sessionId;

        next();
    } catch (error) {
        // Token expired holeo 403 pathate hobe jate refresh hoy
        return res.status(401).json({
            message: "Token is not valid",
            code: "AUTH_TOKEN_INVALID"
        });
    }
};
export const authorizedAdmin = async(req,res,next)=>{
    const user =req.user;

    if(user.role !== "admin"){
        return res.status(401).json({
            message:"you are not allowed for this activity",
        })
    }

    next();
}