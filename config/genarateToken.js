import jwt from "jsonwebtoken";
import { redisClint } from "../index.js";
import { genarateCSRFToken, revokeCSRFTOKEN } from "./csrfMiddleware.js";
import crypto from "crypto";


export const genarateToken = async (id, res) => {
    const sessionId = crypto.randomBytes(16).toString("hex");

    const accessToken = jwt.sign({ id, sessionId }, process.env.JWT_SECRET, {
        expiresIn: "15m",
    });
    const refreshToken = jwt.sign({ id, sessionId }, process.env.REFRESH_SECRET, {
        expiresIn: "7d",
    });

    const refreshTokenkey = `refresh_token:${id}`;
    const activeSessionKey = `active_session:${id}`;
    const sessionDataKey = `session:${sessionId}`;

    const existingSession = await redisClint.get(activeSessionKey);
    if (existingSession) {
        await redisClint.del(`session:${existingSession}`);
        await redisClint.del(refreshToken); 
    }

    const sessionData = {
        userId: id,
        sessionId,
        createdAt: new Date().toISOString(),
        lastActivity: new Date().toISOString()
    };

    await redisClint.setEx(refreshTokenkey, 7 * 24 * 60 * 60, refreshToken);
    await redisClint.setEx(
        sessionDataKey, 7 * 24 * 60 * 60,
        JSON.stringify(sessionData)
    );
    await redisClint.setEx(activeSessionKey, 7 * 24 * 60 * 60, sessionId);

    // Cookie r dorkar nei, token response e pathabo
    const csrfToken = await genarateCSRFToken(id, res);
    return { accessToken, refreshToken, csrfToken, sessionId };
};

export const verifyRefreshToken = async (refreshToken) => {
    try {
        const decode = jwt.verify(refreshToken, process.env.REFRESH_SECRET);
        const storedToken = await redisClint.get(`refresh_token:${decode.id}`);
        
        if (storedToken !== refreshToken) {
            return null;
        }

        const activeSessionId = await redisClint.get(`active_session:${decode.id}`);
        if (activeSessionId !== decode.sessionId) {
            return null;
        }

        const sessionData = await redisClint.get(`session:${decode.sessionId}`);
        if (!sessionData) {
            return null;
        }

        const parsedSessionData = JSON.parse(sessionData);
        parsedSessionData.lastActivity = new Date().toISOString();

        await redisClint.setEx(`session:${decode.sessionId}`, 7 * 24 * 60 * 60, JSON.stringify(parsedSessionData));

        return decode;
    } catch (error) {
        return null;
    }
};

// accessToken return korbe
export const generateAccessToken = (id, sessionId) => {
    const accessToken = jwt.sign({ id, sessionId }, process.env.JWT_SECRET, {
        expiresIn: "15m",
    });
    return accessToken;
};

export const revokeRefreshToken = async (userId) => {
    const activeSessionId = await redisClint.get(`active_session:${userId}`);
    await redisClint.del(`refresh_token:${userId}`);
    await redisClint.del(`active_session:${userId}`);
    
    if (activeSessionId) {
        await redisClint.del(`session:${activeSessionId}`);
    }
    await revokeCSRFTOKEN(userId);
};

export const isSessionActive = async (userId, sessionId) => {
    const activeSessionId = await redisClint.get(`active_session:${userId}`);
    return activeSessionId === sessionId;
};