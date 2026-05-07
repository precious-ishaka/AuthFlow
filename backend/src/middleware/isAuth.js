import jwt from 'jsonwebtoken';

/**
 * isAuth.js
 * Verifies the Bearer access token on every protected request.
 * Attaches req.userId so controllers can identify the caller.
 */

export const isAuth = (req, res, next) => {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
        return res.status(401).json({ message: 'Unauthorized — no token provided' });
    }

    const token = authHeader.split(' ')[1];

    try {
        const payload = jwt.verify(token, process.env.ACCESS_TOKEN_SECRET);
        req.userId = payload.userId;
        next();
    } catch (err) {
        if (err.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Access token expired' });
        }
        return res.status(401).json({ message: 'Invalid access token' });
    }
};