import { hash, compare } from 'bcryptjs';
import { users } from '../model/staticDB.js';
import { generateAccessToken, generateRefreshToken, setRefreshCookie} from '../middleware/token.js';

/* ────────────────────────────────────────────
   REGISTER
   POST /register
   Body: { username, email, password }
   Returns: { message, accessToken, user }
──────────────────────────────────────────── */
export const register = async (req, res) => {
    const { email, password, username } = req.body;

    try {
        if (!email || !password || !username) {
            return res.status(400).json({ message: 'All fields are required' });
        }

        const userExists = users.find(u => u.email === email);
        if (userExists) {
            return res.status(400).json({ message: 'User already exists' });
        }

        const hashedPassword = await hash(password, 10);

        // Generate tokens upfront so they exist when building newUser
        const accessToken  = generateAccessToken(users.length + 1);
        const refreshToken = generateRefreshToken(users.length + 1);

        const newUser = {
            id: users.length + 1,
            email,
            username,
            password: hashedPassword,
            refreshToken
        };

        users.push(newUser);

        // Send refresh token as HttpOnly cookie
        setRefreshCookie(res, refreshToken);

        console.log('User registered:', { id: newUser.id, email: newUser.email, username: newUser.username });

        return res.status(201).json({
            message: 'User created successfully',
            accessToken,
            user: {
                id:       newUser.id,
                email:    newUser.email,
                username: newUser.username
            }
        });

    } catch (error) {
        console.error('Register error:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
};

/* ────────────────────────────────────────────
   LOGIN
   POST /login
   Body: { email, password }
   Returns: { message, accessToken, user }
──────────────────────────────────────────── */
export const login = async (req, res) => {
    const { email, password } = req.body;

    try {
        if (!email || !password) {
            return res.status(400).json({ message: 'Email and password are required' });
        }

        const user = users.find(u => u.email === email);
        if (!user) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const isValidPassword = await compare(password, user.password);
        if (!isValidPassword) {
            return res.status(401).json({ message: 'Invalid credentials' });
        }

        const accessToken  = generateAccessToken(user.id);
        const refreshToken = generateRefreshToken(user.id);

        // Rotate stored refresh token
        user.refreshToken = refreshToken;

        setRefreshCookie(res, refreshToken);

        return res.status(200).json({
            message:     'Login successful',
            accessToken,
            user: {
                id:       user.id,
                email:    user.email,
                username: user.username
            }
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ message: 'Internal server error', error: error.message });
    }
};

/* ────────────────────────────────────────────
   LOGOUT
   POST /logout
   Clears the refresh token cookie + invalidates stored token
──────────────────────────────────────────── */
export const logout = (req, res) => {
    const token = req.cookies?.refreshToken;

    if (token) {
        const user = users.find(u => u.refreshToken === token);
        if (user) user.refreshToken = null;
    }

    res.clearCookie('refreshToken', { path: '/' });

    return res.status(200).json({ message: 'Logged out successfully' });
};

/* ────────────────────────────────────────────
   PROTECTED ROUTE
   GET /protect
   Requires: isAuth middleware (sets req.userId)
   Returns: { message, userId, email, username }
──────────────────────────────────────────── */
export const protectedRoute = async (req, res) => {
    try {
        const user = users.find(u => u.id === req.userId);

        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        return res.status(200).json({
            message:  'Protected route accessed successfully',
            userId:   user.id,
            email:    user.email,
            username: user.username
        });

    } catch (error) {
        console.error('Protected route error:', error);
        res.status(500).json({ message: 'Server error', error: error.message });
    }
};

/* ────────────────────────────────────────────
   REFRESH TOKEN
   POST /refresh-token
   Reads HttpOnly cookie, rotates both tokens
   Returns: { accessToken, message }
──────────────────────────────────────────── */
export const refreshToken = async (req, res) => {
    const token = req.cookies?.refreshToken;

    if (!token) {
        return res.status(401).json({ message: 'No refresh token provided' });
    }

    try {
        const payload = jwt.verify(token, process.env.REFRESH_TOKEN_SECRET);
        const user    = users.find(u => u.id === payload.userId);

        if (!user) {
            return res.status(401).json({ message: 'User not found' });
        }

        if (user.refreshToken !== token) {
            // Possible token reuse attack — invalidate stored token
            user.refreshToken = null;
            return res.status(401).json({ message: 'Refresh token reuse detected' });
        }

        // Rotate both tokens
        const newAccessToken  = generateAccessToken(user.id);
        const newRefreshToken = generateRefreshToken(user.id);

        user.refreshToken = newRefreshToken;
        setRefreshCookie(res, newRefreshToken);

        return res.status(200).json({
            accessToken: newAccessToken,
            message:     'Token refreshed successfully'
        });

    } catch (error) {
        console.error('Refresh token error:', error);

        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ message: 'Refresh token expired — please log in again' });
        }

        return res.status(401).json({ message: 'Invalid refresh token', error: error.message });
    }
};