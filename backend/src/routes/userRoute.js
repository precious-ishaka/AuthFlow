import express from 'express';
import { register, login, logout, protectedRoute, refreshToken } from '../controller/userController.js';
import { isAuth } from '../middleware/isAuth.js';

const router = express.Router();

// User routes
router.post('/register', register);
router.post('/login', login);
router.post('/logout', logout);
router.post('/protect', isAuth, protectedRoute);
router.post('/refresh-token', refreshToken);

export default router;