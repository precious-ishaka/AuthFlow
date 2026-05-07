import express from 'express';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import dotenv from 'dotenv';
import userRouter from './routes/userRoute.js';
import { users } from './model/staticDB.js';

dotenv.config();

const PORT = process.env.PORT;

const app = express();

// Middlewares
app.use(cookieParser());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(
    cors({
        origin: process.env.FRONTEND_URL,
        credentials: true
    })
);

// Routes
app.use('/', userRouter);
app.get("/angular",(_req, res)=>{
    res.status(200).json({message:"success",users})
})


app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});

 