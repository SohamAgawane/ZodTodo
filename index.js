require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const { z } = require("zod");

const { UserModel, TodoModel } = require("./db");
const { authMiddlware, JWT_SECRET } = require("./auth"); 

const MONGO_URI = process.env.MONGO_URI;

mongoose
  .connect(MONGO_URI)
  .then(() => console.log("Connected to MongoDB"))
  .catch((error) => console.error("MongoDB Connection Error:", error));

const app = express();
app.use(express.json());

app.post("/signup", async (req, res) => {
  try {
    const signupSchema = z.object({
      email: z.string().email().min(3).max(100),
      password: z
        .string()
        .min(8)
        .max(100)
        .refine((password) => /[A-Z]/.test(password), {
          message: "Required at least one uppercase character",
        })
        .refine((password) => /[a-z]/.test(password), {
          message: "Required at least one lowercase character",
        })
        .refine((password) => /[0-9]/.test(password), {
          message: "Required at least one number",
        })
        .refine((password) => /[!@#$%^&*]/.test(password), {
          message: "Required at least one special character",
        }),
      name: z.string().min(3).max(50),
    });

    const parsedDataWithSuccess = signupSchema.safeParse(req.body);

    if (!parsedDataWithSuccess.success) {
      return res.status(400).json({
        message: "Incorrect format",
        error: parsedDataWithSuccess.error,
      });
    }

    const { email, password, name } = req.body;

    const hashedPassword = await bcrypt.hash(password, 10);

    await UserModel.create({
      email,
      password: hashedPassword,
      name,
    });

    res.status(201).json({
      message: "User registered successfully",
    });
  } catch (error) {
    res.status(500).json({
      message: "Error while signing up",
    });
  }
});

app.post("/signin", async (req, res) => {
  try {
    const { email, password } = req.body;

    const response = await UserModel.findOne({ email });

    if (!response) {
      return res.status(403).json({
        message: "User does not exist",
      });
    }

    const passwordMatch = await bcrypt.compare(password, response.password);

    if (passwordMatch) {
      const token = jwt.sign(
        { id: response._id.toString() },
        JWT_SECRET
      );
      res.json({ token });
    } else {
      return res.status(403).json({
        message: "Incorrect credentials",
      });
    }
  } catch (error) {
    res.status(500).json({
      message: "Error while logging in",
    });
  }
});

app.post("/todo", authMiddlware, async (req, res) => {
  try {
    const { title } = req.body;

    const todo = await TodoModel.create({
      title,
      userId: req.userId,
    });

    res.status(201).json({ todo });
  } catch (error) {
    res.status(500).json({
      message: "Error while creating todo",
    });
  }
});

app.get("/todos", authMiddlware, async (req, res) => {
  try {
    const userId = req.userId;
    const todos = await TodoModel.find({ userId });

    res.json({ todos });
  } catch (error) {
    res.status(500).json({
      message: "Error while fetching todos",
    });
  }
});

app.listen(3000, () => {
  console.log("Server Started...");
});