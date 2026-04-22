const dns = require('dns');
// Google DNS set karna taaki Atlas connection mein issue na aaye
dns.setServers(['8.8.8.8', '8.8.4.4']);
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();

/* ===========================
   ✅ CORS FIX (IMPORTANT)
=========================== */
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000",
  "https://expense-management-system-6-c616.onrender.com" // 👈 YOUR FRONTEND URL
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("❌ Not allowed by CORS"));
    }
  },
  credentials: true
}));

app.use(express.json());

/* ===========================
   MongoDB Connection
=========================== */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err));

/* ===========================
   User Schema
=========================== */
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ===========================
   Expense Schema
=========================== */
const expenseSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  title: { type: String, required: true },
  amount: { type: Number, required: true },
  category: {
    type: String,
    enum: ["Food", "Travel", "Bills", "Shopping", "Entertainment", "Health", "Others"],
    default: "Others"
  },
  date: { type: Date, default: Date.now }
}, { timestamps: true });

const Expense = mongoose.model("Expense", expenseSchema);

/* ===========================
   Auth Middleware
=========================== */
const authMiddleware = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      return res.status(401).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    return res.status(401).json({ message: "Invalid or expired token" });
  }
};

/* ===========================
   Routes
=========================== */

// 🔹 REGISTER
app.post("/api/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const user = new User({ name, email, password: hashedPassword });
    await user.save();

    res.status(201).json({
      message: "User registered successfully",
      userId: user._id
    });

  } catch (error) {
    console.error("❌ Register Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// 🔹 LOGIN
app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login successful",
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email
      }
    });

  } catch (error) {
    console.error("❌ Login Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// 🔹 ADD EXPENSE
app.post("/api/expense", authMiddleware, async (req, res) => {
  try {
    const { title, amount, category, date } = req.body;

    const expense = new Expense({
      userId: req.user.id,
      title,
      amount,
      category,
      date: date || Date.now()
    });

    await expense.save();

    res.status(201).json({ message: "Expense added", expense });

  } catch (error) {
    console.error("❌ Add Expense Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// 🔹 GET EXPENSES
app.get("/api/expenses", authMiddleware, async (req, res) => {
  try {
    const expenses = await Expense.find({ userId: req.user.id }).sort({ date: -1 });
    res.json(expenses);
  } catch (error) {
    console.error("❌ Fetch Expenses Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

// 🔹 TOTAL EXPENSE
app.get("/api/expenses/total", authMiddleware, async (req, res) => {
  try {
    const total = await Expense.aggregate([
      { $match: { userId: new mongoose.Types.ObjectId(req.user.id) } },
      { $group: { _id: null, total: { $sum: "$amount" } } }
    ]);

    res.json({ total: total[0]?.total || 0 });

  } catch (error) {
    console.error("❌ Total Error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

/* ===========================
   SERVER START
=========================== */
const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`🚀 Server running on port ${PORT}`);
});