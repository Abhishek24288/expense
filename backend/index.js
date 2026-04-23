const dns = require('dns');
dns.setServers(['8.8.8.8', '8.8.4.4']);

const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
require("dotenv").config();

const app = express();

/* ===========================
   CORS
=========================== */
const allowedOrigins = [
  "http://localhost:5173",
  "http://localhost:3000"
];

app.use(cors({
  origin: function (origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("CORS blocked"));
    }
  },
  credentials: true
}));

app.use(express.json());

/* ===========================
   MongoDB
=========================== */
mongoose.connect(process.env.MONGO_URI)
  .then(() => console.log("✅ MongoDB Connected"))
  .catch(err => console.error("❌ MongoDB Error:", err));

/* ===========================
   USER SCHEMA
=========================== */
const userSchema = new mongoose.Schema({
  name: { type: String, required: true },
  email: { type: String, unique: true, required: true },
  password: { type: String, required: true }
}, { timestamps: true });

const User = mongoose.model("User", userSchema);

/* ===========================
   ITEM SCHEMA
=========================== */
const itemSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
    required: true
  },
  itemName: { type: String, required: true },
  description: String,
  type: {
    type: String,
    enum: ["Lost", "Found"],
    required: true
  },
  location: String,
  date: { type: Date, default: Date.now },
  contactInfo: String
}, { timestamps: true });

const Item = mongoose.model("Item", itemSchema);

/* ===========================
   AUTH MIDDLEWARE
=========================== */
const authMiddleware = (req, res, next) => {
  try {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) {
      console.log("❌ No Token");
      return res.status(401).json({ message: "No token provided" });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;

    next();
  } catch (err) {
    console.error("❌ Auth Error:", err.message);
    return res.status(401).json({ message: "Invalid token" });
  }
};

/* ===========================
   AUTH ROUTES
=========================== */

// REGISTER
app.post("/api/register", async (req, res) => {
  try {
    console.log("📩 Register Body:", req.body);

    const { name, email, password } = req.body;

    if (!name || !email || !password) {
      return res.status(400).json({ message: "All fields required" });
    }

    const exist = await User.findOne({ email });
    if (exist) {
      return res.status(400).json({ message: "Email already exists" });
    }

    const hash = await bcrypt.hash(password, 10);

    const user = await User.create({
      name,
      email,
      password: hash
    });

    res.status(201).json({
      message: "Registered successfully",
      userId: user._id
    });

  } catch (err) {
    console.error("❌ Register Error:", err);
    res.status(500).json({ message: err.message });
  }
});

// LOGIN
app.post("/api/login", async (req, res) => {
  try {
    console.log("📩 Login Body:", req.body);

    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email/password" });
    }

    const match = await bcrypt.compare(password, user.password);
    if (!match) {
      return res.status(400).json({ message: "Invalid email/password" });
    }

    const token = jwt.sign(
      { id: user._id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({
      message: "Login success",
      token
    });

  } catch (err) {
    console.error("❌ Login Error:", err);
    res.status(500).json({ message: err.message });
  }
});

/* ===========================
   ITEM ROUTES
=========================== */

// ADD ITEM
app.post("/api/items", authMiddleware, async (req, res) => {
  try {
    console.log("📩 Add Item Body:", req.body);

    const item = await Item.create({
      userId: req.user.id,
      ...req.body
    });

    res.status(201).json(item);

  } catch (err) {
    console.error("❌ Add Item Error:", err);
    res.status(500).json({ message: err.message });
  }
});

// GET ALL ITEMS
app.get("/api/items", async (req, res) => {
  try {
    const items = await Item.find().sort({ date: -1 });
    res.json(items);
  } catch (err) {
    console.error("❌ Get Items Error:", err);
    res.status(500).json({ message: err.message });
  }
});

// GET ITEM BY ID
app.get("/api/items/:id", async (req, res) => {
  try {
    const item = await Item.findById(req.params.id);
    res.json(item);
  } catch (err) {
    console.error("❌ Get Item Error:", err);
    res.status(500).json({ message: err.message });
  }
});

// UPDATE ITEM
app.put("/api/items/:id", authMiddleware, async (req, res) => {
  try {
    const item = await Item.findByIdAndUpdate(
      req.params.id,
      req.body,
      { new: true }
    );
    res.json(item);
  } catch (err) {
    console.error("❌ Update Error:", err);
    res.status(500).json({ message: err.message });
  }
});

// DELETE ITEM
app.delete("/api/items/:id", authMiddleware, async (req, res) => {
  try {
    await Item.findByIdAndDelete(req.params.id);
    res.json({ message: "Deleted successfully" });
  } catch (err) {
    console.error("❌ Delete Error:", err);
    res.status(500).json({ message: err.message });
  }
});

// SEARCH
app.get("/api/items/search", async (req, res) => {
  try {
    const { name } = req.query;

    const items = await Item.find({
      itemName: { $regex: name, $options: "i" }
    });

    res.json(items);
  } catch (err) {
    console.error("❌ Search Error:", err);
    res.status(500).json({ message: err.message });
  }
});

/* ===========================
   SERVER
=========================== */
const PORT = process.env.PORT || 2000;

app.listen(PORT, () => {
  console.log("🚀 Server running on " + PORT);
});