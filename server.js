import express from "express";
import mongoose from "mongoose";
import bcrypt from "bcrypt";
import jwt from "jsonwebtoken";
import cors from "cors";
import dotenv from "dotenv";
import CryptoJS from "crypto-js";

dotenv.config();

const app = express();
app.use(express.json());
app.use(cors());

// Connect to MongoDB
mongoose
  .connect(process.env.mongo_uri, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("MongoDB connected"))
  .catch((err) => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
  name: String,
  email: { type: String, unique: true },
  password: String,
  savedPasswords: [
    {
      website: { type: String, required: true },
      username: { type: String, required: true },
      password: { type: String, required: true }, // Should be encrypted
    },
  ],
});

const User = mongoose.model("User", UserSchema);

// Register Route
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 10);

    const newUser = new User({
      name,
      email,
      password: hashedPassword,
      savedPasswords: [],
    });
    await newUser.save();

    res.status(201).json({ message: "User registered successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Login Route
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const isMatch = bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign({ userId: user._id }, process.env.jwt_secret, {
      expiresIn: "1h",
    });

    res.status(200).json({
      message: "Login successful",
      token,
      user: {
        name: user.name,
        email: user.email,
      },
    });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Middleware to verify JWT
const authMiddleware = (req, res, next) => {
  const authHeader = req.header("Authorization");

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res
      .status(401)
      .json({ message: "Access denied, token missing or incorrect" });
  }

  const token = authHeader.split(" ")[1];

  try {
    const decoded = jwt.verify(token, process.env.jwt_secret);

    req.user = decoded;
    next();
  } catch (error) {
    res.status(401).json({ message: "Invalid or expired token" });
  }
};

// Save Password Route
app.post("/save-password", authMiddleware, async (req, res) => {
  try {
    const { website, username, password } = req.body;
    // const encryptedPassword = await bcrypt.hash(password, 10);

    const user = await User.findById(req.user.userId);
    if (!user) return res.status(404).json({ message: "User not found" });

    user.savedPasswords.push({
      website,
      username,
      password,
    });

    await user.save();

    res.status(201).json({
      message: "Password saved successfully",
      savedPasswords: user.savedPasswords.map((pwd) => pwd.toObject()),
    });
  } catch (error) {
    console.error("Save password error:", error);
    res.status(500).json({ message: "Server error", error });
  }
});

app.get("/me", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId).select("-password"); // Get user without password
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    res.json(user);
  } catch (error) {
    res.status(500).json({ message: "Server error" });
  }
});

// Get All Saved Passwords
app.get("/get-passwords", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    // const decryptedPasswords = user.savedPasswords.map((entry) => ({
    //   website: entry.website,
    //   username: entry.username,
    //   password: entry.password, // Assuming passwords are stored in plain text
    // }));

    res.status(200).json(user.savedPasswords); // ✅ Ensure this is sent as an array
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Update Saved Password
// Get a single password entry
app.get("/get-password/:id", authMiddleware, async (req, res) => {
  try {
    console.log("User ID:", req.user.userId);
    console.log("Password Entry ID:", req.params.id);

    const user = await User.findById(req.user.userId);
    if (!user) {
      console.log("User not found");
      return res.status(404).json({ error: "User not found" });
    }

    const passwordEntry = user.savedPasswords.id(req.params.id);
    if (!passwordEntry) {
      console.log("Password entry not found");
      return res.status(404).json({ error: "Password not found" });
    }

    res.json(passwordEntry);
  } catch (err) {
    console.error("Server error:", err);
    res.status(500).json({ error: "Server error" });
  }
});

// Update a password entry
app.put("/update-password/:id", authMiddleware, async (req, res) => {
  const { username, password, website } = req.body;
  const user = await User.findById(req.user.userId);
  const entry = user.savedPasswords.id(req.params.id);
  if (!entry) return res.status(404).json({ error: "Password not found" });

  entry.username = username;
  entry.password = password;
  entry.website = website;
  await user.save();

  res.json({ message: "Password updated" });
});

// Delete Saved Password
app.delete("/delete-password/:id", authMiddleware, async (req, res) => {
  try {
    const user = await User.findById(req.user.userId);

    user.savedPasswords = user.savedPasswords.filter(
      (passwordEntry) => passwordEntry._id.toString() !== req.params.id
    );

    await user.save();
    res.status(200).json({ message: "Password deleted successfully" });
  } catch (error) {
    res.status(500).json({ message: "Server error", error });
  }
});

// Start server
const PORT = 4000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
