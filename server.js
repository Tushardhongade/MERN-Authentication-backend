const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

const app = express();

// CORS middleware - Updated with proper credentials
app.use((req, res, next) => {
  const allowedOrigins = [
    "http://localhost:5173",
    "http://localhost:3000",
    "https://mern-authentication-frontend-nu.vercel.app"
  ];
  
  const origin = req.headers.origin;
  if (allowedOrigins.includes(origin)) {
    res.header("Access-Control-Allow-Origin", origin);
  }
  
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-auth-token");
  res.header("Access-Control-Allow-Credentials", "true");
  
  if (req.method === "OPTIONS") {
    return res.status(200).end();
  }
  next();
});

app.use(express.json());

// TEST ROUTE
app.get("/api/test", (req, res) => {
  res.json({ 
    message: "API is working!",
    status: "success",
    timestamp: new Date().toISOString()
  });
});

// HEALTH CHECK
app.get("/api/health", (req, res) => {
  res.json({ 
    status: "OK",
    message: "Server is healthy",
    database: mongoose.connection.readyState === 1 ? "Connected" : "Disconnected"
  });
});

// ROOT ROUTE
app.get("/", (req, res) => {
  res.json({ 
    message: "MERN Auth API Server is running!",
    status: "success",
    endpoints: {
      test: "/api/test",
      health: "/api/health", 
      register: "/api/auth/register",
      login: "/api/auth/login",
      get_user: "/api/auth/me"
    },
    timestamp: new Date().toISOString()
  });
});

// User Model
const userSchema = new mongoose.Schema(
  {
    name: { 
      type: String, 
      required: [true, "Name is required"], 
      trim: true,
      minlength: [2, "Name must be at least 2 characters"]
    },
    email: { 
      type: String, 
      required: [true, "Email is required"], 
      unique: true, 
      lowercase: true, 
      trim: true,
      match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, "Please enter a valid email"]
    },
    password: { 
      type: String, 
      required: [true, "Password is required"], 
      minlength: [6, "Password must be at least 6 characters"] 
    },
  },
  { timestamps: true }
);

userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();
  
  try {
    this.password = await bcrypt.hash(this.password, 12);
    next();
  } catch (error) {
    next(error);
  }
});

userSchema.methods.comparePassword = async function (candidatePassword) {
  try {
    return await bcrypt.compare(candidatePassword, this.password);
  } catch (error) {
    throw new Error("Password comparison failed");
  }
};

// Remove any existing model to avoid OverwriteModelError
if (mongoose.models.User) {
  mongoose.deleteModel("User");
}
const User = mongoose.model("User", userSchema);

// Auth middleware
const auth = (req, res, next) => {
  const token = req.header("x-auth-token");
  
  if (!token) {
    return res.status(401).json({ 
      success: false,
      message: "No token, authorization denied" 
    });
  }
  
  try {
    const decoded = jwt.verify(
      token, 
      process.env.JWT_SECRET || "fallback-secret-key-for-development"
    );
    req.user = { id: decoded.userId };
    next();
  } catch (error) {
    return res.status(401).json({ 
      success: false,
      message: "Token is not valid" 
    });
  }
};

// REGISTER ROUTE
app.post("/api/auth/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // Validation
    if (!name || !email || !password) {
      return res.status(400).json({ 
        success: false,
        message: "All fields are required" 
      });
    }
    
    if (password.length < 6) {
      return res.status(400).json({ 
        success: false,
        message: "Password must be at least 6 characters" 
      });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        success: false,
        message: "User already exists with this email" 
      });
    }

    // Create user
    const user = new User({ name, email, password });
    await user.save();

    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || "fallback-secret-key-for-development",
      { expiresIn: "7d" }
    );

    res.status(201).json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
    
  } catch (error) {
    console.error("Register error:", error);
    
    // Handle duplicate key error
    if (error.code === 11000) {
      return res.status(400).json({
        success: false,
        message: "User already exists with this email"
      });
    }
    
    // Handle validation errors
    if (error.name === 'ValidationError') {
      const messages = Object.values(error.errors).map(err => err.message);
      return res.status(400).json({
        success: false,
        message: messages.join(', ')
      });
    }
    
    res.status(500).json({ 
      success: false,
      message: "Server error during registration" 
    });
  }
});

// LOGIN ROUTE
app.post("/api/auth/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // Validation
    if (!email || !password) {
      return res.status(400).json({ 
        success: false,
        message: "Email and password are required" 
      });
    }

    // Find user
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // Check password
    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(400).json({ 
        success: false,
        message: "Invalid email or password" 
      });
    }

    // Generate token
    const token = jwt.sign(
      { userId: user._id },
      process.env.JWT_SECRET || "fallback-secret-key-for-development",
      { expiresIn: "7d" }
    );

    res.json({
      success: true,
      token,
      user: {
        id: user._id,
        name: user.name,
        email: user.email,
      },
    });
    
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ 
      success: false,
      message: "Server error during login" 
    });
  }
});

// GET CURRENT USER
app.get("/api/auth/me", auth, async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("-password");
    
    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found"
      });
    }
    
    res.json({
      success: true,
      user
    });
    
  } catch (error) {
    console.error("Get user error:", error);
    res.status(500).json({ 
      success: false,
      message: "Server error while fetching user data" 
    });
  }
});

// Connect to MongoDB
const connectDB = async () => {
  try {
    if (process.env.MONGODB_URI) {
      await mongoose.connect(process.env.MONGODB_URI, {
        useNewUrlParser: true,
        useUnifiedTopology: true,
      });
      console.log("✅ MongoDB connected successfully");
    } else {
      console.log("⚠️  MONGODB_URI not set, running without database connection");
    }
  } catch (error) {
    console.log("❌ MongoDB connection failed:", error.message);
  }
};

connectDB();

// Global error handler
app.use((error, req, res, next) => {
  console.error("Unhandled error:", error);
  res.status(500).json({
    success: false,
    message: "Internal server error"
  });
});

// 404 handler for undefined API routes
app.use("/api/*", (req, res) => {
  res.status(404).json({
    success: false,
    error: "API route not found",
    path: req.originalUrl,
    method: req.method
  });
});

// Catch-all handler
app.use("*", (req, res) => {
  res.status(404).json({
    success: false,
    error: "Route not found",
    path: req.originalUrl,
    method: req.method
  });
});

// Export the app for Vercel
module.exports = app;
