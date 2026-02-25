import "dotenv/config";
import express from "express";
import cors from "cors";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import crypto from "crypto";
import pkg from "@prisma/client";
const { PrismaClient } = pkg;
import { PrismaPg } from "@prisma/adapter-pg";
import { Resend } from "resend";
const resend = new Resend(process.env.RESEND_API_KEY);

console.log("RESEND KEY EXISTS:", !!process.env.RESEND_API_KEY);

/* ======================
   DATABASE SETUP
====================== */

const adapter = new PrismaPg({
  connectionString: process.env.DATABASE_URL,
});

const prisma = new PrismaClient({ adapter });


/* ======================
   EXPRESS SETUP
====================== */

const app = express();
app.use(express.json());
app.use(cors());

/* ======================
   AUTH MIDDLEWARE
====================== */

async function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ message: "Access token required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await prisma.user.findUnique({
      where: { id: decoded.userId },
    });

    if (!user || !user.isActive) {
      return res.status(403).json({ message: "Access denied" });
    }

    req.user = user; // always fresh from DB
    next();
  } catch {
    return res.status(403).json({ message: "Invalid or expired token" });
  }
}

function requireRole(role) {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Not authenticated" });
    }

    if (req.user.role !== role) {
      return res.status(403).json({ message: "Access denied: insufficient role" });
    }

    next();
  };
}

/* ======================
   PUBLIC ROUTES
====================== */

app.get("/api/test", (req, res) => {
  res.send("Server is running");
});

/* ======================
   AUTH ROUTES
====================== */

app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const existing = await prisma.user.findUnique({
      where: { email },
    });

    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
      data: {
        email,
        password: hashed,
      },
    });

    res.status(201).json({ message: "User created", userId: user.id });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await prisma.user.findUnique({
      where: { email },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, user.password);

    if (!valid) {
      return res.status(400).json({ message: "Invalid credentials" });
    }

    const token = jwt.sign(
      { userId: user.id },
      process.env.JWT_SECRET,
      { expiresIn: "7d" }
    );

    res.json({ token });
  } catch (error) {
    console.error("Login error:", error);
    res.status(500).json({ message: "Server error" });
  }
});





app.post("/api/register", async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password) {
      return res.status(400).json({ message: "Email and password required" });
    }

    const existing = await prisma.user.findUnique({
      where: { email },
    });

    if (existing) {
      return res.status(400).json({ message: "User already exists" });
    }

    const hashed = await bcrypt.hash(password, 12);

    const user = await prisma.user.create({
      data: {
        email,
        password: hashed,
      },
    });

    res.status(201).json({ message: "User created", userId: user.id });
  } catch (error) {
    console.error("Register error:", error);
    res.status(500).json({ message: "Server error" });
  }
});








/* ======================
   PROTECTED ROUTES
====================== */

app.get("/api/student", authenticateToken, (req, res) => {
  res.json({
    message: "Student dashboard",
    user: req.user,
  });
});

app.get(
  "/api/strategy-tracking",
  authenticateToken,
  (req, res) => {
    if (!req.user.hasStrategyTracking && req.user.role !== "ADMIN") {
      return res.status(403).json({ message: "Strategy access required" });
    }

    res.json({ message: "Strategy Tracking Access Granted" });
  }
);

app.get(
  "/api/probability-calculator",
  authenticateToken,
  (req, res) => {
    if (!req.user.hasProbabilityCalculator && req.user.role !== "ADMIN") {
      return res.status(403).json({ message: "Probability access required" });
    }

    res.json({ message: "Probability Calculator Access Granted" });
  }
);

app.get(
  "/api/admin",
  authenticateToken,
  requireRole("ADMIN"),
  (req, res) => {
    res.json({
      message: "Admin dashboard",
      user: req.user,
    });
  }
);

/* ======================
   ADMIN CONTROL API
   (Manual Access Grant)
====================== */

app.put(
  "/api/admin/grant-access",
  authenticateToken,
  requireRole("ADMIN"),
  async (req, res) => {
    try {
      const { email, strategy, probability } = req.body;

      const updatedUser = await prisma.user.update({
        where: { email },
        data: {
          hasStrategyTracking: strategy,
          hasProbabilityCalculator: probability,
        },
      });

      res.json({
        message: "Access updated successfully",
        user: updatedUser,
      });
    } catch (error) {
      console.error("Grant access error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);






app.post(
  "/api/admin/create-user",
  authenticateToken,
  requireRole("ADMIN"),
  async (req, res) => {
    try {
      const { email } = req.body;

      if (!email) {
        return res.status(400).json({ message: "Email required" });
      }

      const existing = await prisma.user.findUnique({
        where: { email },
      });

      if (existing) {
        return res.status(400).json({ message: "User already exists" });
      }

      // Generate secure reset token
      const resetToken = crypto.randomBytes(32).toString("hex");
      const resetTokenExpiry = new Date(Date.now() + 1000 * 60 * 60); // 1 hour

      await prisma.user.create({
        data: {
          email,
          resetToken,
          resetTokenExpiry,
        },
      });

      const resetLink = `https://noiruniversity.com/set-password?token=${resetToken}`;

      const result = await resend.emails.send({
        from: "Noir University <noreply@access.noiruniversity.com>",
        to: email,
        subject: "Set Your Noir University Password",
        html: `
          <h3>Welcome to Noir University</h3>
          <p>Click below to set your password:</p>
          <a href="${resetLink}">${resetLink}</a>
          <p>This link expires in 1 hour.</p>
        `,
      });

      console.log("Resend result:", result);
      res.json({ message: "User created and reset email sent" });

    } catch (error) {
      console.error("Create user error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);



app.post("/api/set-password", async (req, res) => {
  try {
    const { token, password } = req.body;

    if (!token || !password) {
      return res.status(400).json({ message: "Token and password required" });
    }

    const user = await prisma.user.findFirst({
      where: {
        resetToken: token,
        resetTokenExpiry: {
          gt: new Date(),
        },
      },
    });

    if (!user) {
      return res.status(400).json({ message: "Invalid or expired token" });
    }

    const hashed = await bcrypt.hash(password, 12);

    await prisma.user.update({
      where: { id: user.id },
      data: {
        password: hashed,
        resetToken: null,
        resetTokenExpiry: null,
      },
    });

    res.json({ message: "Password set successfully" });

  } catch (error) {
    console.error("Set password error:", error);
    res.status(500).json({ message: "Server error" });
  }
});





app.get(
  "/api/admin/members",
  authenticateToken,
  requireRole("ADMIN"),
  async (req, res) => {
    try {
      const users = await prisma.user.findMany({
        select: {
          id: true,
          email: true,
          hasStrategyTracking: true,
          hasProbabilityCalculator: true,
          createdAt: true,
        },
        orderBy: { createdAt: "desc" }
      });

      res.json(users);
    } catch (error) {
      console.error("Fetch members error:", error);
      res.status(500).json({ message: "Server error" });
    }
  }
);









/* ======================
   SERVER START
====================== */

const PORT = process.env.PORT || 3001;


app.get("/api/debug-db", async (req, res) => {
  const users = await prisma.user.findMany({
    select: {
      email: true,
      hasStrategyTracking: true,
    },
  });

  res.json(users);
});



app.get("/api/debug-users", async (req, res) => {
  const users = await prisma.user.findMany({
    select: { email: true }
  });
  res.json(users);
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Server running on port ${PORT}`);
});