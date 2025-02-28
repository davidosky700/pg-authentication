import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import dotenv from "dotenv";
import session from "express-session";
import bcrypt from "bcrypt";
import pgSession from "connect-pg-simple";

dotenv.config();

const app = express();
const port = process.env.PORT || 3000;
const saltRounds = 10;

// PostgreSQL Database Configuration
const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.DATABASE_URL.includes("localhost") ? false : { rejectUnauthorized: false }, 
});

db.connect()
  .then(() => console.log("✅ Connected to PostgreSQL Database"))
  .catch((err) => console.error("❌ Database Connection Error:", err));

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));

// Session Configuration
app.use(
  session({
    store: new (pgSession(session))({
      conString: process.env.DATABASE_URL, 
    }),
    secret: process.env.MY_SECRET || "default_secret",
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 },
  })
);

// Authentication Middleware
function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  }
  res.redirect("/login");
}

// Cache Control
app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  next();
});

// Routes
app.get("/", (req, res) => res.render("home.ejs"));
app.get("/login", (req, res) => res.render("login.ejs"));
app.get("/register", (req, res) => res.render("register.ejs"));
app.get("/secrets", isAuthenticated, (req, res) => res.render("secrets.ejs"));

// Register Route
app.post("/register", async (req, res) => {
  const { username: email, password } = req.body;
  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      const hashedPassword = await bcrypt.hash(password, saltRounds);
      await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, hashedPassword]);
      req.session.user = email;
      res.redirect("/secrets");
    }
  } catch (err) {
    console.error("❌ Error during registration:", err);
    res.status(500).send("Internal Server Error");
  }
});

// Login Route
app.post("/login", async (req, res) => {
  const { username: email, password: loginPassword } = req.body;
  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const match = await bcrypt.compare(loginPassword, user.password);
      if (match) {
        req.session.user = email;
        res.redirect("/secrets");
      } else {
        res.send("Incorrect Password");
      }
    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.error("❌ Error during login:", err);
    res.status(500).send("Internal Server Error");
  }
});

// Logout Route
app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error("❌ Logout Error:", err);
      return res.redirect("/secrets");
    }
    res.clearCookie("connect.sid");
    res.redirect("/");
  });
});

// Increase Timeout to Prevent 502 Errors
const server = app.listen(port, "0.0.0.0", () => {
  console.log(`🚀 Server running on http://localhost:${port}`);
});

// Extend Keep-Alive Timeout (for Render)
server.keepAliveTimeout = 120 * 1000; 
server.headersTimeout = 120 * 1000; 
