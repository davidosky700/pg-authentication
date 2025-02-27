import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import env from "dotenv";
import session from "express-session";
import bcrypt from "bcrypt";
import pgSession from "connect-pg-simple";

const app = express();
const port = 3000;
const saltRounds = 10;
env.config();

const db = new pg.Client({
  connectionString: process.env.DATABASE_URL,  
  ssl: {
    rejectUnauthorized: false, 
  },
});
db.connect();


app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));


app.use(
  session({
    store: new (pgSession(session))({
      pool: db,
    }),
    secret: process.env.MY_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: { secure: false, maxAge: 1000 * 60 * 60 * 24 }, 
  })
);


function isAuthenticated(req, res, next) {
  if (req.session.user) {
    return next();
  } else {
    res.redirect("/login");
  }
}

app.use((req, res, next) => {
  res.set("Cache-Control", "no-store, no-cache, must-revalidate, private");
  next();
});

app.get("/", (req, res) => {
  res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/secrets", isAuthenticated, (req, res) => {
  if (!req.session.user) {
    return res.redirect("/login");
  }
  res.render("secrets.ejs");
});


app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rows.length > 0) {
      res.send("Email already exists. Try logging in.");
    } else {
      bcrypt.hash(password, saltRounds, async (err, hash) => {
        if (err) {
          console.log("Error hashing password", err);
        } else {
        const result = await db.query(
          "INSERT INTO users (email, password) VALUES ($1, $2)",
          [email, hash]
        );
        console.log(result);
        res.render("secrets.ejs");
      }
      });
      
    }
  } catch (err) {
    console.log(err);
  }
});

app.post("/login", async (req, res) => {
  const email = req.body.username;
  const loginPassword = req.body.password;

  try {
    const result = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);
    if (result.rows.length > 0) {
      const user = result.rows[0];
      const storedHashPassword = user.password;

      bcrypt.compare(loginPassword, storedHashPassword, (err, result) => {
        if (err) {
          console.log("Error comparing passwords", err);
        } else {
          if (result) {
            res.render("secrets.ejs");
        } else {
            res.send("Incorrect Password");
        }
        }
      });

    } else {
      res.send("User not found");
    }
  } catch (err) {
    console.log(err);
  }
});

app.get("/logout", (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.log(err);
      return res.redirect("/secrets");
    }
    res.clearCookie("connect.sid"); 
    res.redirect("/");
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
