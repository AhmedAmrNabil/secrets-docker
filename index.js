import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
// import "dotenv/config.js";
import session from "express-session";
import connectPgSimple from "connect-pg-simple";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import { Strategy as GoogleStrategy } from "passport-google-oauth20";

const app = express();
const port = process.env.PORT;
const saltRounds = 10;
const pgStore = connectPgSimple(session);

app.use(bodyParser.urlencoded({ extended: true }));
app.use(express.static("public"));
app.use(
  session({
    store: new pgStore(),
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      maxAge: 100 * 60 * 60 * 30,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());

const db = new pg.Client({
  port:5432
});
console.log(process.env.PGPORT);

try{
  db.connect();
}catch (err){
  console.error(err);
}

app.get("/", (req, res) => {
  if (req.isAuthenticated()) res.redirect("/secrets");
  else res.render("home.ejs");
});

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.get("/secrets", async (req, res) => {
  if (req.isAuthenticated()) {
    const result = await db.query("SELECT secret FROM users WHERE id = $1",[req.user.id]);
    let secret = "you have no secret saved";
    if(result.rowCount > 0 && result.rows[0].secret)secret = result.rows[0].secret;
    res.render("secrets.ejs",{secret:secret});
  } else {
    res.redirect("/login");
  }
});

app.get("/submit", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("submit.ejs");
  } else {
    res.redirect("/login");
  }
});

app.get(
  "/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.get("/register", (req, res) => {
  res.render("register.ejs");
});

app.get("/logout", (req, res) => {
  req.logout((err) => {
    if (err) console.log(err);
    else res.redirect("/");
  });
});

app.post("/register", async (req, res) => {
  const email = req.body.username;
  const password = req.body.password;

  try {
    const checkResult = await db.query("SELECT * FROM users WHERE email = $1", [
      email,
    ]);

    if (checkResult.rowCount > 0) {
      res.send("Email already exists. Try logging in.");
      return;
    }
    const hash = await bcrypt.hash(password, saltRounds);
    const result = await db.query(
      "INSERT INTO users (email, password) VALUES ($1, $2) RETURNING *",
      [email, hash]
    );
    const user = result.rows[0];
    req.login(user, (err) => {
      if (err) console.log(err);
      else res.redirect("/secrets");
    });
  } catch (err) {
    console.log(err);
  }
});

app.post(
  "/login",
  passport.authenticate("local", {
    successRedirect: "/secrets",
    failureRedirect: "/login",
  })
);

app.post("/submit",async(req,res)=>{
  try{
    const result = await db.query("UPDATE users SET secret = $1 WHERE id = $2",[req.body.secret,req.user.id]);
    res.redirect("/secrets");
  }catch(err){
    console.error(err);
  }
});

passport.use(
  "local",
  new LocalStrategy(async (username, passowrd, cb) => {
    try {
      const query = await db.query("SELECT * FROM users WHERE email = $1", [
        username,
      ]);
      if (query.rows.length <= 0) return cb(null, false);
      const user = query.rows[0];
      const storedHashedPassword = user.password;
      const result = await bcrypt.compare(passowrd, storedHashedPassword);
      if (result) return cb(null, user);
      return cb(null, false);
    } catch (err) {
      return cb(err);
    }
  })
);

passport.use(
  "google",
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: process.env.GOOGLE_CLIENT_CALLBACK,
      // callbackURL: "http://btngana.viewdns.net/auth/google/secrets",
    },
    async (accessToken, refreshToken, profile, cb) => {
      try {
        const result = await db.query("SELECT * FROM users WHERE email = $1", [
          profile._json.email,
        ]);
        if (result.rowCount > 0) return cb(null, result.rows[0]);
        const user = await db.query(
          "INSERT INTO users (email,password) VALUES ($1,$2) RETURNING *",
          [profile._json.email, "google"]
        );
        return cb(null, user.rows[0]);
      } catch (err) {
        return cb(err);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user);
});

passport.deserializeUser((user, done) => {
  done(null, user);
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
