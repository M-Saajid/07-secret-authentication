//jshint esversion:6
require("dotenv").config();
const express = require("express");
const bodyParser = require("body-parser");
const ejs = require("ejs");
const mongoose = require("mongoose");
const encrypt = require("mongoose-encryption");
const md5 = require("md5");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const session = require("express-session");
const passport = require("passport");
const passportLocalMongoose = require("passport-local-mongoose");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const findOrCreate = require("mongoose-findorcreate");

const app = express();

app.set("view engine", "ejs");

app.use(
  bodyParser.urlencoded({
    extended: true
  })
);

app.use(
  session({
    secret: "keygen.",
    resave: false,
    saveUninitialized: true
    //   cookie: { secure: true }
  })
);

app.use(passport.initialize());

app.use(passport.session());

mongoose.connect("mongodb://localhost:27017/userDB");

const userSchema = new mongoose.Schema({
  email: String,
  password: String,
  googleId: String,
  secret: String
});

userSchema.plugin(passportLocalMongoose);
userSchema.plugin(findOrCreate);

const user = new mongoose.model("user", userSchema);

passport.use(user.createStrategy());
passport.serializeUser(function (newUser, done) {
  done(null, newUser._id);

});

passport.deserializeUser(function (id, done) {
  user.findById(id, function (err, newuser) {
    done(err, newuser);
  });
});

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.CLIENT_ID,
      clientSecret: process.env.CLIENT_SECRETS,
      callbackURL: "http://localhost:3000/auth/google/secrets",
      userProfileURL: "https://www.googleapis.com/oauth2/v3/userinfo"
    },
    function (accessToken, refreshToken, profile, cb) {
      console.log(profile);
      user.findOrCreate({ googleId: profile.id }, function (err, user) {
        return cb(err, user);
      });
    }
  )
);

app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile"]
  })
);

app.get(
  "/auth/google/secrets",
  passport.authenticate("google", {
    failureRedirect: "/login",
    failureMessage: true
  }),
  function (req, res) {
    res.redirect("/secrets");
  }
);
app.get("/secrets", function (req, res) {
  user.find({ secret: { $ne: null } }, function (err, foundUsers) {
    if (err) {
      console.log(err);
    } else {
      if (foundUsers) {
        res.render("secrets", { usersWithSecrets: foundUsers });
      }
    }
  });
});
app.get("/submit", function (req, res) {
  if (req.isAuthenticated()) {
    res.render("submit");
  } else {
    res.redirect("/login");
  }
});

app.post("/submit", function (req, res) {
  const submittedSecret = req.body.secret;

  user.findById(req.user.id, function (err, foundUser) {
    if (err) {
      console.log(err);
    } else {
      if (foundUser) {
        foundUser.secret = submittedSecret;
        foundUser.save(function () {
          res.redirect("/secrets");
        });
      }
    }
  });
});
///////////////////////////////////////////////////////////////////////////////////////////////////////
// app.post("/login", (req, res) => {
//     const username = req.body.username
//     const password = req.body.password
//     user.findOne({ email: username }, (e, foundUser) => {
//         if (!e) {
//             if (foundUser) {
//                 bcrypt.compare(password, foundUser.password, function (err, result) {
//                     if (result === true) {
//                         res.render("secrets")
//                     }
//                 });

//             }
//         }
//     })
// })
//////////////////////////////////////////////////////////////////////////////////////////////////////////
app.post("/login", (req, res) => {
  const usernew = new user({
    username: req.body.username,
    password: req.body.password
  });

  req.login(usernew, function (err) {
    if (err) {
      console.log(err);
    } else {
      passport.authenticate("local")(req, res, function () {
        res.redirect("/secrets");
      });
    }
  });
});
app.get("/logout", (req, res) => {
  req.logOut();
  res.redirect("/");
});

app.post("/register", (req, res) => {
  user.register(
    { username: req.body.username },
    req.body.password,
    function (err, newUser) {
      if (err) {
        console.log(err);
        res.redirect("/register");
      } else {
        passport.authenticate("local")(req, res, function () {
          res.redirect("/secrets");
        });
      }
    }
  );
  /////////////////////////////////////////////////////////////////////////////////////////////////
  // bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
  //     const newUser = new user({
  //         email: req.body.username,
  //         password: hash
  //     })

  //     newUser.save((e) => {
  //         if (!e) {
  //             res.render("secrets")
  //         } else {

  //         } console.log(e)
  //     })
  // });
  //////////////////////////////////////////////////////////////////////////////////////////////////
});

app.get("/", (req, res) => {
  res.render("home");
});

app.get("/login", (req, res) => {
  res.render("login");
});
app.get("/secrets", (req, res) => {
  if (req.isAuthenticated()) {
    res.render("secrets");
  } else {
    res.redirect("/login");
  }
});
app.get("/register", function (req, res) {
  res.render("register");
});

app.listen(3000, function () {
  console.log("Server started on port 3000");
});
