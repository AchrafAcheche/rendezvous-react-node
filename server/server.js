var mysql = require("mysql");
const express = require("express");
const cors = require("cors");
const bcrypt = require("bcrypt");

//cokkie session
const bodyParser = require("body-parser");
const cookieParser = require("cookie-parser");
const session = require("express-session");

const saltRounds = 10; //for bcrypt

const app = express(); //for api
app.use(express.json()); // for api
//for api/auth
app.use(
  cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true,
  })
);
app.use(cookieParser());//for auth
app.use(bodyParser.urlencoded({ extended: true }));//for auth

//auth
app.use(
  session({
    key: "userId",
    secret: "subscribe",//word hard to find
    resave: false,
    saveUninitialized: false,
    cookie: {
      expires: 60 * 60 * 24,//24 h
    },
  })
);

  //create connection with db
var db = mysql.createConnection({

  host: "localhost",
  user: "root",
  password: "",
  port: 3308,
  database: "rendezvous",
});
//register
app.post("/register", (req, res) => {
  const username = req.body.username; //username name from the front (app)
  const password = req.body.password;
  //crypt the password --> hash
  bcrypt.hash(password, saltRounds, (err, hash) => {
  
    if (err) {
      console.log(err);
    }
    db.query(
      "INSERT INTO users (userid,username,passwd) VALUES(NULL,?,?)",
      [username, hash],
      (err, result) => {
        console.log(err);
      }
    );
  });
});
//login auth/ parse session if logged
app.get("/login", (req, res) => {
  if (req.session.user) {
    res.send({ loggedIn: true, user: req.session.user });
  } else {
    res.send({ loggedIn: false });
  }
});
//login
app.post("/login", (req, res) => {
  const username = req.body.username; //username name from the front (app)
  const password = req.body.password;

  db.query(
    "SELECT * FROM users WHERE username = ? ;",
    username,
    (err, result) => {
      if (err) {
        res.send({ err: err });
      }
      if (result.length != 0) {
        bcrypt.compare(password, result[0].passwd, (error, response) => {
          if (response) {
            req.session.user = result;
            console.log(req.session.user);
            res.send(result);
          } else {
            res.send({ message: "Wrong username/password combination" });
          }
        });
      } else {
        res.send({ message: "User dosen't exist" });
      }
    }
  );
});

app.listen(3001, () => {
  console.log("running server");
});
