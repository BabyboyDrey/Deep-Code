const express = require("express");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const connectDb = require("./db/database.js");
const individualUsersRoutes = require("./controllers/individual_users.js");
const smeUsersRoutes = require("./controllers/sme_users.js");
const passport = require("./utils/passport.js");
const MongoStore = require("connect-mongo");
const session = require("express-session");

const app = express();

if (process.env.NODE_ENV !== "production") {
  require("dotenv").config({
    path: ".env",
  });
}

app.use(
  cors({
    origin: [
      "https://deepcode.onrender.com",
      "http://localhost:5173",
      "http://localhost:5174",
      ,
      "http://localhost:5174",
      ,
      "http://localhost:5175",
      ,
      "http://localhost:5176",
    ],
    credentials: true,
  })
);

app.use(express.urlencoded({ extended: true }));
app.use(cookieParser());

app.use(express.json());
app.use(
  session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB,
      collectionName: "sessions",
      autoRemove: "native",
      ttl: 24 * 60 * 60,
    }),
    cookie: {
      secure: process.env.NODE_ENV === "production",
      httpOnly: true,
      maxAge: 24 * 60 * 60 * 1000,
    },
  })
);
app.use(passport.initialize());
app.use(passport.session());
app.use("/", express.static("uploads"));
app.use("/api/v1/indi-user", individualUsersRoutes);
app.use("/api/v1/sme-user", smeUsersRoutes);
connectDb();
app.options("*", cors());

process.on("uncaughtException", (err) => {
  console.log(`Uncaught Exception Err: ${err}`);
  console.log("Shutting down server for uncaught exception");
});

process.on("unhandledRejection", (err) => {
  console.log(`Unhandled Rejection Err: ${err}`);
  console.log("Shutting down server for unhandled rejection");
  server.close(() => {
    process.exit(1);
  });
});

process.on("SIGTERM", () => {
  console.log("SIGTERM signal received: closing server");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

process.on("SIGINT", () => {
  console.log("SIGINT signal received: closing server");
  server.close(() => {
    console.log("Server closed");
    process.exit(0);
  });
});

process.on("warning", (warning) => {
  console.warn(
    `Warning: ${warning.name} - ${warning.message}\n${warning.stack}`
  );
});

process.on("rejectionHandled", (promise) => {
  console.log("Promise rejection handled:", promise);
});

process.on("beforeExit", (code) => {
  console.log("Process before Exit event with code:", code);
});

app.get("/dice", (req, res) => {
  res.send("Url of ngrok functional");
});

const PORT = process.env.SERVER_PORT || 5002;

const server = app.listen(PORT, () => {
  console.log(`Server listening on Port ${PORT}`);
  console.log(`worker pid: ${process.pid}`);
});
