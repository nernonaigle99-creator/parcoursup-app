const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
require("dotenv").config();

const app = express();
app.use(cors());
app.use(bodyParser.json());
app.use(express.static("public"));

const db = new sqlite3.Database("./database.db");

db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT,
    email TEXT,
    password TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS formations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nom TEXT,
    universite TEXT,
    ville TEXT
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS voeux (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    formation_id INTEGER
  )`);
});

app.post("/register", async (req, res) => {
  const { nom, email, password } = req.body;
  const hashedPassword = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (nom, email, password) VALUES (?, ?, ?)",
    [nom, email, hashedPassword],
    () => res.json({ message: "Inscription réussie" })
  );
});

app.post("/login", (req, res) => {
  const { email, password } = req.body;

  db.get("SELECT * FROM users WHERE email = ?", [email], async (err, user) => {
    if (!user) return res.status(401).json({ message: "Utilisateur introuvable" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(401).json({ message: "Mot de passe incorrect" });

    const token = jwt.sign({ id: user.id }, process.env.SECRET_KEY, {
      expiresIn: "2h",
    });

    res.json({ token });
  });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Serveur démarré");
});
