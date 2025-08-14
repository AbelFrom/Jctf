// ctf-server.js
const express = require('express');
const bodyParser = require('body-parser');
const fs = require('fs');
const path = require('path');
const multer = require('multer');
const app = express();
const upload = multer({ dest: 'uploads/' });
const PORT = 3000;

// Dummy user database
const users = {
    alice: { password: 'alice123', role: 'user' },
    admin: { password: 'admin123', role: 'admin' }
};

// CTF flags for each vulnerability
const flags = {
    lfi: "FLAG-LFI-12345",
    sql: "FLAG-SQLI-67890",
    xss: "FLAG-XSS-ABCDE",
    cmd: "FLAG-CMD-54321"
};

app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());

// Serve the HTML frontend
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'ctf.html')); // Save your HTML as ctf.html
});

// Simple login (vulnerable)
app.post('/login', (req, res) => {
    const { username, password } = req.body;
    if(users[username] && users[username].password === password){
        res.send(`Welcome ${username}. Role: ${users[username].role}`);
    } else {
        res.send("Invalid login.");
    }
});

// LFI endpoint
app.get('/view', (req, res) => {
    const file = req.query.file; // NO validation
    if(!file) return res.send("No file specified.");
    fs.readFile(path.join(__dirname, file), 'utf8', (err, data) => {
        if(err) return res.send("File not found.");
        res.type('text/plain').send(data + "\nFlag: " + flags.lfi);
    });
});

// SQLi simulation (insecure string concatenation)
app.get('/profile', (req, res) => {
    const user = req.query.user; // no sanitization
    if(users[user]){
        res.send(`User found: ${user}. Password: ${users[user].password}. Flag: ${flags.sql}`);
    } else {
        res.send("User not found.");
    }
});

// Stored XSS
let comments = [];
app.post('/comment', (req, res) => {
    const { msg } = req.body;
    comments.push(msg); // No sanitization
    res.send("Comment added!");
});
app.get('/comments', (req, res) => {
    res.send(comments.join('<br>') + "<br>Flag: " + flags.xss);
});

// Command Injection
app.get('/ping', (req, res) => {
    const host = req.query.host;
    const { exec } = require('child_process');
    exec(`ping -c 1 ${host}`, (err, stdout, stderr) => {
        if(err) return res.send("Error pinging host.");
        res.send(`<pre>${stdout}</pre>\nFlag: ${flags.cmd}`);
    });
});

// Insecure file upload
app.post('/upload', upload.single('file'), (req, res) => {
    res.send(`File uploaded: ${req.file.originalname}`);
});

app.listen(PORT, () => console.log(`CTF server running at http://localhost:${PORT}`));
