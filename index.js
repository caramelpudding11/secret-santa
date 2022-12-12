const express = require('express');
const cors = require('express-cors');
const bodyParser = require('body-parser');
const bcrypt = require("bcryptjs");
const sqlite = require("better-sqlite3");
const session = require("express-session");
const serveStatic = require('serve-static');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(serveStatic(__dirname + "/static"))
app.use(cors());
const port = process.env.PORT || 4000;
const SqliteStore = require("better-sqlite3-session-store")(session)
const sess_db = new sqlite("sessions.db");

app.use(
    session({
        store: new SqliteStore({
            client: sess_db,
            expired: {
                clear: true,
                intervalMs: 900000 //ms = 15min
            }
        }),
        secret: "keyboard cat",
        resave: false,
        saveUninitialized: false
    })
)
app.listen(port, () => {
    console.log(`Server is running on port ${port}.`);
});

const db = sqlite('secret-santa.db');

db.exec('CREATE TABLE IF NOT EXISTS users (username TEXT unique, password TEXT)');
db.exec('CREATE TABLE IF NOT EXISTS games (participants TEXT, admin TEXT, pairs TEXT, name TEXT unique, budget INTEGER)');
app.post('/register', (req, res) => {
    const { username, password } = req.body;
    const exist = db.prepare('SELECT * FROM users WHERE username=?').get(username);
    if (!exist) {
        db.prepare('INSERT INTO users(username,password) VALUES (?,?)').run(username, bcrypt.hashSync(password));
        res.send({ msg: 'User Registered' });
    }
    else {
        res.send({ msg: 'User Already Exists' });
    }
});

app.post('/login', (req, res) => {
    const { username, password } = req.body;
    const user = db.prepare('SELECT * FROM users WHERE username=?').get(username);
    if (user) {
        if (bcrypt.compareSync(password, user.password)) {
            req.session.user = user;
            res.send({ msg: 'Logged In' });
        }
        else {
            res.send({ msg: 'Incorrect Password' });
        }
    }
    else {
        res.send({ msg: 'User Not Found' });
    }
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get('/is-logged-in', (req, res) => {
    res.send(!!req.session.user);
});

function createPairs(participants, exclusions) {
    const res = {};
    const participantsCopy = [...participants];
    const assignedGiftees = [];
    for (let i = 0; i < participants.length; i++) {
        const participant = participants[i];
        const filtered = participantsCopy.filter(p => p !== participant && !(participant in exclusions && exclusions[participant].includes(p)));
        console.log({
            participant, filtered
        })
        let randomIndex = Math.floor(Math.random() * filtered.length);
        while (assignedGiftees.includes(filtered[randomIndex])) {
            randomIndex = Math.floor(Math.random() * filtered.length);
        }
        res[participant] = filtered[randomIndex];
        assignedGiftees.push(filtered[randomIndex]);
    }
    return res;
}

function parseExclusions(exclusionString) {
    // exclusion string is a string of the form "a,b;c,d;e,f;a,c"
    // parse it into the following format {a:[b,c],c:[a],e:[f]}
    const exclusions = {};
    const exclusionList = exclusionString.split(';');
    for (let i = 0; i < exclusionList.length; i++) {
        const exclusion = exclusionList[i].split(',');
        if (exclusion[0] in exclusions) {
            exclusions[exclusion[0]].push(exclusion[1]);
        }
        else {
            exclusions[exclusion[0]] = [exclusion[1]];
        }
        if (exclusion[1] in exclusions) {
            exclusions[exclusion[1]].push(exclusion[0]);
        }
        else {
            exclusions[exclusion[1]] = [exclusion[0]];
        }
    }
    console.log(exclusions);
    return exclusions;
}


app.post('/create-game', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send({
            msg: "Not Logged In"
        })
    }
    const { participants, exclusions, name, budget } = req.body;
    const row = db.prepare('SELECT * FROM games WHERE name=?').get(name);
    if (row) {
        return res.status(409).send({ msg: 'Game Exists' });
    }
    const participantList = participants.split(',');
    const participants_s = JSON.stringify(participantList);
    // validate participants to make sure they exist in the database
    // if not send back an error message

    const pairs = JSON.stringify(createPairs(participantList, parseExclusions(exclusions)));
    db.prepare('INSERT INTO games(participants,admin,pairs,name,budget) VALUES (?,?,?,?,?)').run(participants_s, req.session.user.username, pairs, name, budget);
    res.send({ msg: "Ok" });
});

app.get('/users', (req, res) => {
    const users = db.prepare('SELECT * FROM users').all();
    res.send(users.map(user => user.username));
});

app.post('/delete-game', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send({
            msg: "Not Logged In"
        })
    }
    console.info(req.body);
    const { name } = req.body;
    const row = db.prepare('SELECT * FROM games WHERE name=?').get(name);
    console.log(name, row);
    if (row.admin !== req.session.user.username) {
        res.status(401).send({ msg: 'Only the creator of a game can delete it.' });
    }
    db.prepare('DELETE FROM games WHERE name=?').run(name);
    res.send({ msg: 'Game Deleted' });
});

app.post('/results', (req, res) => {
    const { name } = req.body;
    const row = db.prepare('SELECT * FROM games WHERE name=?').get(name);
    if (!row) {
        res.status(404).send({ msg: 'Game Not Found' });
    }
    res.send({ msg: JSON.parse(row.pairs)[req.session.user.username] });
});

app.get('/games', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send({
            msg: "Not Logged In"
        })
    }
    const games = db.prepare('SELECT * FROM games').all();
    res.send(games
        .filter(game => JSON.parse(game.participants).includes(req.session.user.username))
        .map(game => {
            return { name: game.name, budget: game.budget, admin: game.admin, participants: game.participants }
        }));
});

app.get('/adminned-games', (req, res) => {
    if (!req.session.user) {
        return res.status(401).send({
            msg: "Not Logged In"
        })
    }
    const games = db.prepare('SELECT * FROM games').all();
    res.send(games
        .filter(game => game.admin === req.session.user.username)
        .map(game => game.name));
});