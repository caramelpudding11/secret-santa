const express = require('express');
const cors = require('express-cors');
const bodyParser = require('body-parser');
const bcrypt = require("bcryptjs");
const sqlite = require("better-sqlite3");
const session = require("express-session");
const serveStatic = require('serve-static');
const captcha = require('trek-captcha');
const { v4 } = require('uuid');

const app = express();
app.use(bodyParser.urlencoded({ extended: true }))
app.use(bodyParser.json())
app.use(serveStatic(__dirname + "/static"))
app.use(cors());
const port = process.env.PORT || 4000;
const SqliteStore = require("better-sqlite3-session-store")(session)
const sess_db = new sqlite("sessions.db");
const captchas = {}

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
    const { username, password, captchaId, captchaValue } = req.body;
    const exists = db.prepare('SELECT * FROM users WHERE username=?').get(username);
    if (!exists) {
        if (req.body.nicetry) return res.send({ msg: "Unknown error" });
        if (captchas[captchaId] !== captchaValue) {
            return res.send({ msg: "Invalid or expired captcha. Refresh the page if this persists." });
        }
        delete captchas[captchaId];
        db.prepare('INSERT INTO users(username,password) VALUES (?,?)').run(username, bcrypt.hashSync(password));
        res.send({ msg: 'User Registered' });
    }
    else {
        res.send({ msg: 'User Already Exists' });
    }
});

app.get('/whoami', (req, res) => {
    res.type('json').send(JSON.stringify(req.session.user.username));
})

app.get('/captcha', async (req, res) => {
    const uuid = v4();
    const { token, buffer } = await captcha();
    captchas[uuid] = token;
    res.send({
        buf: buffer.toString('base64'),
        uuid
    })
})

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

function* priorityIterator(array, cmp) {
    let i = 0;
    const yielded = new Set();
    while (i++ < array.length) {
        const next = array.filter(a => !yielded.has(a)).reduce((a, b) => (cmp(a, b) < 0 ? a : b));
        yielded.add(next);
        yield next;
    }
}

function createPairs(participants, exclusions, { disallowDuplexPairing = false } = {}) {
    const _exclusions = { ...exclusions };
    for (const participant of participants) {
        if (!_exclusions[participant]) {
            _exclusions[participant] = [];
        }
    }
    const allowedPairings = Object.fromEntries(
        participants.map(participant => [
            participant,
            participants
                .filter(p => p !== participant)
                .filter(p => !_exclusions[participant].includes(p)),
        ])
    );

    const pairings = {};
    const randomChoice = arr => arr[Math.floor(Math.random() * arr.length)];
    const generator = priorityIterator(
        participants,
        (a, b) => allowedPairings[a].length - allowedPairings[b].length
    );

    for (const gifter of generator) {
        const giftee = randomChoice(allowedPairings[gifter]);
        if (!giftee) {
            return false;
        }
        pairings[gifter] = giftee;
        for (const participant of participants) {
            allowedPairings[participant] = allowedPairings[participant].filter(p => p !== giftee);
        }
        if (disallowDuplexPairing) {
            allowedPairings[giftee] = allowedPairings[giftee].filter(p => p !== gifter);
        }
    }

    return pairings;
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
    let pairs = null;
    while (!(pairs = createPairs(participantList, JSON.parse(exclusions), { disallowDuplexPairing: true })));
    try {
        const pairString = JSON.stringify(pairs);
        db.prepare('INSERT INTO games(participants,admin,pairs,name,budget) VALUES (?,?,?,?,?)').run(participants_s, req.session.user.username, pairString, name, budget);
        res.send({ msg: "Ok" });
    }
    catch (e) {
        res.send({ msg: e.message });
    }
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
    const { name } = req.body;
    const row = db.prepare('SELECT * FROM games WHERE name=?').get(name);
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