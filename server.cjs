require('dotenv').config();

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const express = require('express');
const app = express();
const mongoose = require('mongoose');
const User = require('./models.cjs');
mongoose.connect('mongodb://localhost:27017/myapp', { useNewUrlParser: true, useUnifiedTopology: true });
const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:')); db.once('open', () => { console.log('Connected to database'); });


const secretKey = process.env.JWT_SECRET_KEY;
const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 10;

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login requests per windowMs
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

app.use(helmet());

app.get('/', (req, res) => { res.send('Hello World!'); });
app.listen(3000, () => { console.log('Server running on port 3000'); });

app.post('/login', loginLimiter, async (req, res) => {
    const { email, password } = req.body;
    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(401).send('Authentication failed');
        }

        const isMatch = await checkPassword(password, user.password);
        if (!isMatch) {
            return res.status(401).send('Authentication failed');
        }

        const token = generateToken(user);
        res.status(200).json({ token });
    } catch (error) {
        console.error('Login error:', error); // Log the error
        res.status(500).send('Internal server error');
    }
});

app.post('/signup', async (req, res) => {
    const { email, password } = req.body;
    try {
        const hashedPassword = await hashPassword(password);
        const newUser = new User({ email, password: hashedPassword });
        await newUser.save();
        res.status(201).send('User registered successfully');
    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).send('Internal server error');
    }
});


// gets all users
app.get('/users', (req, res) => { User.find((err, users) => { if (err) return console.error(err); res.send(users); }); });

// updates existing user
app.put('/users/:id', (req, res) => { User.findOneAndUpdate({ _id: req.params.id }, { $set: req.body }, { new: true }, (err, user) => { if (err) return console.error(err); res.send(user); }); });

// deletes user
app.delete('/users/:id', (req, res) => { User.findOneAndDelete({ _id: req.params.id }, (err, user) => { if (err) return console.error(err); res.send(user); }); });

async function hashPassword(password) {
    const salt = await bcrypt.genSalt(saltRounds);
    const hash = await bcrypt.hash(password, salt);
    return hash;
}

async function checkPassword(password, hash) {
    return bcrypt.compare(password, hash);
}

function generateToken(user) {
    return jwt.sign({ id: user.id, email: user.email }, secretKey, {
        expiresIn: '1h',
        issuer: 'FenwayCDCApp', // Optional: Specify the issuer
        audience: 'FenwayCDCMembers' // Optional: Specify the audience
    });
}

function verifyToken(token) {
    try {
        return jwt.verify(token, secretKey);
    } catch (error) {
        return null;
    }
}
