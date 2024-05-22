require('dotenv').config();

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const express = require('express');

const mongoose = require('mongoose');
const { User, Deal } = require('./models.cjs');
const bodyParser = require('body-parser');
mongoose.connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true });
const port = process.env.PORT || 3000;

const app = express();
app.use(bodyParser.json());

const db = mongoose.connection;
db.on('error', console.error.bind(console, 'connection error:')); db.once('open', () => { console.log('Connected to database'); });
db.once('open', function () {
    console.log('Connected to MongoDB');
    insertDeals();
});

function insertDeals() {
    const categoriesImages = {
        sushi: 'https://res.cloudinary.com/dguy8o0uf/image/upload/v1713049742/sushi_jvq1fd.jpg',
        pizza: 'https://res.cloudinary.com/dguy8o0uf/image/upload/v1713125530/apple-event.64d9fae8.jpeg_3_yp2vr4.png',
        hardware: 'https://res.cloudinary.com/dguy8o0uf/image/upload/v1713296001/Screenshot_2024-04-16_at_3.28.36_PM_mhwywi.png',
        flowers: 'https://res.cloudinary.com/dguy8o0uf/image/upload/v1713296229/Screenshot_2024-04-16_at_3.35.42_PM_gkzohv.png',
        mexican: 'https://res.cloudinary.com/dguy8o0uf/image/upload/v1713297149/Screenshot_2024-04-16_at_3.50.56_PM_y3ug2l.png',
        greek: 'https://res.cloudinary.com/dguy8o0uf/image/upload/v1713297346/Screenshot_2024-04-16_at_3.55.21_PM_evwsr3.png',
        red_socks: "https://res.cloudinary.com/dguy8o0uf/image/upload/v1713297502/Screenshot_2024-04-16_at_3.57.58_PM_nkf1pf.png",
        theater: 'https://res.cloudinary.com/dguy8o0uf/image/upload/v1713297595/Screenshot_2024-04-16_at_3.59.07_PM_redpgs.png',
        gym: 'https://res.cloudinary.com/dguy8o0uf/image/upload/v1713297686/Screenshot_2024-04-16_at_4.00.32_PM_n8zi4l.png',
    }

    const deals = [
        {
            id: 1,
            name: 'Tenderoni\'s',
            discounts: [('Free Fries with purchase of $10+', new Date(2025, 4, 4)), ('20% off any meal', new Date(2025, 4, 4)), ("Buy one get one free", new Date(2025, 4, 4)), ("25% off your next order", new Date(2025, 4, 4)), ("50% off a side of fries", new Date(2025, 4, 4))],
            imageUrl: categoriesImages.pizza
        },
        {
            id: 2,
            name: 'Economy True Value',
            discounts: [('10% discount', null)],
            imageUrl: categoriesImages.hardware
        },
        {
            id: 3,
            name: 'Fern Flowers',
            discounts: [('10% discount', null)],
            imageUrl: categoriesImages.flowers
        },
        {
            id: 4,
            name: 'El Pelon Taqueria',
            discounts: [("A free 'Mountain Dew' drink with $10 purchase", null)],
            imageUrl: categoriesImages.mexican
        },
        {
            id: 5,
            name: 'Saloniki Greek',
            discounts: [("Enjoy free fries with purchase of $10+", null)],
            details: 'This offer is only valid at the Fenway location',
            imageUrl: categoriesImages.greek
        },
        {
            id: 6,
            name: 'Basho Japanese Brasserie',
            discounts: [('10% off any catering order of $100+', null)],
            imageUrl: categoriesImages.sushi
        },
        {
            id: 7,
            name: 'Huntington Theater',
            discounts: [("$20 tickets", null)],
            imageUrl: categoriesImages.theater
        },
        {
            id: 8,
            name: 'YMCA Huntington',
            discounts: [("10% off YMCA membership", null)],
            imageUrl: categoriesImages.gym
        },
        {
            id: 9,
            name: 'Boston Red Sox',
            discounts: [("Free tickets for Neighborhood Night Red Sox games, movie nights, and other events", null)],
            details: "Giveaways are organized for members by the Fenway CDC team when tickets are available",
            imageUrl: categoriesImages.red_socks
        },];

    Deal.insertMany(deals)
        .then(() => console.log('Deals inserted successfully'))
        .catch(err => console.error('Failed to insert deals', err));
}

const secretKey = process.env.JWT_SECRET_KEY;
const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 10;

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login requests per windowMs
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

app.use(helmet());

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

// Ensure database connection is secure
mongoose.connection.on('error', err => {
    console.log('Mongoose connection error:', err.message);
});

app.get('/', (req, res) => { res.send('Hello World!'); });
// Listen on the configured port
app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});

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

app.use((req, res, next) => {
    // Exclude the login and signup routes from token authentication
    if (req.path === '/login' || req.path === '/signup') {
        return next();
    }

    const token = req.headers['authorization']?.split(' ')[1]; // Bearer Token
    if (!token) {
        return res.status(401).json({ error: 'Access denied. No token provided.' });
    }

    try {
        const decoded = verifyToken(token);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Invalid token.' });
    }
});


// gets all users
app.get('/users', (req, res) => { User.find((err, users) => { if (err) return console.error(err); res.send(users); }); });

// updates existing user
app.put('/users/:id', (req, res) => { User.findOneAndUpdate({ _id: req.params.id }, { $set: req.body }, { new: true }, (err, user) => { if (err) return console.error(err); res.send(user); }); });

// deletes user
app.delete('/users/:id', (req, res) => { User.findOneAndDelete({ _id: req.params.id }, (err, user) => { if (err) return console.error(err); res.send(user); }); });

// Create a new deal
app.post('/deals', async (req, res) => {
    const deal = new Deal(req.body);
    try {
        await deal.save();
        res.status(201).send(deal);
    } catch (error) {
        res.status(400).send(error);
    }
});

// Get all deals
app.get('/deals', async (req, res) => {
    try {
        const deals = await Deal.find();
        res.status(200).json(deals);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Update a deal
app.put('/deals/:id', async (req, res) => {
    try {
        const deal = await Deal.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!deal) {
            return res.status(404).send();
        }
        res.send(deal);
    } catch (error) {
        res.status(400).send(error);
    }
});

// Delete a deal
app.delete('/deals/:id', async (req, res) => {
    try {
        const deal = await Deal.findByIdAndDelete(req.params.id);
        if (!deal) {
            return res.status(404).send();
        }
        res.send(deal);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Add a discount to a specific deal
app.post('/deals/:id/discounts', async (req, res) => {
    const { discount } = req.body;
    try {
        const deal = await Deal.findById(req.params.id);
        if (!deal) {
            return res.status(404).send('Deal not found');
        }
        deal.discounts.push(discount); // assuming discounts is an array in your Deal schema
        await deal.save();
        res.status(201).send(deal);
    } catch (error) {
        res.status(400).send(error);
    }
});

// Get all discounts for a specific deal
app.get('/deals/:id/discounts', async (req, res) => {
    try {
        const deal = await Deal.findById(req.params.id);
        if (!deal) {
            return res.status(404).send('Deal not found');
        }
        res.status(200).send(deal.discounts);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Update a discount within a deal
app.put('/deals/:dealId/discounts/:discountId', async (req, res) => {
    try {
        const deal = await Deal.findById(req.params.dealId);
        if (!deal) {
            return res.status(404).send('Deal not found');
        }
        const discount = deal.discounts.id(req.params.discountId); // assuming discounts are stored with _id in mongoose
        if (!discount) {
            return res.status(404).send('Discount not found');
        }
        discount.set(req.body);
        await deal.save();
        res.send(deal);
    } catch (error) {
        res.status(400).send(error);
    }
});

// Delete a discount from a deal
app.delete('/deals/:dealId/discounts/:discountId', async (req, res) => {
    try {
        const deal = await Deal.findById(req.params.dealId);
        if (!deal) {
            return res.status(404).send('Deal not found');
        }
        const discount = deal.discounts.id(req.params.discountId);
        if (!discount) {
            return res.status(404).send('Discount not found');
        }
        discount.remove();
        await deal.save();
        res.send(deal);
    } catch (error) {
        res.status(500).send(error);
    }
});

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

function authenticateToken(req, res, next) {
    const token = req.headers['authorization']?.split(' ')[1]; // Assume Bearer Token
    if (!token) {
        return res.status(401).json({ error: 'No token provided' });
    }

    try {
        const decoded = verifyToken(token);
        req.user = decoded;
        next();
    } catch (error) {
        return res.status(403).json({ error: 'Failed to authenticate token' });
    }
}

function verifyToken(token) {
    try {
        return jwt.verify(token, secretKey);
    } catch (error) {
        return null;
    }
}
