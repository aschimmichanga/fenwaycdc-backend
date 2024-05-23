require('dotenv').config();

const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const express = require('express');
const { User, Organization, Admin } = require('./models');
const db = require('./db');
const morgan = require('morgan');
const bodyParser = require('body-parser');
const port = process.env.PORT || 3000;

const app = express();
app.use(bodyParser.json());
app.use(express.urlencoded({ extended: true }));
app.use(helmet());
app.use(morgan('combined'));

const secretKey = process.env.JWT_SECRET_KEY;
const saltRounds = parseInt(process.env.BCRYPT_SALT_ROUNDS, 10) || 10;

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5, // limit each IP to 5 login requests per windowMs
    message: 'Too many login attempts from this IP, please try again after 15 minutes'
});

app.use((err, req, res, next) => {
    console.error(err.stack);
    res.status(500).send('Something broke!');
});

app.get('/', (req, res) => {
    res.send('Hello World!');
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

// User routes
app.get('/users', async (req, res) => {
    try {
        const users = await User.find();
        res.send(users);
    } catch (error) {
        res.status(500).send(error);
    }
});

app.put('/users/:id', async (req, res) => {
    try {
        const user = await User.findByIdAndUpdate(req.params.id, req.body, { new: true });
        res.send(user);
    } catch (error) {
        res.status(500).send(error);
    }
});

app.delete('/users/:id', async (req, res) => {
    try {
        const user = await User.findByIdAndDelete(req.params.id);
        res.send(user);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Organization routes
app.post('/organizations', async (req, res) => {
    const organization = new Organization(req.body);
    try {
        await organization.save();
        res.status(201).send(organization);
    } catch (error) {
        res.status(400).send(error);
    }
});

app.get('/organizations', async (req, res) => {
    try {
        const organizations = await Organization.find();
        res.status(200).json(organizations);
    } catch (error) {
        res.status(500).send(error);
    }
});

app.put('/organizations/:id', async (req, res) => {
    try {
        const organization = await Organization.findByIdAndUpdate(req.params.id, req.body, { new: true });
        if (!organization) {
            return res.status(404).send();
        }
        res.send(organization);
    } catch (error) {
        res.status(400).send(error);
    }
});

app.delete('/organizations/:id', async (req, res) => {
    try {
        const organization = await Organization.findByIdAndDelete(req.params.id);
        if (!organization) {
            return res.status(404).send();
        }
        res.send(organization);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Discount routes within an organization
app.post('/organizations/:id/discounts', async (req, res) => {
    const { discount } = req.body;
    try {
        const organization = await Organization.findById(req.params.id);
        if (!organization) {
            return res.status(404).send('Organization not found');
        }
        organization.discounts.push(discount); // assuming discounts is an array in your Organization schema
        await organization.save();
        res.status(201).send(organization);
    } catch (error) {
        res.status(400).send(error);
    }
});

app.get('/organizations/:id/discounts', async (req, res) => {
    try {
        const organization = await Organization.findById(req.params.id);
        if (!organization) {
            return res.status(404).send('Organization not found');
        }
        res.status(200).send(organization.discounts);
    } catch (error) {
        res.status(500).send(error);
    }
});

app.put('/organizations/:organizationId/discounts/:discountId', async (req, res) => {
    try {
        const organization = await Organization.findById(req.params.organizationId);
        if (!organization) {
            return res.status(404).send('Organization not found');
        }
        const discount = organization.discounts.id(req.params.discountId);
        if (!discount) {
            return res.status(404).send('Discount not found');
        }
        discount.set(req.body);
        await organization.save();
        res.send(organization);
    } catch (error) {
        res.status(400).send(error);
    }
});

app.delete('/organizations/:organizationId/discounts/:discountId', async (req, res) => {
    try {
        const organization = await Organization.findById(req.params.organizationId);
        if (!organization) {
            return res.status(404).send('Organization not found');
        }
        const discount = organization.discounts.id(req.params.discountId);
        if (!discount) {
            return res.status(404).send('Discount not found');
        }
        discount.remove();
        await organization.save();
        res.send(organization);
    } catch (error) {
        res.status(500).send(error);
    }
});

// Admin routes
app.post('/admin/verify-pin', async (req, res) => {
    const { pin } = req.body;

    try {
        const admin = await Admin.findOne();
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        if (admin.pin !== pin) {
            return res.status(401).send('Invalid PIN');
        }

        res.status(200).send('PIN verified');
    } catch (error) {
        res.status(500).send(error);
    }
});

app.put('/admin/image', async (req, res) => {
    const { imageUrl } = req.body;

    try {
        const admin = await Admin.findOne();
        if (!admin) {
            return res.status(404).send('Admin not found');
        }

        admin.imageUrl = imageUrl;
        await admin.save();

        res.status(200).send(admin);
    } catch (error) {
        res.status(500).send(error);
    }
});

app.get('/admin/image', async (req, res) => {
    try {
        const admin = await Admin.findOne();
        res.status(200).json({ imageUrl: admin.imageUrl });
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

function verifyToken(token) {
    try {
        return jwt.verify(token, secretKey);
    } catch (error) {
        return null;
    }
}

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
