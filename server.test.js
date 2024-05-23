// test/server.test.js

import 'dotenv/config';
import chai from 'chai';
import chaiHttp from 'chai-http';
import mongoose from 'mongoose';
import server from '../server'; // Adjust the path as necessary
import { User, Organization, Admin } from '../models'; // Adjust the path as necessary

const expect = chai.expect;
chai.use(chaiHttp);

const dbURI = process.env.MONGODB_URI;

mongoose.connect(dbURI, {
    useNewUrlParser: true,
    useUnifiedTopology: true
});

const db = mongoose.connection;

db.on('error', console.error.bind(console, 'connection error:'));

before(async () => {
    await new Promise((resolve, reject) => {
        db.once('open', async () => {
            console.log('Connected to MongoDB');

            try {
                // Clean the database
                await User.deleteMany({});
                await Organization.deleteMany({});
                await Admin.deleteMany({});

                // Insert initial data
                await insertOrganizations();
                await insertAdminInfo();

                resolve();
            } catch (error) {
                reject(error);
            }
        });
    });
});

after(async () => {
    await mongoose.disconnect();
});

async function insertOrganizations() {
    const organizations = [
        { name: 'Organization 1', discounts: [] },
        { name: 'Organization 2', discounts: [] }
    ];
    await Organization.insertMany(organizations);
}

async function insertAdminInfo() {
    const admin = new Admin({ pin: '1234', imageUrl: '' });
    await admin.save();
}

describe('Server', () => {
    describe('GET /', () => {
        it('should return Hello World!', (done) => {
            chai.request(server)
                .get('/')
                .end((err, res) => {
                    expect(res).to.have.status(200);
                    expect(res.text).to.equal('Hello World!');
                    done();
                });
        });
    });

    describe('POST /signup', () => {
        it('should register a new user', (done) => {
            const newUser = {
                email: 'test@example.com',
                password: 'password123'
            };

            chai.request(server)
                .post('/signup')
                .send(newUser)
                .end((err, res) => {
                    expect(res).to.have.status(201);
                    expect(res.text).to.equal('User registered successfully');
                    done();
                });
        });

        it('should not register a user with an existing email', (done) => {
            const existingUser = {
                email: 'test@example.com',
                password: 'password123'
            };

            chai.request(server)
                .post('/signup')
                .send(existingUser)
                .end((err, res) => {
                    expect(res).to.have.status(500);
                    done();
                });
        });
    });

    describe('POST /login', () => {
        it('should log in a user with valid credentials', (done) => {
            const user = {
                email: 'test@example.com',
                password: 'password123'
            };

            chai.request(server)
                .post('/login')
                .send(user)
                .end((err, res) => {
                    expect(res).to.have.status(200);
                    expect(res.body).to.have.property('token');
                    done();
                });
        });

        it('should not log in a user with invalid credentials', (done) => {
            const user = {
                email: 'test@example.com',
                password: 'wrongpassword'
            };

            chai.request(server)
                .post('/login')
                .send(user)
                .end((err, res) => {
                    expect(res).to.have.status(401);
                    expect(res.text).to.equal('Authentication failed');
                    done();
                });
        });
    });
});
