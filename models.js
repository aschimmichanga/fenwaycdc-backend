const mongoose = require('mongoose');

const adminSchema = new mongoose.Schema({
    pin: { type: String },
    imageUrl: { type: String }
});

const Admin = mongoose.model('Admin', adminSchema);

const userSchema = new mongoose.Schema({ name: String, password: String });
const User = mongoose.model('User', userSchema);

const discountSchema = new mongoose.Schema({
    description: String,
    expiry: Date
});

const organizationSchema = new mongoose.Schema({
    name: String,
    discounts: [discountSchema],
    imageUrl: String,
    details: String
});

const Organization = mongoose.model('Organization', organizationSchema);
module.exports = { User, Organization, Admin };