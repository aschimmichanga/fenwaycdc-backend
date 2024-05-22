const mongoose = require('mongoose');

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
module.exports = { User, Organization };