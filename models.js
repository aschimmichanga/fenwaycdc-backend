const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({ name: String, password: String });
const User = mongoose.model('User', userSchema);

const discountSchema = new mongoose.Schema({
    description: String,
    expiry: Date
});

const dealSchema = new mongoose.Schema({
    name: String,
    discounts: [discountSchema],
    imageUrl: String,
    details: String
});

const Deal = mongoose.model('Deal', dealSchema);

const organizationSchema = new mongoose.Schema({
    name: String,
    imageUrl: String,
    deals: [dealSchema]
});

const Organization = mongoose.model('Organization', organizationSchema);
module.exports = { User, Deal, Organization };