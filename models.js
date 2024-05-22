const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({ name: String, password: String });
const User = mongoose.model('User', userSchema);

const discountSchema = new mongoose.Schema({
    description: String,
    expiryDate: Date
});

const dealSchema = new mongoose.Schema({
    name: String,
    discounts: [discountSchema],
    imageUrl: String,
    details: String
});

const Deal = mongoose.model('Deal', dealSchema);
module.exports = { User, Deal };