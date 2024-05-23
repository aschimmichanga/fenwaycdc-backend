import mongoose from 'mongoose';

const adminSchema = new mongoose.Schema({
    pin: { type: String },
    imageUrl: { type: String }
});

export const Admin = mongoose.model('Admin', adminSchema);

const userSchema = new mongoose.Schema({ name: String, password: String });
export const User = mongoose.model('User', userSchema);

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

export const Organization = mongoose.model('Organization', organizationSchema);