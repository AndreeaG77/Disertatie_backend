const express = require('express');
const bcrypt = require('bcrypt');
const User = require('../models/User');
const router = express.Router();
const jwt = require("jsonwebtoken");
const crypto = require('crypto');
const { sendResetPasswordEmail } = require('../mailer');
const Project = require("../models/Project");


// POST /register
router.post('/register', async (req, res) => {
    const { email, password } = req.body;

    try {
        const existingUser = await User.findOne({ email });
        if (existingUser) {
            return res.status(400).json({ message: 'Email already exists' });
        }

        const passwordHash = await bcrypt.hash(password, 10);

        const newUser = new User({
            email,
            passwordHash,
        });

        await newUser.save();
        res.status(201).json({ message: 'User created successfully' });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

// POST /login
router.post('/login', async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const isMatch = await bcrypt.compare(password, user.passwordHash);
        if (!isMatch) {
            return res.status(400).json({ message: 'Invalid email or password' });
        }

        const token = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "2h" }
        );
        
        res.status(200).json({
            message: 'Login successful',
            token: token,
        });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Server error' });
    }
});

router.get("/validate-token", async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1]; 

    if (!token) {
        return res.status(401).json({ message: "Token missing" });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId).select("-passwordHash");

        if (!user) {
            return res.status(404).json({ message: "User not found" });
        }

        res.status(200).json({ user });
    } catch (err) {
        res.status(401).json({ message: "Invalid or expired token" });
    }
});

// Token-based login
router.post('/token-login', async (req, res) => {
    const { email, token } = req.body;

    if (!email || !token) {
        return res.status(400).json({ message: 'Missing email or token' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);

        if (decoded.email !== email) {
            return res.status(401).json({ message: 'Token does not match email' });
        }

        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }

        res.status(200).json({
            message: 'Token login successful',
            userId: user._id,
            email: user.email,
            token
        });

    } catch (err) {
        console.error(err);
        return res.status(401).json({ message: 'Invalid or expired token' });
    }
});

// POST /api/reset-password
router.post('/reset-password', async (req, res) => {
    const { email } = req.body;

    try {
        const user = await User.findOne({ email });
        if (!user) {
            return res.status(404).json({ message: 'User not found' });
        }
        const newPassword = generateSecurePassword(10);
        const hashedPassword = await bcrypt.hash(newPassword, 10);

        user.passwordHash = hashedPassword;
        await user.save();

        await sendResetPasswordEmail(email, newPassword);

        res.status(200).json({ message: 'New password sent to email' });
    } catch (err) {
        console.error('Reset error:', err);
        res.status(500).json({ message: 'Something went wrong' });
    }
});

function generateSecurePassword(length = 10) {
    const charset = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
    const passwordArray = Array.from(crypto.randomBytes(length)).map(
        (byte) => charset[byte % charset.length]
    );
    return passwordArray.join('');
}

router.delete('/delete-account', async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];

    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.userId;

        await User.findByIdAndDelete(userId);
        await Project.deleteMany({ userId }); 

        res.status(200).json({ message: 'Account deleted' });
    } catch (err) {
        console.error('Delete error:', err);
        res.status(500).json({ message: 'Something went wrong' });
    }
});

router.post('/update-email', async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    const { email } = req.body;

    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);

        const existing = await User.findOne({ email });
        if (existing && existing._id.toString() !== user._id.toString()) {
            return res.status(400).json({ message: 'Email already in use' });
        }

        user.email = email;
        await user.save();

        const newToken = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "2h" }
        );

        res.status(200).json({ message: 'Email updated', token: newToken });
    } catch (err) {
        console.error('Email update error:', err);
        res.status(500).json({ message: 'Something went wrong' });
    }
});


router.post('/change-password', async (req, res) => {
    const token = req.headers.authorization?.split(" ")[1];
    const { oldPassword, newPassword } = req.body;

    if (!token) return res.status(401).json({ message: 'Unauthorized' });

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const user = await User.findById(decoded.userId);

        const isMatch = await bcrypt.compare(oldPassword, user.passwordHash);
        if (!isMatch) {
            return res.status(401).json({ message: 'Incorrect old password' });
        }

        const newHash = await bcrypt.hash(newPassword, 10);
        user.passwordHash = newHash;
        await user.save();

        const newToken = jwt.sign(
            { userId: user._id, email: user.email },
            process.env.JWT_SECRET,
            { expiresIn: "2h" }
        );

        res.status(200).json({ message: 'Password changed', token: newToken });

    } catch (err) {
        console.error(err);
        res.status(500).json({ message: 'Something went wrong' });
    }
});



module.exports = router;
