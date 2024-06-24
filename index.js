// index.js
const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
app.use(bodyParser.json());

// Database Connection
mongoose.connect('mongodb://localhost:27017/login-signup-db', {
    useNewUrlParser: true,
    useUnifiedTopology: true
}).then(() => console.log('MongoDB connected'))
  .catch(err => console.log(err));

// User Schema
const UserSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true },
    password: { type: String, required: true }
});

const User = mongoose.model('User', UserSchema);

// Signup Route
app.post('/signup', async (req, res) => {
    const { username, password } = req.body;
    try {
        const hashedPassword = await bcrypt.hash(password, 10);
        const newUser = new User({ username, password: hashedPassword });
        await newUser.save();
        res.status(201).send('User registered successfully');
    } catch (err) {
        res.status(500).send('Error registering new user');
    }
});

// Login Route
app.post('/login', async (req, res) => {
    const { username, password } = req.body;
    try {
        const user = await User.findOne({ username });
        if (!user) return res.status(400).send('Invalid username or password');
        
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) return res.status(400).send('Invalid username or password');
        
        const token = jwt.sign({ id: user._id }, 'secretkey');
        res.json({ token });
    } catch (err) {
        res.status(500).send('Error logging in user');
    }
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
