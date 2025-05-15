require('dotenv').config();
const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');

const app = express();
const port = process.env.PORT || 3000;

// ✅ MongoDB connection
const mongoURI = process.env.MONGO_URI;
if (!mongoURI) {
    console.error('❌ MongoDB URI is missing. Please check your .env file');
    process.exit(1);
}

mongoose.connect(mongoURI)
    .then(() => console.log('✅ Connected to MongoDB Atlas'))
    .catch(err => {
        console.error('❌ MongoDB connection error:', err.message);
        process.exit(1);
    });

// ✅ Schema
const userSchema = new mongoose.Schema({
    username: { type: String, required: true, unique: true, minlength: 3, maxlength: 30 },
    password: { type: String, required: true, minlength: 6 },
    createdAt: { type: Date, default: Date.now },
    lastLogin: Date
});

// ✅ Password hashing
userSchema.pre('save', async function(next) {
    if (!this.isModified('password')) return next();
    try {
        const salt = await bcrypt.genSalt(10);
        this.password = await bcrypt.hash(this.password, salt);
        next();
    } catch (err) {
        next(err);
    }
});

const User = mongoose.model('User', userSchema);

// ✅ CORS setup for Vercel and local
const allowedOrigins = ['https://arts-wave.vercel.app'];

app.use(cors({
    origin: function(origin, callback) {
        if (!origin || allowedOrigins.includes(origin)) {
            callback(null, true);
        } else {
            callback(new Error('Not allowed by CORS'));
        }
    },
    credentials: true
}));

app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

// *** Removed all static file serving lines below ***
// app.use('/assets', express.static(path.join(__dirname, '../client/assets'), { maxAge: '1y' }));
// app.use(express.static(path.join(__dirname, '../client')));

// app.get('/', (req, res) => {
//     res.sendFile(path.join(__dirname, '../client/index.html'));
// });

// ✅ Register Route
app.post('/api/register', async(req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    try {
        const existingUser = await User.findOne({ username });
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'Username already exists' });
        }

        const newUser = new User({ username, password });
        await newUser.save();

        res.status(201).json({
            success: true,
            message: 'User registered successfully',
            user: {
                username: newUser.username,
                createdAt: newUser.createdAt
            }
        });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during registration' });
    }
});

// ✅ Login Route (no JWT, returns fake token)
app.post('/api/login', async(req, res) => {
    const { username, password } = req.body;
    if (!username || !password) {
        return res.status(400).json({ success: false, message: 'Username and password are required' });
    }

    try {
        const user = await User.findOne({ username });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        user.lastLogin = Date.now();
        await user.save();

        // Send mock token
        res.json({
            success: true,
            message: 'Login successful',
            token: 'mock-token-12345',
            user: {
                username: user.username,
                lastLogin: user.lastLogin
            }
        });
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ success: false, message: 'Internal server error during login' });
    }
});

// ✅ 404 Handler
app.use((req, res) => {
    res.status(404).json({ success: false, message: 'Endpoint not found' });
});

// ✅ Server Start
app.listen(port, () => {
    console.log(`🚀 Server running on port ${port}`);
});