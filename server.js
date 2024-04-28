const express = require('express');
const jwt = require('jsonwebtoken');
const rateLimit = require('express-rate-limit');
const { body, validationResult } = require('express-validator');
const mongoose = require('mongoose');
const crypto = require('crypto');

const cors = require('cors');


const app = express();
app.use(express.json());
app.use(cors());
mongoose.connect("mongodb+srv://sahu86744:password121@cluster0.ciixm9b.mongodb.net/?retryWrites=true&w=majority&appName=Cluster0")

mongoose.connection.on('connected', () => {
    console.log('MongoDB connected!');
});

// Define a Mongoose schema for nonces
const nonceSchema = new mongoose.Schema({
    nonce: { type: String, unique: true, required: true },
    uuid: { type: String, required: true },
    used: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now, expires: 60 * 60 } // Expires after 1 hour
});

const scoreSchema = new mongoose.Schema({
    uuid: { type: String, required: true },
    score: { type: Number, required: true },
    nonce: { type: String, required: true, unique: true },
    createdAt: { type: Date, default: Date.now }
});

// Create models from schemas
const Score = mongoose.model('Score', scoreSchema);
const Nonce = mongoose.model('Nonce', nonceSchema);

// Middleware for rate limiting
const submitScoreLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 100
});

// Middleware to validate token
const tokenValidationMiddleware = async (req, res, next) => {
    const { token } = req.body;
    if (!token || !(await isValidToken(token))) {
        return res.status(401).json({ error: 'Invalid or missing token' });
    }
    next();
};

// Function to validate token
async function isValidToken(token) {
    try {
        const decoded = jwt.verify(token, 'your_jwt_secret');
        return decoded && decoded.user;
    } catch (error) {
        return false;
    }
}

// Function to generate a new nonce
function generateNonce() {
    return crypto.randomBytes(16).toString('hex');
}

// Function to check and invalidate a nonce
async function checkNonce(nonceValue) {
    const nonce = await Nonce.findOne({ nonce: nonceValue, used: false });
    console.log(nonce)
    if (nonce) {
        nonce.used = true;
        await nonce.save();
        return true;
    } else {
        return false;
    }
}

// Function to save the nonce when a session starts
async function saveNonce(nonceValue) {
    const nonce = new Nonce({ nonce: nonceValue });
    await nonce.save();
}

// Function to save score to database
async function saveScoreToDatabase(uuid, scoreValue, nonceValue) {
    const score = new Score({
        uuid,
        score: scoreValue,
        nonce: nonceValue
    });
    await score.save();
}
// Route for submitting scores
app.post('/submit-score',
    submitScoreLimiter,
    // tokenValidationMiddleware,
    body('score').isInt({ min: 0, max: 1000 }),
    async (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        const { uuid, score, nonce } = req.body;
        if (!uuid) {
            return res.status(400).json({ error: 'UUID is required' });
        }

        // Check the nonce
        if (!await checkNonce(nonce)) {
            return res.status(400).json({ error: 'Invalid nonce' });
        }

        // Save the score
        await saveScoreToDatabase(uuid, score, nonce);

        res.json({ message: 'Score submitted successfully' });
    }
);


async function checkActiveSession(req, res, next) {
    const { uuid } = req.body;
    console.log(uuid, "Checking active session");
    if (!uuid) {
        return res.status(400).json({ error: 'UUID is required' });
    }

    try {
        // Check if there's an existing, unused nonce for this UUID
        const existingNonce = await Nonce.findOne({ uuid });
        console.log(existingNonce)
        if (existingNonce) {
            return res.status(409).json({ error: 'Active session already exists for this UUID' });
        }
        next();
    } catch (error) {
        console.error('Error checking for existing nonce:', error);
        res.status(500).json({ error: 'Internal server error' });
    }
}

app.post('/start-session', checkActiveSession, async (req, res) => {
    const { uuid } = req.body;
    if (!uuid) {
        return res.status(400).json({ error: 'UUID is required' });
    }



    const nonceValue = generateNonce();
    const nonce = new Nonce({ nonce: nonceValue, uuid: uuid });
    await nonce.save();

    res.json({ nonce: nonceValue });
});

// Start the server
const port = 8000;
app.listen(port, () => {
    console.log(`Server is running on port ${port}`);
});
