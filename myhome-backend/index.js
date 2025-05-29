const express = require('express');
const app = express();
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcrypt');
require('dotenv').config();

const PORT = process.env.PORT || 3000;

// Middleware
//app.use(cors());
app.use(cors({
  origin: ['https://myhomedesigner.xyz', 'https://www.myhomedesigner.xyz'], 
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

app.use(express.json());

const authRoutes = require('./routes/auth');
app.use('/api', authRoutes);

const projectRoutes = require("./routes/projects");
app.use("/api/projects", projectRoutes);

console.log('MONGO_URI:', process.env.MONGO_URI);

// MongoDB connection
mongoose.connect(process.env.MONGO_URI);


// Test route
app.get('/', (req, res) => {
    res.send('My Home Designer Backend is running');
});

app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
});


