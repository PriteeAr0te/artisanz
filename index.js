require('dotenv').config();
const express = require('express');
const connectDB = require('./config/db');
const authRoutes = require('./routes/userRoutes');

const app = express();
connectDB();
app.use(express.json());

app.get('/', (req, res) => {
    res.send('API is running...');
});

app.use('/api/auth', authRoutes);

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => console.log(`Server Running on Port ${PORT}`));