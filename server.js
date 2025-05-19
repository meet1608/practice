const express = require('express');
const connectdb = require('./config/db.js');
require('dotenv').config();
const authRoutes = require('./routes/auth.js');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());
connectdb();
app.use('/api/auth', authRoutes);
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
});