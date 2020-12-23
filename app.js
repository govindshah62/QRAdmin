const express = require("express");
const cors = require("cors");
const compression = require("compression");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const connectDB = require('./database/serverMongo');

require('dotenv').config({path:'./config.env'});
const app = express();
connectDB();
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(cors());
app.use(compression());
app.use(helmet());


const limiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 100, // 7 requests,
});
app.use(limiter);

//importing routers
const company = require('./routes/company');
//calling route
app.use('/v1',company);


const port = process.env.PORT || 5000;
app.listen(port, () => {
  console.log(`Application is running on port ${port}`);
});