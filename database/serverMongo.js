const mongoose = require('mongoose');
const {returnErrorJsonResponse,statusCode} = require('../Helpers/status')

const serverDB = async () => {
    try {
        await mongoose.connect(process.env.SERVER_URI, {
            useNewUrlParser: true,
            useUnifiedTopology: true,
            useCreateIndex: true,
            useFindAndModify: false
        });
    } catch (error) {
        console.log(error)
        return returnErrorJsonResponse(
            statusCode.bad,
            "fail",
            "Something went wrong, Please try again",
            error
        );
    }
};
module.exports = serverDB;