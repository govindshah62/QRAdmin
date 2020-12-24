const nodemailer = require('nodemailer');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcrypt');
const UserMaster = require('../models/MasterUser');
const Token = require('../models/Token');
const { encrypt, getRandomString } = require('../Helpers/crypto');
const { statusCode, returnJsonResponse, returnErrorJsonResponse } = require("../Helpers/status.js");
require('dotenv').config({path:'../config.env'});

module.exports.register = async (req, res, next) => {
    try {
        if (!req.body.email || !req.body.option || !req.body.companyName) {
            return res
                .status(statusCode.bad)
                .json(
                    returnErrorJsonResponse(
                        statusCode.nocontent,
                        "fail",
                        "Please enter all the required fileds",
                    )
                );
        }
        UserMaster.findOne({ email: req.body.email }, async (error, user) => {
            if (error) {
                return res
                    .status(statusCode.bad)
                    .json(
                        returnErrorJsonResponse(
                            statusCode.bad,
                            "fail",
                            "Something went wrong, Please try again",
                            error
                        )
                    );
            }
            // if email exist into database
            else if (user) {
                return res
                    .status(statusCode.bad)
                    .json(
                        returnErrorJsonResponse(
                            statusCode.bad,
                            "fail",
                            "This email address is already associated with another account."
                        )
                    );
            }
            else {
                user = new UserMaster({ companyName: req.body.companyName, email: req.body.email, option: req.body.option });
                let gentoken = jwt.sign({ id: user.email }, process.env.JWT_SECRET);
                let token = new Token({ _userId: user._id, token: gentoken });
                //Sending email
                var transporter = nodemailer.createTransport({ service: 'gmail',host: 'smtp.gmail.com', auth: { user: process.env.EMAIL, pass: process.env.PASSWORD } });
                var mailOptions = { from: process.env.EMAIL_FROM, to: user.email, subject: 'Account Verification Link', text: 'Hello ' + req.body.email + ',\n\n' + 'Please verify your account by clicking the link: \nhttp:\/\/' + req.headers.host + '\/v1\/verify\/' + user.email + '\/' + token.token + '\n\nThank You!\nXP-COVER' };
                transporter.sendMail(mailOptions, (error) => {
                    if (error) {
                        return res
                            .status(statusCode.bad)
                            .json(
                                returnErrorJsonResponse(
                                    statusCode.bad,
                                    "fail",
                                    "Technical Issue!, Please click on resend for verify your Email.",
                                    error
                                )
                            );
                    }
                    user.save((error) => {
                        if (error) {
                            return res
                                .status(statusCode.bad)
                                .json(
                                    returnErrorJsonResponse(
                                        statusCode.bad,
                                        "fail",
                                        "Something went wrong, Please try again",
                                        error
                                    )
                                );
                        };
                    });
                    token.save((error) => {
                        if (error) {
                            return res
                                .status(statusCode.bad)
                                .json(
                                    returnErrorJsonResponse(
                                        statusCode.bad,
                                        "fail",
                                        "Something went wrong, Please try again",
                                        error
                                    )
                                );
                        }
                    });
                    return res
                        .status(statusCode.success)
                        .json(
                            returnJsonResponse(
                                statusCode.success,
                                "success",
                                "A verification email has been sent to " + user.email + ". Please check mail to verify your account."
                            )
                        );
                });
            }
        });
    } catch (error) {
        return res
            .status(statusCode.error)
            .json(
                returnErrorJsonResponse(
                    statusCode.error,
                    "fail",
                    "Something went wrong, Please try again",
                    error
                )
            );
    }
};

module.exports.verify = async (req, res, next) => {
    try {
        Token.findOne({ token: req.params.token }, (error, token) => {
            if (error) {
                return res
                    .status(statusCode.bad)
                    .json(
                        returnErrorJsonResponse(
                            statusCode.bad,
                            "fail",
                            "Something went wrong, Please try again",
                            error
                        )
                    );
            }
            // token is not found into database
            else if (!token) {
                return res
                    .status(statusCode.bad)
                    .json(
                        returnErrorJsonResponse(
                            statusCode.bad,
                            "fail",
                            "We were unable to find a email for this verification. Please SignUp!"
                        )
                    );
            }
            // if token is found then check valid email
            else {
                UserMaster.findOne({ _id: token._userId, email: req.params.email }, async (error, user) => {
                    if (error) {
                        return res
                            .status(statusCode.bad)
                            .json(
                                returnErrorJsonResponse(
                                    statusCode.bad,
                                    "fail",
                                    "Something went wrong, Please try again",
                                    error
                                )
                            );
                    }
                    // not valid email
                    else if (!user) {
                        return res
                            .status(statusCode.unauthorized)
                            .json(
                                returnErrorJsonResponse(
                                    statusCode.unauthorized,
                                    "fail",
                                    "We were unable to find a email for this verification. Please SignUp!"
                                )
                            );
                    }
                    // email is already verified
                    else if (user.isVerified) {
                        return res
                            .status(statusCode.unauthorized)
                            .json(
                                returnErrorJsonResponse(
                                    statusCode.unauthorized,
                                    "fail",
                                    "Email has been already verified. Please Login"
                                )
                            );
                    }
                    else {
                        let crypt = {
                            email: req.params.email,
                            option: user.option,
                            companyName:user.companyName,
                            expiryDate: new Date(+user.createdAt+365*24*60*60*1000)
                        };
                        let hash = await encrypt(JSON.stringify(crypt));
                        const salt = await bcrypt.genSalt(10);
                        const password = await bcrypt.hash(req.body.password, salt);
                        user.licenseNo = await getRandomString(hash.content.toUpperCase());
                        user.licenseKey = hash
                        user.password = password;
                        user.isVerified = true;
                        user.isAdmin = true;
                        user.save((error) => {
                            // error occur
                            if (error) {
                                return res
                                    .status(statusCode.bad)
                                    .json(
                                        returnErrorJsonResponse(
                                            statusCode.bad,
                                            "fail",
                                            "Something went wrong, Please try again",
                                            error
                                        )
                                    );
                            }
                            // account successfully verified
                            else {
                                return res
                                    .status(statusCode.success)
                                    .json(
                                        returnJsonResponse(
                                            statusCode.success,
                                            "success",
                                            "Your account has been successfully verified. Please login to setup profile and to get access!"
                                        )
                                    );
                            }
                        });
                    }
                });
            }
        });
    } catch (error) {
        return res
            .status(statusCode.error)
            .json(
                returnErrorJsonResponse(
                    statusCode.error,
                    "fail",
                    "Something went wrong, Please try again",
                    error
                )
            );
    }
};

module.exports.login = async (req, res, next) => {
    try {
        const { email, password } = req.body;
        if (!email || !password) {
            return res
                .status(statusCode.bad)
                .json(
                    returnErrorJsonResponse(
                        statusCode.nocontent,
                        "fail",
                        "Please enter all the required fileds",
                    )
                );
        }
        const user = await UserMaster.findOne({ email });
        if (!user) {
            return res
                .status(statusCode.unauthorized)
                .json(
                    returnErrorJsonResponse(
                        statusCode.unauthorized,
                        "fail",
                        "The email address " + email + " is not associated with any account. please check email and try again!"
                    )
                );
        }
        if (user.isAdmin) {
            if (!user.isVerified) {
                return res
                    .status(statusCode.unauthorized)
                    .json(
                        returnErrorJsonResponse(
                            statusCode.unauthorized,
                            "fail",
                            "Your Email has not been verified. Please check mail to verify your email"
                        )
                    );
            }
        };
        if (!user.password) {
            return res
                .status(statusCode.unauthorized)
                .json(
                    returnErrorJsonResponse(
                        statusCode.unauthorized,
                        "fail",
                        "Your Email has not been verified. Please check mail to verify your email"
                    )
                );
        };
        const ismatched = await bcrypt.compare(password, user.password);
        if (!ismatched) {
            return res
                .status(statusCode.unauthorized)
                .json(
                    returnErrorJsonResponse(
                        statusCode.unauthorized,
                        "fail",
                        "Invalid Credentials"
                    )
                );
        }
        else {
            const token = jwt.sign({ id: user._id }, process.env.JWT_SECRET, { expiresIn: '30d' });
            return res
                .status(statusCode.success)
                .header('Authorization', 'Bearer ' + token)
                .json(
                    returnJsonResponse(
                        statusCode.success,
                        "success",
                        "Successfully logged-in",
                    )
                );
        }
    } catch (error) {
        return res
            .status(statusCode.error)
            .json(
                returnErrorJsonResponse(
                    statusCode.error,
                    "fail",
                    "Something went wrong, Please try again",
                    error
                )
            );
    }
};

module.exports.getAdminUsers = async (req, res, next) => {
    try {
        const user = await UserMaster.find();
        return res
            .status(statusCode.success)
            .json(
                returnJsonResponse(
                    statusCode.success,
                    "success",
                    "Users Fetched Successfully",
                    user
                )
            );
    } catch (error) {
        return res
            .status(statusCode.error)
            .json(
                returnErrorJsonResponse(
                    statusCode.error,
                    "fail",
                    "Something went wrong, Please try again",
                    error
                )
            );
    }
};

module.exports.getlicenseNo = async (req, res, next) => {
    try {
        if (!req.body.email) {
            return res
                .status(statusCode.bad)
                .json(
                    returnErrorJsonResponse(
                        statusCode.nocontent,
                        "fail",
                        "Please enter all the required fileds",
                    )
                );
        }
        const user = await UserMaster.findOne({ email: req.body.email });
        return res
            .status(statusCode.success)
            .json(
                returnJsonResponse(
                    statusCode.success,
                    "success",
                    "Users Fetched Successfully",
                    user.licenseNo
                )
            );
    } catch (error) {
        return res
            .status(statusCode.error)
            .json(
                returnErrorJsonResponse(
                    statusCode.error,
                    "fail",
                    "Something went wrong, Please try again",
                    error
                )
            );
    }
};

module.exports.compareLicenseNo = async (req, res, next) => {
    try {
        if (!req.body.licenseNo) {
            return res
                .status(statusCode.bad)
                .json(
                    returnErrorJsonResponse(
                        statusCode.nocontent,
                        "fail",
                        "Please enter all the required fileds",
                    )
                );
        }
        await UserMaster.findOne({ licenseNo: req.body.licenseNo }, (error, user) => {
            if (error) {
                return res
                    .status(statusCode.bad)
                    .json(
                        returnErrorJsonResponse(
                            statusCode.bad,
                            "fail",
                            "Something went wrong, Please try again",
                            error
                        )
                    );
            }
            else if (!user) {
                return res
                    .status(statusCode.unauthorized)
                    .json(
                        returnErrorJsonResponse(
                            statusCode.unauthorized,
                            "fail",
                            "We were unable to find the entered License Number."
                        )
                    );
            } else {
                return res
                    .status(statusCode.success)
                    .json(
                        returnJsonResponse(
                            statusCode.success,
                            "success",
                            "Your License Number has been successfully verified.",
                            user
                        )
                    );
            }
        })
    } catch (error) {
        console.log(error)
        return res
            .status(statusCode.error)
            .json(
                returnErrorJsonResponse(
                    statusCode.error,
                    "fail",
                    "Something went wrong, Please try again",
                    error
                )
            );
    }
};