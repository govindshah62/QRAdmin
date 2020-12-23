const express = require('express');
const router= express.Router();
const {register,login, verify, getAdminUsers, getlicenseNo, compareLicenseNo} = require('../controllers/company');

router.post('/register',register);
router.post('/verify/:email/:token',verify);
router.post('/login',login);
router.get('/getAdminUsers', getAdminUsers);
router.post('/getlicenseNo', getlicenseNo);
router.post('/comparelicenseNo', compareLicenseNo);

module.exports= router;