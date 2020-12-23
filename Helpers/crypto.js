const crypto = require('crypto');
const algorithm = 'aes-256-ctr';
const secretKey = crypto.randomBytes(32);    //32 character
const iv = crypto.randomBytes(16);    //16 character

module.exports.encrypt = (text) => {
    try {
        const cipher = crypto.createCipheriv(algorithm, secretKey, iv);
        const encrypted = Buffer.concat([cipher.update(text), cipher.final()]);
        return {
            secretKey: secretKey.toString('hex'),
            iv: iv.toString('hex'),
            content: encrypted.toString('hex')
        }
    } catch (error) {
        return error;
    }

};

module.exports.decrypt = (hash) => {
    try {
        const decipher = crypto.createDecipheriv(algorithm, Buffer.from(hash.secretKey, 'hex'), Buffer.from(hash.iv, 'hex'));
        const decrpyted = Buffer.concat([decipher.update(Buffer.from(hash.content, 'hex')), decipher.final()]);
        return decrpyted.toString();
    } catch (error) {
        return error;
    }
};

module.exports.getRandomString = (char) => {
    try {
        var randomchar = char;
        var result = '';
        for (let i = 0; i < 16; i++) {
            result += randomchar.charAt(Math.floor(Math.random() * randomchar.length));
        }
        return result;
    } catch (error) {
        return error;
    }
};