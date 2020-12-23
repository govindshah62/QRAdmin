const mongoose = require('mongoose');

const tokenSchema = new mongoose.Schema({
    _userId: { 
        type: mongoose.Schema.Types.ObjectId, 
        required: true, 
        ref: 'MasterUser' 
    },
    token: { 
        type: String, 
        required: true 
    },
    createdAt: {
        type: Date,
        default: Date.now
    }
},
{versionKey:false});

module.exports = mongoose.model('Token',tokenSchema);
