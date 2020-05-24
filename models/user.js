import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
const saltRounds = 10;

const UserSchema = mongoose.Schema({
    username: {
        type: String,
        required: true
    },
    password: {
        type: String,
        required: true
    }
});

const User = module.exports = mongoose.model('User', UserSchema);

module.exports.getUserById = (id, callback) => {
    User.findById(id, callback);
}

module.exports.getUserByUsername = (username, callback) => {
    const query = {
        username: username
    }
    User.findOne(query, callback);
}

module.exports.addUser = (newUser, callback) => {
    bcrypt.hash(newUser.password, saltRounds, (err, hash) => {
        if (err) throw err;
        newUser.password = hash;
        newUser.save(callback);
    });
}

module.exports.comparePassword = (candidatePassword, hash, callback) => {
    bcrypt.compare(candidatePassword, hash, (err, isMatch) => {
        if (err) throw err;
        callback(null, isMatch);
    });
}