import { Router } from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import * as database from '../config/database';
import User from '../models/user';
const JWT_duration = 0.5; // Minutes

const router = Router();

router.post('/register', (req, res, next) => {
    let newUser = new User({ ...req.body });

    User.getUserByUsername(newUser.username, (err, user) => {
        if (err) throw err;
        if (user) {
            return res.json({
                success: false,
                msg: `The user with username '${newUser.username}' already exist`
            });
        }
        User.addUser(newUser, (err, user) => {
            if (err) {
                res.json({
                    success: false,
                    msg: `The user could not be registered`
                });
            } else if (user) {
                res.json({
                    success: true,
                    msg: `User registered`,
                    userId: user._id
                });
            }
        });
    });
});

router.post('/authenticate', (req, res, next) => {
    const username = req.body.username;
    const password = req.body.password;

    User.getUserByUsername(username, (err, user) => {
        if (err) throw err;
        if (!user) {
            return res.json({
                success: false,
                msg: `There is no user with username '${username}'`
            });
        }
        User.comparePassword(password, user.password, (err, isMatch) => {
            if (err) throw err;
            if (isMatch) {
                const token = jwt.sign(user.toJSON(), database.secret, {
                    expiresIn: JWT_duration * 60
                });
                res.json({
                    success: true,
                    access_token: 'JWT ' + token,
                    user: {
                        id: user._id,
                        username: user.username
                    }
                });
            } else {
                return res.json({
                    success: false,
                    msg: 'Wrong Password'
                });
            }
        });
    });
});

router.get('/profile', passport.authenticate('jwt', { session: false }),
    (req, res, next) => {
        res.json({
            user: req.user
        });
    });

module.exports = router;
