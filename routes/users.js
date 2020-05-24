// 1xx informational response – the request was received, continuing process
// 2xx successful – the request was successfully received, understood, and accepted
// 3xx redirection – further action needs to be taken in order to complete the request
// 4xx client error – the request contains bad syntax or cannot be fulfilled
// 5xx server error – the server failed to fulfil an apparently valid request

import { Router } from 'express';
import passport from 'passport';
import jwt from 'jsonwebtoken';
import * as config from '../config/variables';
import User from '../models/user';
const JWT_duration = 0.5; // Minutes

const router = Router();

router.post('/register', (req, res, next) => {
    let newUser = new User({ ...req.body });

    User.getUserByUsername(newUser.username, (err, user) => {
        if (err) throw err;
        if (user) {
            return res.status(403).json({
                success: false,
                msg: `The user with username '${newUser.username}' already exist`
            });
        }
        User.addUser(newUser, (err, user) => {
            if (err) {
                res.status(500).json({
                    success: false,
                    msg: `The user could not be registered`
                });
            } else if (user) {
                res.status(201).json({
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
            return res.status(404).json({
                success: false,
                msg: `There is no user with username '${username}'`
            });
        }
        User.comparePassword(password, user.password, (err, isMatch) => {
            if (err) throw err;
            if (isMatch) {
                const token = jwt.sign(user.toJSON(), config.secret, {
                    expiresIn: JWT_duration * 60
                });
                res.status(202).json({
                    success: true,
                    access_token: 'JWT ' + token,
                    user: {
                        id: user._id,
                        username: user.username
                    }
                });
            } else {
                return res.status(401).json({
                    success: false,
                    msg: 'Wrong Password'
                });
            }
        });
    });
});

router.get('/profile', passport.authenticate('jwt', { session: false }),
    (req, res, next) => {
        res.status(202).json({
            id: req.user._id,
            username: req.user.username
        });
    });

module.exports = router;
