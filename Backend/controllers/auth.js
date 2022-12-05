const { validationResult } = require('express-validator/check');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const User = require('../models/user');

exports.signup = (req, res, next) => {
  try {
    const errors = validationResult(req);

    if (!errors.isEmpty()) {
      const error = new Error('Validation failed.');
      error.statusCode = 422;
      error.data = errors.array();
      throw error;
    }
    const {firstName, lastName, email, password} = req.body;
    
    bcrypt
      .hash(password, 12)
      .then(hashedPw => {
        const user = new User({
          firstName,
          lastName,
          email,
          password: hashedPw,
        });
        return user.save();
      })
      .then(result => {
        res.status(201).json({ message: 'User created!', userId: result._id });
      })
      .catch(err => {
        if (!err.statusCode) {
          err.statusCode = 500;
        }
        next(err);
      });
  }
  catch(err) {
    return res.status(err.statusCode).send({error: true, data: err.data})
  }
};

exports.signin =  (req, res, next) => {
  try {
    const {email, password} = req.body
    let loadedUser;
    User.findOne({ email: email })
      .then(user => {
        if (!user) {
          const error = new Error('A user with this email could not be found.');
          error.statusCode = 401;
          throw error;
        }
        loadedUser = user;
        return bcrypt.compare(password, user.password);
      })
      .then(isEqual => {
        if (!isEqual) {
          const error = new Error('Wrong password!');
          error.statusCode = 401;
          throw error;
        }
        const token = jwt.sign(
          {
            email: loadedUser.email,
            userId: loadedUser._id.toString()
          },
          'somesupersecretsecret',
          { expiresIn: '1h' }
        );
        return {token: token,userId: loadedUser._id};
      })
      .then(async (tokenUserId) => {
        const handyman =  await User.find({userId: tokenUserId.userId});
        if(!handyman || !handyman.length) return res.status(200).json({ token: tokenUserId.token, userId: tokenUserId.userId.toString() });
        return res.status(200).json({ token: tokenUserId.token, userId: tokenUserId.userId.toString(), handymanId: handyman._id });
      })
      .catch(err => {
        if (!err.statusCode) {
          err.statusCode = 500;
        }
        next(err);
      });
  }
  catch(err) {
    return res.status(err.statusCode).send({error: true, data: err.data})
  }
};
