const jwt = require("jsonwebtoken");
const User = require("../models/user.model");

// Middleware that validates the JWT Token.
exports.authMiddleware = (req, res, next) => {
  const token = req.header("Authorization");

  if (!token) {
    return res
      .status(401)
      .json({ message: "No token, Authorization Denied", status: false });
  }

  try {
    jwt.verify(token, process.env.JWT_SECRET, (error, decoded) => {
      if (error) {
        return res
          .status(401)
          .json({ message: "Token is Not Valid", status: false });
      } else {
        User.findById(decoded._id, (err, data) => {
          if (err) {
            res.status(400).json({ message: err, status: false });
          } else if (!data) {
            res
              .status(401)
              .json({ message: "Token is Not Valid", status: false });
          } else {
            req.user = { ...data, status: true };
            next();
          }
        });
      }
    });
  } catch (err) {
    console.error(`Something went Wrong with auth Middleware : ${err}`);
    res.status(500).json({ message: "Server Error", status: false });
  }
};
