const asyncErrCatcher = require("./asyncErrCatcher");
const jwt = require("jsonwebtoken");

const userAuth = (requiredTokenType = null) => {
  return async (req, res, next) => {
    try {
      let token;

      if (requiredTokenType === "sme") {
        token = req.cookies.sme_user_token;
      } else if (requiredTokenType === "indi") {
        token = req.cookies.indi_user_token;
      } else {
        token = req.cookies.sme_user_token || req.cookies.indi_user_token;
      }

      if (!token) {
        return res.status(403).json({
          error: true,
          message: "Forbidden: No token provided.",
        });
      }

      const decoded = jwt.verify(token, process.env.JWT_SECRET);

      req.user = decoded;

      next();
    } catch (err) {
      console.error(err);
      return res.status(401).json({
        error: true,
        message: "Unauthorized: Invalid token.",
      });
    }
  };
};

module.exports = userAuth;
