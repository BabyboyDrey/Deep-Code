const asyncErrCatcher = require("./asyncErrCatcher");
const jwt = require("jsonwebtoken");

module.exports = userAuth = asyncErrCatcher(async (req, res, next) => {
  const userToken = req.cookies.indi_user_token || req.cookies.sme_user_token;
  console.log("tok:", userToken, req.cookies);
  if (!userToken) {
    return res.status(403).json({
      error: true,
      message: "Forbidden Access",
    });
  }

  const verified_user = jwt.verify(userToken, process.env.JWT_SECRET);

  req.user = verified_user;
  console.log("req.user:", req.user);
  next();
});
