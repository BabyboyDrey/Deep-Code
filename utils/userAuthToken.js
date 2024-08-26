const userAuthToken = (user, statusCode, res, userType) => {
  const user_token = user.getJwtToken();
  console.log("token:", user_token);
  const JWT_EXPIRES_MS = 8 * 60 * 60 * 1000;

  const options = {
    maxAge: JWT_EXPIRES_MS,
    httpOnly: true,
    sameSite: "none",
    secure: true,
  };
  if (userType === "individual") {
    res.status(statusCode).cookie("indi_user_token", user_token, options).json({
      success: true,
      user,
    });
  }
  if (userType === "sme") {
    res.status(statusCode).cookie("sme_user_token", user_token, options).json({
      success: true,
      user,
    });
  }
};

module.exports = userAuthToken;
