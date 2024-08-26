const Users = require("../models/individual_users.js");
const TempUser = require("../models/tempUser.js");
const VerificationCodes = require("../models/verificationCodes.js");
const router = require("express").Router();
const asyncErrCatcher = require("../middlewares/asyncErrCatcher.js");
const bcrypt = require("bcryptjs");
const userAuthToken = require("../utils/userAuthToken.js");
const sendMail = require("../utils/sendMail.js");
const generateSixDigitVerificationCode = require("../utils/generateSixDigitVerificationCode.js");
const generateFourDigitVerificationCode = require("../utils/generateFourDigitVerificationCode.js");
const passport = require("passport");

router.post(
  "/sign-up",
  asyncErrCatcher(async (req, res) => {
    try {
      const items = req.body;
      let found_user;
      console.log("nm", items);

      found_user = await Users.findOne({
        email_address: items.email_address,
      });
      console.log("kop", JSON.stringify(found_user));

      if (found_user) {
        return res.status(403).json({
          error: true,
          message: "User does exist with this email address",
        });
      }

      const salt = await bcrypt.genSalt(12);
      const hashedPass = await bcrypt.hash(items.password, salt);

      const tempUser = {
        email_address: items.email_address,
        full_name: items.full_name,
        password: hashedPass,
      };
      console.log("temp:", tempUser);
      await TempUser.deleteMany({
        email_address: items.email_address,
      });

      const verificationCode = generateSixDigitVerificationCode();
      console.log("ui:", verificationCode);
      await TempUser.create({
        ...tempUser,
        verificationCode: verificationCode,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      });

      await sendMail({
        email: items.email_address,
        subject: "Activate your account",
        context: {
          userName: items.full_name,
          activationCode: verificationCode,
          message: " activate your account.",
          subject: "Account Verification Code",
        },
      });

      res.status(200).json({
        success: true,
        message: "Verification code sent",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.post(
  "/resend-six-digit-code",
  asyncErrCatcher(async (req, res) => {
    try {
      const items = req.body;
      const verificationCode = generateSixDigitVerificationCode();
      const found_temp = await TempUser.findOne({
        email_address: items.email_address,
      });
      if (!found_temp)
        return res.status(401).json({
          error: true,
          message: "Anauthorized action! Stop!",
        });
      await TempUser.deleteOne({
        _id: found_temp._id,
      });
      await TempUser.create({
        full_name: found_temp.full_name,
        email_address: found_temp.email_address,
        password: found_temp.password,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
        verificationCode,
      });
      await sendMail({
        email: items.email_address,
        subject: "Activate your account",
        context: {
          userName: items.full_name,
          activationCode: verificationCode,
          message: " activate your account.",
          subject: "Account Verification Code",
        },
      });
      res.status(200).json({
        success: true,
        message: "Verification code sent",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.post(
  "/verify-code-sign-up",
  asyncErrCatcher(async (req, res) => {
    try {
      const items = req.body;
      console.log("kl:", items.code, items);
      const tempUser = await TempUser.findOne({
        email_address: items.email_address,
      });
      console.log("loh:", JSON.stringify(tempUser));

      if (!tempUser) {
        return res.status(400).json({
          error: true,
          message: "Invalid or expired verification code or no temp user found",
        });
      }
      if (Number(tempUser.verificationCode) !== Number(items.code)) {
        return res.status(401).json({
          error: true,
          message: "Invalid or expired verification code",
        });
      }
      console.log("now:", Date.now(), "expiry:", tempUser.expiresAt);
      if (tempUser.expiresAt < Date.now()) {
        return res.status(400).json({
          error: true,
          message: "Verification code has expired",
        });
      }

      const newUser = await Users.create({
        ...items,
        password: tempUser.password,
      });
      await TempUser.deleteOne({ _id: tempUser._id });

      userAuthToken(newUser, 200, res, "individual");
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.post(
  "/login",
  asyncErrCatcher(async (req, res) => {
    try {
      const items = req.body;
      const found_user = await Users.findOne({
        email_address: items.email_address,
      });
      if (!found_user)
        return res.staus(403).json({
          error: true,
          message: "No user found with this email address",
        });

      const verifiedUser = await bcrypt.compare(
        items.password,
        found_user.password
      );
      if (!verifiedUser)
        return res.tatus(404).json({
          error: true,
          message: "Wrong password or email credentials",
        });

      userAuthToken(found_user, 200, res, "individual");
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.post(
  "/reset-password-p1",
  asyncErrCatcher(async (req, res) => {
    try {
      const items = req.body;

      const found_user = await Users.findOne({
        email_address: items.email_address,
      });
      if (!found_user) {
        return res.status(403).json({
          error: true,
          message: "User does not exist with this email address",
        });
      }

      await VerificationCodes.deleteMany({
        email_address: items.email_address,
      });

      const verificationCode = generateFourDigitVerificationCode();

      await VerificationCodes.create({
        email_address: items.email_address || null,
        verificationCode,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      });

      await sendMail({
        email: items.email_address,
        subject: "Reset your password",
        context: {
          userName: found_user.full_name,
          activationCode: verificationCode,
          message: " reset your password.",
          subject: "Reset Password Code",
        },
      });

      res.status(200).json({
        success: true,
        message: "Code sent",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.post(
  "/resend-four-digit-code",
  asyncErrCatcher(async (req, res) => {
    try {
      const items = req.body;
      const verificationCode = generateFourDigitVerificationCode();
      const found_temp = await VerificationCodes.findOne({
        email_address: items.email_address,
      });
      const found_user = await Users.findOne({
        email_address: items.email_address,
      });
      console.log("lp/:", found_temp);
      if (!found_temp)
        return res.status(401).json({
          error: true,
          message: "Anauthorized action! Stop!",
        });
      await VerificationCodes.deleteOne({
        _id: found_temp._id,
      });
      await VerificationCodes.create({
        email_address: found_temp.email_address,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
        verificationCode,
      });
      await sendMail({
        email: items.email_address,
        subject: "Reset your password",
        context: {
          userName: found_user.full_name,
          activationCode: verificationCode,
          message: " reset your password.",
          subject: "Reset Password Code",
        },
      });
      res.status(200).json({
        success: true,
        message: "Code sent",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.post(
  "/verify-code-reset-pass",
  asyncErrCatcher(async (req, res) => {
    const { email_address, code } = req.body;

    try {
      const verifiedCode = await VerificationCodes.findOne({
        email_address,
        verificationCode: code,
      });

      if (!verifiedCode) {
        return res.status(400).json({
          error: true,
          message: "Invalid or expired verification code",
        });
      }
      if (verifiedCode.verificationCode !== code) {
        return res.status(400).json({
          error: true,
          message: "Invalid or expired verification code",
        });
      }
      if (verifiedCode.expiresAt < Date.now()) {
        return res.status(400).json({
          error: true,
          message: "Verification code has expired",
        });
      }

      await VerificationCodes.deleteOne({ _id: verifiedCode._id });

      res.status(200).json({
        success: true,
        message: "Code verified",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.post(
  "/reset-password-p2",
  asyncErrCatcher(async (req, res) => {
    try {
      const items = req.body;
      console.log("it:", items);

      const found_user = await Users.findOne({
        email_address: items.email_address,
      });
      if (!found_user) {
        return res.status(403).json({
          error: true,
          message: "User does not exist with this email address",
        });
      }

      if (items.password !== items.confirm_password) {
        return res.status(400).json({
          error: true,
          message: "Passwords do not match",
        });
      }
      const verifiedUser = await bcrypt.compare(
        items.password,
        found_user.password
      );

      if (verifiedUser)
        return res.status(404).json({
          error: true,
          message: "Old password can not be the same with new password",
        });

      const salt = await bcrypt.genSalt(12);
      const hashedPass = await bcrypt.hash(items.password, salt);
      console.log("user b4 updt:", found_user);
      found_user.password = hashedPass;
      found_user.updatedAt = new Date(Date.now());
      console.log("lop:", JSON.stringify(found_user), found_user.password);
      await found_user.save();

      res.status(200).json({
        success: true,
        message: "New Password saved",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.get("/auth/google", (req, res, next) => {
  const role = req.query.state || "indi";

  passport.authenticate("google", {
    scope: ["profile", "email"],
    state: role,
  })(req, res, next);
});

router.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/",
  }),
  (req, res) => {
    console.log("route hit");
    userAuthToken(req.user, 200, res);
    res.redirect("/user/dashboard");
  }
);

module.exports = router;
