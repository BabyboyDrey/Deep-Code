const Users = require("../models/sme_users.js");
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
const userAuth = require("../middlewares/userAuth.js");
const OAuthToken = require("../models/oauthToken.js");
const alertPreferences = require("../models/alertPreferences.js");
const breaches = require("../models/breaches.js");

router.post(
  "/sign-up",
  asyncErrCatcher(async (req, res) => {
    try {
      const items = req.body;

      console.log("nm", items);

      const found_user = await Users.findOne({
        company_email_address: items.company_email_address,
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
        email_address: items.company_email_address,
        company_name: items.company_name,
        full_name: items.full_name,
        password: hashedPass,
      };
      console.log("temp:", tempUser);
      await TempUser.deleteMany({
        email_address: items.company_email_address,
      });

      const verificationCode = generateSixDigitVerificationCode();
      console.log("ui:", verificationCode);
      const oop = await TempUser.create({
        ...tempUser,
        verificationCode: verificationCode,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      });
      console.log(".//:", oop);
      await sendMail({
        email: items.company_email_address,
        subject: "Activate your account",
        context: {
          userName: items.full_name,
          activationCode: verificationCode,
          message: " activate your account.",
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
        email_address: items.company_email_address,
      });
      console.log("lp:", found_temp);
      await TempUser.deleteOne({
        _id: found_temp._id,
      });
      await TempUser.create({
        full_name: found_temp.full_name,
        company_name: found_temp.company_name,
        email_address: found_temp.email_address,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
        password: found_temp.password,
        verificationCode,
      });
      await sendMail({
        email: items.company_email_address,
        subject: "Activate your account",
        context: {
          userName: items.full_name,
          activationCode: verificationCode,
          message: " activate your account.",
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
        email_address: items.company_email_address,
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
        company_email_address: tempUser.email_address,
        company_name: tempUser.company_name,
        full_name: tempUser.full_name,
        password: tempUser.password,
        monitored_query_users: [tempUser.email_address],
      });
      await TempUser.deleteOne({ _id: tempUser._id });

      userAuthToken(newUser, 200, res, "sme");
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
        company_email_address: items.company_email_address,
      });
      if (!found_user)
        return res.status(403).json({
          error: true,
          message: "No user found with this email address",
        });

      const verifiedUser = await bcrypt.compare(
        items.password,
        found_user.password
      );
      if (!verifiedUser)
        return res.status(404).json({
          error: true,
          message: "Wrong password or email credentials",
        });

      userAuthToken(found_user, 200, res, "sme");
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
      console.log("//ak:", items);
      const found_user = await Users.findOne({
        company_email_address: items.company_email_address,
      });
      if (!found_user) {
        return res.status(403).json({
          error: true,
          message: "User does not exist with this email address",
        });
      }
      console.log("fod:", found_user);
      await VerificationCodes.deleteMany({
        email_address: items.company_email_address,
      });

      const verificationCode = generateFourDigitVerificationCode();

      const new_verification_code = await VerificationCodes.create({
        email_address: items.company_email_address,
        verificationCode,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
      });
      console.log("shhs:", new_verification_code);
      await sendMail({
        email: items.company_email_address,
        subject: "Reset your password",
        context: {
          userName: found_user.full_name,
          activationCode: verificationCode,
          message: " reset your password.",
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
  "/resend-four-digit-code",
  asyncErrCatcher(async (req, res) => {
    try {
      const items = req.body;
      const found_user = await Users.findOne({
        company_email_address: items.company_email_address,
      });
      if (!found_user) {
        return res.status(403).json({
          error: true,
          message: "User does not exist with this email address",
        });
      }
      const verificationCode = generateFourDigitVerificationCode();
      const found_temp = await VerificationCodes.findOne({
        email_address: items.company_email_address,
      });
      if (!found_temp)
        return res.status(401).json({
          error: true,
          message: "Anauthorized action! Stop!",
        });
      console.log("/lll:", found_temp);
      await VerificationCodes.deleteOne({
        _id: found_temp._id,
      });
      const new_verification_code = await VerificationCodes.create({
        email_address: found_temp.email_address,
        expiresAt: new Date(Date.now() + 15 * 60 * 1000),
        verificationCode,
      });
      console.log("ADf:", new_verification_code);
      await sendMail({
        email: items.company_email_address,
        subject: "Reset Password code",
        context: {
          userName: found_user.full_name,
          activationCode: verificationCode,
          message: " reset your password.",
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
  "/verify-code-reset-pass",
  asyncErrCatcher(async (req, res) => {
    const { company_email_address, code } = req.body;

    try {
      console.log("aka:", company_email_address, code);
      const verifiedCode = await VerificationCodes.findOne({
        email_address: company_email_address,
        verificationCode: code,
      });
      console.log("jk:", verifiedCode);
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
        company_email_address: items.company_email_address,
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
  const role = req.query.state || "sme";
  console.log("reqq.", req.query);
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

router.get(
  "/get-monitored-user",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const foundUser = await Users.findOne({
        _id: req.user.id,
      });

      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found!",
        });
      }

      res.json({
        success: true,
        monitored_users: foundUser.monitored_query_users,
      });
    } catch (err) {
      console.error(err);
      next(err);
    }
  })
);

router.post(
  "/add-monitored-user",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { new_domain } = req.body;
      if (!new_domain) {
        return res.status(404).json({
          error: true,
          message: "No domain provided",
        });
      }
      const foundUser = await Users.findOne({
        _id: req.user.id,
      });
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found",
        });
      }
      const domain_exists =
        foundUser.monitored_query_users.includes(new_domain);
      if (domain_exists) {
        return res.status(409).json({
          error: true,
          message: "Domain already exists",
        });
      }
      console.log("foundUser:", foundUser, foundUser.monitored_query_users);
      foundUser.monitored_query_users.push(new_domain);
      await foundUser.save();

      res.json({
        success: true,
        message: "New domain added to monitoring succesffully!",
      });
    } catch (error) {
      console.error(error);
      next(error);
    }
  })
);

router.get(
  "/logout",
  userAuth("sme"),
  asyncErrCatcher(async (req, res) => {
    await OAuthToken.deleteMany({ userId: req.user.id })
      .then(() => {
        req.session.destroy((err) => {
          if (err) {
            return res.status(500).json({
              success: false,
              message: "Failed to log out",
            });
          }

          res.cookie("sme_user_token", "", {
            maxAge: 0,
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            path: "/",
          });

          res.cookie("connect.sid", "", {
            maxAge: 0,
            httpOnly: true,
            secure: process.env.NODE_ENV === "production",
            path: "/",
          });
          console.log(`SME User: ${req.user.id} logs out`);

          res.status(200).json({
            success: true,
            message: "Logged out successfully",
          });
        });
      })
      .catch((err) => {
        console.error(err);
        return res.status(500).json({
          success: false,
          message: "Failed to delete oauth tokens hence failed to log out",
        });
      });
  })
);

router.post(
  "/add-team-member",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const new_team_member = req.body;
      console.log("new_team_member:", new_team_member);
      const foundUser = await Users.findOne({
        _id: req.user.id,
      });

      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found!",
        });
      }
      console.log("foundUser:", foundUser);
      if (!foundUser.team_memebers) {
        foundUser.team_memebers = [];
      }

      const existingMember = foundUser.team_memebers.find((e) => {
        return e && e.domain === new_team_member.domain;
      });

      if (existingMember) {
        return res.status(409).json({
          error: true,
          message: "Team member already exists with this domain!",
        });
      }

      foundUser.team_memebers.push(new_team_member);
      await foundUser.save();
      res.json({
        success: true,
        message: "Team member added successfully!",
        new_team_members: foundUser.team_memebers,
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);

router.post(
  "/change-alert-preferences",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const update = req.body;
      const foundUserAlertPrefs = await alertPreferences.findOne({
        userId: req.user.id,
      });
      let newUserPrefs;
      if (!foundUserAlertPrefs) {
        newUserPrefs = alertPreferences.create({
          userId: req.user.id,
        });
      }
      newUserPrefs = newUserPrefs ? newUserPrefs : foundUserAlertPrefs;
      console.log("update", update);
      if (
        update.alertChannels &&
        (!update?.alertChannels?.email ||
          update?.alertChannels?.inApp ||
          update?.alertChannels?.smsAlerts)
      ) {
        throw new Error("Email alert functionality enabled only for now!");
      }
      if (update.emailAlert && update?.emailAlert !== "Immediately") {
        return res.status(409).json({
          error: true,
          message: "Email alerts is already set to immediately",
        });
      }
      if (update.severity && update?.severity !== "High") {
        return res.status(409).json({
          error: true,
          message: "Email severity is already set to High",
        });
      }
      res.json({
        success: true,
      });
    } catch (err) {
      console.error(err);
      next(err);
    }
  })
);

//In the works
router.get(
  "/domain-monitoring-summary",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const foundUserBreach = await breaches.findOne({
        userId: req.user.id,
      });

      if (!foundUserBreach) {
        throw new Error("User has no breach record!");
      }
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);

module.exports = router;
