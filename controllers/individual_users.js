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
const userAuth = require("../middlewares/userAuth.js");
const OAuthToken = require("../models/oauthToken.js");
const alertPreferences = require("../models/alertPreferences.js");

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
        full_name: tempUser.full_name,
        email_address: tempUser.email_address,
        password: tempUser.password,
        monitored_query_users: [tempUser.email_address],
      });
      await alertPreferences.create({
        userId: newUser._id,
        userType: "Individual",
        email_alert_brackets: [
          {
            alertChannels: {
              email: true,
              inApp: false,
              smsAlerts: false,
            },
            user_monitored_email: newUser.email_address,
            emailAlert: "Soon",
            severity: "Soon",
          },
        ],
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
      console.log("route hit:", items);
      const found_user = await Users.findOne({
        email_address: items.email_address,
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
      console.log("user:", found_user, verifiedUser);
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
      console.log("/sgsh:", found_user);
      await VerificationCodes.deleteMany({
        email_address: items.email_address,
      });

      const verificationCode = generateFourDigitVerificationCode();

      await VerificationCodes.create({
        email_address: items.email_address,
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
    try {
      const { email_address, code } = req.body;

      const verifiedCode = await VerificationCodes.findOne({
        email_address,
        verificationCode: code,
      });
      console.log("cdf:", email_address, code);
      console.log("--P", verifiedCode);
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

router.get(
  "/get-monitored-user",
  userAuth("indi"),
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
  userAuth("indi"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { new_email } = req.body;
      const foundUser = await Users.findOne({
        _id: req.user.id,
      });
      if (!new_email) {
        return res.status(404).json({
          error: true,
          message: "No email provided",
        });
      }
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found",
        });
      }
      console.log("foundUser:", foundUser, foundUser.monitored_query_users);

      const email_exists = foundUser.monitored_query_users.includes(new_email);
      if (email_exists) {
        return res.status(409).json({
          error: true,
          message: "Email already exists",
        });
      }

      foundUser.monitored_query_users.push(new_email);
      const foundAlert = await alertPreferences.findOne({
        userId: req.user.id,
      });
      console.log("foundAlert:", foundAlert);
      if (!foundAlert) {
        await alertPreferences.create({
          userId: foundUser._id,
          userType: "Individual",
          email_alert_brackets: [
            {
              alertChannels: {
                email: true,
                inApp: false,
                smsAlerts: false,
              },
              user_monitored_email: new_email,
              emailAlert: "Soon",
              severity: "Soon",
            },
          ],
        });
      } else {
        foundAlert.email_alert_brackets.push({
          alertChannels: {
            email: true,
            inApp: false,
            smsAlerts: false,
          },
          user_monitored_email: new_email,
          emailAlert: "Soon",
          severity: "Soon",
        });
        await foundAlert.save();
      }
      await foundUser.save();

      res.json({
        success: true,
        message: "New email added to monitoring succesffully!",
      });
    } catch (error) {
      console.error(error);
      next(error);
    }
  })
);

router.get(
  "/logout",
  userAuth("indi"),
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

          res.cookie("indi_user_token", "", {
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
          console.log(`Indi User: ${req.user.id} logs out`);

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
  "/change-alert-preferences",
  userAuth("indi"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const updateInfo = req.body;
      const foundUser = await Users.findOne({ _id: req.user.id });
      const foundUserAlertPrefs = await alertPreferences.findOne({
        userId: req.user.id,
      });
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found!",
        });
      }
      let newUserPrefs;
      if (!foundUserAlertPrefs) {
        newUserPrefs = await alertPreferences.create({
          userId: req.user.id,
          userType: "Individual",
          email_alert_brackets: [
            {
              alertChannels: {
                email: true,
                inApp: false,
                smsAlerts: false,
              },
              user_monitored_email: foundUser.email_address,
              emailAlert: "Soon",
              severity: "Soon",
            },
          ],
        });
      }
      newUserPrefs = newUserPrefs ? newUserPrefs : foundUserAlertPrefs;

      console.log("updateInfo", updateInfo);

      if (!updateInfo.email) {
        throw new Error("Required field email address not provided!");
      }

      const verifiedQuery = foundUser.monitored_query_users.find(
        (elem) => elem === updateInfo.email
      );

      if (!verifiedQuery) {
        return res.status(403).json({
          error: true,
          message: "Query parameter forbidden!",
        });
      }
      console.log("newUserPrefs:", newUserPrefs);
      if (newUserPrefs.email_alert_brackets.length === 0) {
        newUserPrefs.email_alert_brackets.push({
          user_monitored_email: updateInfo.email,
          alertChannels: {
            email:
              updateInfo.alertChannels?.email !== undefined
                ? updateInfo.alertChannels.email
                : true,
            inApp:
              updateInfo.alertChannels?.inApp !== undefined
                ? updateInfo.alertChannels.inApp
                : false,
            smsAlerts:
              updateInfo.alertChannels?.smsAlerts !== undefined
                ? updateInfo.alertChannels.smsAlerts
                : false,
          },
          emailAlert:
            updateInfo.emailAlert !== undefined
              ? updateInfo.emailAlert
              : "Default",
          severity:
            updateInfo.severity !== undefined ? updateInfo.severity : "Default",
        });
      } else {
        const index = newUserPrefs.email_alert_brackets.findIndex(
          (elem) => elem.user_monitored_email === updateInfo.email
        );
        console.log("index:", index);
        if (index !== -1) {
          const foundAlertPref = newUserPrefs.email_alert_brackets[index];
          console.log("foundAlertPref:", foundAlertPref);
          if (updateInfo.alertChannels) {
            if (updateInfo.alertChannels.email !== undefined) {
              foundAlertPref.alertChannels.email =
                updateInfo.alertChannels.email;
            }
            if (updateInfo.alertChannels.inApp !== undefined) {
              foundAlertPref.alertChannels.inApp =
                updateInfo.alertChannels.inApp;
            }
            if (updateInfo.alertChannels.smsAlerts !== undefined) {
              foundAlertPref.alertChannels.smsAlerts =
                updateInfo.alertChannels.smsAlerts;
            }
          }
          if (updateInfo.emailAlert !== undefined) {
            foundAlertPref.emailAlert = updateInfo.emailAlert;
          }
          if (updateInfo.severity !== undefined) {
            foundAlertPref.severity = updateInfo.severity;
          }
        } else {
          return res.status(404).json({
            error: true,
            message: "Alert preferences for the provided email not found.",
          });
        }
      }
      console.log(
        "newUserPrefsn",
        JSON.stringify(newUserPrefs.email_alert_brackets)
      );
      const result = await newUserPrefs.save();

      res.json({
        success: true,
        message: "Update successful",
        result,
      });
    } catch (err) {
      console.error(err);
      next(err);
    }
  })
);

router.get(
  "/get-alert-preferences",
  userAuth("indi"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { query } = req.query;
      console.log("query:", query);
      const foundUser = await Users.findOne({ _id: req.user.id });
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No indi user found!",
        });
      }
      const foundUserAlertPrefs = await alertPreferences.findOne({
        userId: req.user.id,
        "email_alert_brackets.user_monitored_email": query,
      });
      const verifiedQuery = foundUser.monitored_query_users.find(
        (elem) => elem === query
      );

      if (!verifiedQuery) {
        return res.status(403).json({
          error: true,
          message: "Query parameter forbidden!",
        });
      }
      console.log("foundUserAlertPrefs:", foundUserAlertPrefs);
      // if (!foundUserAlertPrefs) {
      //   return res.status(404).json({
      //     error: true,
      //     message: "No alert preferences created",
      //   });
      // }
      // let newUserPrefs;
      if (!foundUserAlertPrefs) {
        newUserPrefs = alertPreferences.create({
          userId: req.user.id,
          userType: "Individual",
          email_alert_brackets: [
            {
              alertChannels: {
                email: true,
                inApp: false,
                smsAlerts: false,
              },
              user_monitored_email: foundUser.email_address,
              emailAlert: "Soon",
              severity: "Soon",
            },
          ],
        });
      }
      // newUserPrefs = newUserPrefs ? newUserPrefs : foundUserAlertPrefs;
      const matchedBracket = foundUserAlertPrefs.email_alert_brackets.find(
        (bracket) => bracket.user_monitored_email === query
      );
      res.json({
        success: true,
        matchedBracket,
      });
    } catch (err) {
      console.error(err);
      next(err);
    }
  })
);

router.get(
  "/user-info",
  userAuth("indi"),
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
        foundUser,
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);
module.exports = router;
