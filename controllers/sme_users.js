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
const jwt = require("jsonwebtoken");
const { upload } = require("../multer/multerImage.js");
const checkAndDeleteFile = require("../utils/checkAndDeleteFile.js");
const path = require("path");
const UAParser = require("ua-parser-js");
const notificationsSettings = require("../models/notificationsSettings.js");
const parser = new UAParser();
const fs = require("fs").promises;

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

      const ipAddress =
        req.headers["x-forwarded-for"]?.split(",").shift() ||
        req.socket?.remoteAddress ||
        req.connection?.remoteAddress;

      const agent = parser.setUA(req.headers["user-agent"]).getResult();
      console.log("agent:", agent);
      const deviceName = agent.device.model || "Unknown Device";
      const deviceVendor = agent.device.vendor || "Unknown Vendor";
      const os = agent.os.name || "Unknown OS";

      const newUser = await Users.create({
        company_email_address: tempUser.email_address,
        company_name: tempUser.company_name,
        full_name: tempUser.full_name,
        password: tempUser.password,
        monitored_query_users: [tempUser.email_address],
        last_login: {
          date: new Date(),
          ip_address: ipAddress,
          device_name: `${deviceVendor} ${deviceName} (${os})`,
        },
      });
      await alertPreferences.create({
        userId: newUser._id,
        userType: "SME",
        email_alert_brackets: [
          {
            alertChannels: {
              email: true,
              inApp: false,
              smsAlerts: false,
            },
            user_monitored_email: newUser.company_email_address,
            emailAlert: "Soon",
            severity: "Soon",
          },
        ],
      });
      await notificationsSettings.create({
        userId: newUser._id,
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

      const ipAddress =
        req.headers["x-forwarded-for"]?.split(",").shift() ||
        req.socket?.remoteAddress ||
        req.connection?.remoteAddress;
      console.log("ipAddress:", ipAddress);

      const agent = parser.setUA(req.headers["user-agent"]).getResult();
      console.log("agent:", agent);

      const deviceName = agent.device.model || "Unknown Device";
      const deviceVendor = agent.device.vendor || "Unknown Vendor";
      const os = agent.os.name || "Unknown OS";

      found_user.last_login = {
        date: new Date(),
        ip_address: ipAddress,
        device_name: `${deviceVendor} ${deviceName} (${os})`,
      };

      await found_user.save();

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
      found_user.updateInfodAt = new Date(Date.now());
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

router.post(
  "/auth-reset-password",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { currentPassword, confirmPassword, newPassword } = req.body;

      const foundUser = await Users.findOne({
        _id: req.user.id,
      });

      if (!foundUser) {
        throw new Error("User do not exist!");
      }

      const verifiedPassword = await bcrypt.compare(
        currentPassword,
        foundUser.password
      );

      if (!verifiedPassword) {
        throw new Error("Current Password is incoorect! Please try again.");
      }

      if (newPassword !== confirmPassword) {
        throw new Error("New password and confirm password does not match!");
      }

      if (newPassword === currentPassword) {
        throw new Error("New password cannot be same as old password");
      }

      const salt = await bcrypt.genSalt(12);
      const hashedPassword = await bcrypt.hash(newPassword, salt);

      foundUser.password = hashedPassword;
      await foundUser.save();

      res.json({
        success: true,
        message: "New password saved!",
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);

router.put(
  "/update-avatar",
  upload.single("avatar"),
  userAuth("sme"),
  asyncErrCatcher(async (req, res) => {
    try {
      console.log("req.file:", req.file.filename);

      const user = await Users.findById({
        _id: req.user.id,
      });
      console.log("user b4 update:", user);
      if (!user) {
        await new Promise((resolve, reject) => {
          checkAndDeleteFile(`uploads/${req.file.filename}`, (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
        return res.status(404).json({
          error: true,
          message: "No user found!",
        });
      }

      if (!req.file) {
        return res.status(400).json({
          error: true,
          message: "No file sent",
        });
      }
      console.log("starting processing");

      const imagePath = req.file.path;
      let base64Image;
      console.log("imagePath:", imagePath);

      try {
        await fs.access(imagePath);
        console.log("File exists at the expected path.");
      } catch (err) {
        await new Promise((resolve, reject) => {
          checkAndDeleteFile(`uploads/${req.file.filename}`, (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
        console.error("File does not exist at the path:", imagePath);
        return res.status(404).json({
          error: true,
          message: "File not found on server",
        });
      }

      try {
        const data = await fs.readFile(imagePath);
        base64Image = data.toString("base64");
        console.log("File read successfully, base64Image:", base64Image);
      } catch (err) {
        await new Promise((resolve, reject) => {
          checkAndDeleteFile(`uploads/${req.file.filename}`, (err) => {
            if (err) reject(err);
            else resolve();
          });
        });
        if (err.code === "ENOENT") {
          console.warn("File not found, skipping base64 conversion.");
          base64Image = null;
        } else {
          console.error("Error reading image file:", err);
          return res.status(500).json({
            error: true,
            message: "Error processing image file",
          });
        }
      }

      user.avatar = req.file.filename;
      user.avatar_base64_string = base64Image;
      user.updatedAt = new Date(Date.now());

      await user.save();
      console.log("user after update:", user);

      res.status(200).json({
        success: true,
        message: "User avatar updated successfully",
        avatar: base64Image,
      });
    } catch (err) {
      await new Promise((resolve, reject) => {
        checkAndDeleteFile(`uploads/${req.file.filename}`, (err) => {
          if (err) reject(err);
          else resolve();
        });
      });
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.post(
  "/team-member-create-pass/:superId",
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { superId } = req.params;
      const { domain, password, confirm_password } = req.body;
      if (!domain && !password && !confirm_password) {
        throw new Error("Required fields not provided!");
      }
      const foundUser = await Users.findOne({
        _id: superId,
      });
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found!",
        });
      }
      console.log("foundUser:", foundUser);
      const foundMember = foundUser.team_members.find(
        (elem) => elem.domain === domain
      );

      if (!foundMember) {
        return res.status(404).json({
          error: true,
          message: "No member found!",
        });
      }

      if (password !== confirm_password) {
        return res.status(400).json({
          error: true,
          message: "Passwords mismatch",
        });
      }
      const salt = await bcrypt.genSalt(12);
      const hashedPass = await bcrypt.hash(password, salt);
      foundMember.password = hashedPass;
      await foundUser.save();

      res.json({
        success: true,
        message: "Member's Password saved!",
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);

router.post(
  "/team-member-login",
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { domain, password } = req.body;
      const foundUser = await Users.findOne({
        "team_members.domain": domain,
      });
      if (!domain && !password) {
        throw new Error("Required fields not provided!");
      }
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found!",
        });
      }
      const foundMember = foundUser.team_members.find(
        (member) => member.domain === domain
      );
      if (!foundMember) {
        return res.status(404).json({
          error: true,
          message: "No member found!",
        });
      }
      const verifiedUser = await bcrypt.compare(password, foundMember.password);
      if (!verifiedUser)
        return res.status(404).json({
          error: true,
          message: "Wrong password or email credentials",
        });
      const JWT_EXPIRES_MS = 8 * 60 * 60 * 1000;
      const options = {
        maxAge: JWT_EXPIRES_MS,
        httpOnly: true,
        sameSite: process.env.NODE_ENV === "production" ? "none" : "lax",
        secure: process.env.NODE_ENV === "production" ? true : false,
      };
      const team_member_token = await jwt.sign(
        {
          _id: foundMember._id,
          superId: foundUser._id,
        },
        process.env.JWT_SECRET,
        {
          expiresIn: process.env.JWT_EXPIRES,
        }
      );
      res.cookie("team_member_token", team_member_token, options).json({
        success: true,
        message: "Login successful!",
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
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
      const foundAlert = await alertPreferences.findOne({
        userId: req.user.id,
      });
      console.log("foundAlert:", foundAlert);
      if (!foundAlert) {
        await alertPreferences.create({
          userId: foundUser._id,
          userType: "SME",
          email_alert_brackets: [
            {
              alertChannels: {
                email: true,
                inApp: false,
                smsAlerts: false,
              },
              user_monitored_email: new_domain,
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
          user_monitored_email: new_domain,
          emailAlert: "Soon",
          severity: "Soon",
        });
        await foundAlert.save();
      }

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
      if (!foundUser.team_members) {
        foundUser.team_members = [];
      }

      const existingMember = foundUser.team_members.find((e) => {
        return e && e.domain === new_team_member.domain;
      });

      if (existingMember) {
        return res.status(409).json({
          error: true,
          message: "Team member already exists with this domain!",
        });
      }

      foundUser.team_members.push(new_team_member);
      await foundUser.save();
      await sendMail({
        email: new_team_member.domain,
        subject: "Set up your account",
        context: {
          subject: "Set up your password",
          userName: new_team_member.full_name,
          message: `${foundUser._id}`,
          type: "Team",
        },
      });
      res.json({
        success: true,
        message: "Team member added successfully!",
        new_team_members: foundUser.team_members,
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
          userType: "SME",
          email_alert_brackets: [
            {
              alertChannels: {
                email: true,
                inApp: false,
                smsAlerts: false,
              },
              user_monitored_email: foundUser.company_email_address,
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

      if (newUserPrefs.email_alert_brackets.length === 0) {
        newUserPrefs.email_alert_brackets.push({
          user_monitored_email: updateInfo.email,
          alertChannels: {
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
              updateInfo.severity !== undefined
                ? updateInfo.severity
                : "Default",
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
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { query } = req.query;
      console.log("query:", query);
      const foundUser = await Users.findOne({ _id: req.user.id });
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found!",
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
          userType: "SME",
          email_alert_brackets: [
            {
              alertChannels: {
                email: true,
                inApp: false,
                smsAlerts: false,
              },
              user_monitored_email: foundUser.company_email_address,
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

router.get(
  "/user-info",
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

      function maskPassword(password) {
        const firstPart = password.slice(0, 3);
        const lastPart = password.slice(-3);
        const maskedPart = "****";

        return `${firstPart}${maskedPart}${lastPart}`;
      }

      const maskedPassword = maskPassword(foundUser.password);
      console.log(maskedPassword);

      foundUser.password = maskedPassword;

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

router.put(
  "/edit-team-member",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const updateInfo = req.body;
      const { query } = req.query;
      const foundUser = await Users.findOne({
        _id: req.user.id,
      });
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found!",
        });
      }
      const foundMemeber = foundUser.team_members.find(
        (elem) => elem.domain === query
      );
      if (!foundMemeber) {
        return res.status(404).json({
          error: true,
          message: "Team member not found!",
        });
      }
      if (updateInfo.domain) {
        foundMemeber.domain = updateInfo.domain;
      }
      if (updateInfo.role) {
        foundMemeber.role = updateInfo.role;
      }
      if (updateInfo.full_name) {
        foundMemeber.full_name = updateInfo.full_name;
      }
      if (updateInfo.status) {
        foundMemeber.status = updateInfo.status;
      }
      await foundUser.save();
      res.json({
        success: true,
        message: "Updated team member successfully!",
        updatedMemeber: foundMemeber,
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);

router.delete(
  "/delete-team-member",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { query } = req.query;
      const foundUser = await Users.findOne({
        _id: req.user.id,
      });
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "No user found!",
        });
      }
      const foundMemeber = foundUser.team_members.find(
        (elem) => elem.domain === query
      );
      if (!foundMemeber) {
        return res.status(404).json({
          error: true,
          message: "Team member not found!",
        });
      }
      const newMembers = foundUser.team_members.filter(
        (elem) => elem.domain !== query
      );
      foundUser.team_members = newMembers;
      await foundUser.save();
      res.json({
        success: true,
        message: "Member deleted successfully!",
        team: foundUser.team_members,
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);

router.post(
  "/update-notifications-settings",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { email, sms, inApp, emailSettings } = req.body;
      let foundSettings = await notificationsSettings.findOne({
        userId: req.user.id,
      });
      console.log("body:", email, sms, inApp, emailSettings);
      if (!foundSettings) {
        foundSettings = await notificationsSettings.create({
          userId: req.user.id,
        });
      }
      console.log("foundSettings b4 update:", foundSettings);

      if (email) {
        foundSettings.breachAlert.email = email;
      }
      if (sms) {
        foundSettings.breachAlert.sms = sms;
      }
      if (inApp) {
        foundSettings.breachAlert.inApp = inApp;
      }
      if (emailSettings) {
        foundSettings.emailSettings = emailSettings;
      }
      console.log("foundSettings after update:", foundSettings);
      const newSettings = await foundSettings.save();
      res.json({
        success: true,
        message: "Notifications settings Updated",
        newSettings,
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);
router.get(
  "/get-notifications-settings",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      let foundSettings = await notificationsSettings.findOne({
        userId: req.user.id,
      });
      if (!foundSettings) {
        foundSettings = await notificationsSettings.create({
          userId: req.user.id,
        });
      }

      res.json({
        success: true,

        foundSettings,
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);

router.post(
  "/update-api-integrations",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { apiName, apiKey } = req.body;

      if (!apiName || !apiKey) {
        throw new Error("Missing Api requirements, ApiKey and ApiName.");
      }

      const foundApi = await apiIntegrations.findOne({
        userId: req.user.id,
      });

      if (!foundApi) {
        const newApiIntegration = await apiIntegrations.create({
          userId: req.user.id,
          integrations: [
            {
              apiKey,
              apiName,
            },
          ],
        });
        return res.json({
          success: true,
          newApiIntegration,
        });
      }

      const foundApiNameData = foundApi.integrations.findIndex(
        (e) => e.apiName === apiName
      );

      if (foundApiNameData !== -1) {
        foundApi.integrations[foundApiNameData].apiKey = apiKey;
      } else {
        foundApi.integrations.push({
          apiKey,
          apiName,
        });
      }

      await foundApi.save();

      res.json({
        success: true,
        message: "Api integration updated",
        foundApi,
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);
router.get(
  "/get-api-integrations",
  userAuth("sme"),
  asyncErrCatcher(async (req, res, next) => {
    try {
      const foundApi = await apiIntegrations.findOne({
        userId: req.user.id,
      });

      res.json({
        success: true,

        foundApi,
      });
    } catch (err) {
      console.error(err);
      next(err.message);
    }
  })
);

module.exports = router;
