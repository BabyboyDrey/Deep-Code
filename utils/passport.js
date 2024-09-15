const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const expressSession = require("express-session");
const OAuthToken = require("../models/oauthToken.js");
const SME_users = require("../models/sme_users.js");
const Indi_users = require("../models/individual_users.js");
require("dotenv").config();

async function saveOAuthToken(
  userId,
  accessToken,
  refreshToken,
  expiresAt,
  provider
) {
  await OAuthToken.deleteMany({ userId, provider });
  const token = new OAuthToken({
    userId,
    accessToken,
    refreshToken,
    expiresAt,
    provider,
  });
  await token.save();
}

passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:
        "http://localhost:5002/api/v1/indi-user/auth/google/callback",
      scope: ["profile", "email"],
      passReqToCallback: true,
    },
    async (req, accessToken, refreshToken, profile, done) => {
      try {
        const { id, emails, displayName, photos } = profile;
        const email = emails && emails.length > 0 ? emails[0].value : null;
        const picture = photos && photos.length > 0 ? photos[0].value : null;

        const role = req.query.state;
        console.log("req.query.state:", req.query.state, role);
        let user;
        if (role === "sme") {
          user = await SME_users.findOne({ googleId: id });
          console.log("sme user:", user);

          if (!user && email) {
            user = await SME_users.findOne({ company_email_address: email });

            if (!user) {
              user = await SME_users.create({
                googleId: id,
                company_email_address: email,
                avatar: picture,
                full_name: displayName,
              });
            } else {
              user.googleId = id;
              await user.save();
            }
          }
        } else {
          user = await Indi_users.findOne({ googleId: id });
          if (!user && email) {
            user = await Indi_users.findOne({ email_address: email });

            if (!user) {
              user = await Indi_users.create({
                googleId: id,
                email_address: email,
                avatar: picture,
                full_name: displayName,
              });
            } else {
              user.googleId = id;
              await user.save();
            }
          }
        }

        await saveOAuthToken(
          user._id,
          accessToken,
          refreshToken,
          new Date(Date.now() + 8 * 60 * 60 * 1000),
          "google"
        );

        return done(null, user);
      } catch (error) {
        return done(error, null);
      }
    }
  )
);

passport.serializeUser((user, callback) => {
  callback(null, user.id);
});

passport.deserializeUser(async (data, callback) => {
  try {
    const { id, role } = data;
    let user;
    if (role === "sme") {
      user = await SME_users.findById(id);
    } else {
      user = await Indi_users.findById(id);
    }
    callback(null, user);
  } catch (error) {
    callback(error, null);
  }
});

module.exports = passport;
