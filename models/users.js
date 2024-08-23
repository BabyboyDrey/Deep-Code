const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const userSchema = new mongoose.Schema(
  {
    password: String,
    personal_info: {
      first_name: String,
      last_name: String,
      email_address: String,
      phone_number: String,
      linkedIn: String,
      twitter_x: String,
      country: String,
      city: String,
      address: String,
    },
    company_info: {
      company_name: String,
      country: String,
      city: String,
      company_email: String,
      website: String,
      industry: String,
      founding_year: Number,
      revenue: Number,
      revenue_prev_year: Number,
      gross_profit: Number,
      gross_profit_prev_year: Number,
      ebitda: Number,
      ebitda_prev_year: Number,
    },
    team_info: {
      member_1: {
        full_name: String,
        role: String,
        email_address: String,
        password: String,
      },
      member_2: {
        full_name: String,
        role: String,
        email_address: String,
        password: String,
      },
    },
    credit_card_details: {
      card_number: String,
      full_name: String,
      expiry_date: String,
      cvv: Number,
      card_password: String,
    },
  },
  {
    timestamps: true,
  }
);

userSchema.index({ "personal_info.email_address": 1 });

userSchema.methods.getJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES,
  });
};

userSchema.pre("save", function (next) {
  this.updatedAt = Date();
  next();
});

module.exports = Users = mongoose.model("Users", userSchema);
