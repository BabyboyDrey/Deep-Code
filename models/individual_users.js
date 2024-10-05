const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const individualUserSchema = new mongoose.Schema(
  {
    password: String,
    full_name: String,
    email_address: String,
    googleId: String,
    avatar: String,
    monitored_query_users: [String],
    monitored_query_users_information: [
      {
        email: { type: String, unique: true },
        last_scan: Date,
        next_scan: Date,
      },
    ],
  },
  {
    timestamps: true,
  }
);

individualUserSchema.index({ email_address: 1 });

individualUserSchema.methods.getJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES,
  });
};

individualUserSchema.pre("save", function (next) {
  this.updatedAt = Date();
  next();
});

module.exports = Indi_Users = mongoose.model(
  " Indi_Users",
  individualUserSchema
);
