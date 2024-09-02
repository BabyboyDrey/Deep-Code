const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const individualUserSchema = new mongoose.Schema(
  {
    password: String,
    full_name: String,
    email_address: String,
    googleId: String,
    avatar: String,
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