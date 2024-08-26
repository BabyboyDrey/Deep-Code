const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const smeUserSchema = new mongoose.Schema(
  {
    password: String,
    full_name: String,
    company_name: String,
    company_email_address: String,
    googleId: String,
    avatar: String,
  },
  {
    timestamps: true,
  }
);

smeUserSchema.index({ company_email_address: 1 });

smeUserSchema.methods.getJwtToken = function () {
  return jwt.sign({ id: this._id }, process.env.JWT_SECRET, {
    expiresIn: process.env.JWT_EXPIRES,
  });
};

smeUserSchema.pre("save", function (next) {
  this.updatedAt = Date();
  next();
});

module.exports = Sme_Users = mongoose.model("Sme_Users", smeUserSchema);
