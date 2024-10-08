const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");

const teamMembersSchema = new mongoose.Schema({
  domain: String,
  full_name: String,
  password: String,
  role: String,
  last_login: {
    type: Date,
  },
  status: {
    type: String,
    default: "Pending",
  },
});

const smeUserSchema = new mongoose.Schema(
  {
    password: String,
    full_name: String,
    company_name: String,
    company_email_address: String,
    googleId: String,
    avatar: String,
    monitored_query_users: [String],
    team_members: [teamMembersSchema],
    monitored_query_users_information: [
      {
        domain: { type: String, unique: true },
        last_scan: Date,
        next_scan: Date,
      },
    ],
  },
  {
    timestamps: true,
  }
);

smeUserSchema.index({ company_email_address: 1 });
individualUserSchema.index({ "monitored_query_users_information.domain": 1 });

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
