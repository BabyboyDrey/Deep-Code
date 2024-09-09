const mongoose = require("mongoose");

const singleResultSchema = new mongoose.Schema({
  result_id: String,
  username: String,
  password: String,
  updated_on: String,
  domain: String,
  url: String,
  email: String,
  email_domain: String,
  id: Number,
  log_id: String,
});

const breachesSchema = new mongoose.Schema(
  {
    db_user_disg: String,
    origin_email_or_domain_of_breach: String,
    userId: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
    },
    results: [singleResultSchema],
  },
  {
    timestamps: true,
  }
);

module.exports = Breaches = mongoose.model("Breaches", breachesSchema);
