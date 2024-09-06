const mongoose = require("mongoose");

const alertsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  breach_confirmed: Boolean,
  date_sent: Date,
  recipient: String,
  db_user_disg: String,
});

module.exports = Alerts = mongoose.model("Alerts", alertsSchema);
