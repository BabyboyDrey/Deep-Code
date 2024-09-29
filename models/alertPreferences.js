const mongoose = require("mongoose");

const alertsPreferencesSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  alertChannels: {
    email: {
      type: Boolean,
      default: true,
    },
    inApp: {
      type: Boolean,
      default: false,
    },
    smsAlerts: {
      type: Boolean,
      default: false,
    },
  },
  emailAlert: {
    type: String,
    default: "Immediately",
  },
  severity: {
    type: String,
    default: "High",
  },
});

module.exports = AlertsPreferences = mongoose.model(
  "AlertsPreferences",
  alertsPreferencesSchema
);
