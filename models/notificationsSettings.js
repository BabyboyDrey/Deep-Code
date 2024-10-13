const mongoose = require("mongoose");

const notificationsSettingsSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  breachAlert: {
    email: {
      type: Boolean,
      default: true,
    },
    sms: {
      type: Boolean,
      default: false,
    },
    inApp: {
      type: Boolean,
      default: false,
    },
  },
  emailSettings: {
    type: String,
    default: "Immediately",
  },
});

module.exports = Notificationsettings = mongoose.model(
  "Notificationsettings",
  notificationsSettingsSchema
);
