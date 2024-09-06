const Alerts = require("../models/alerts");
const sendMail = require("./sendMail");

async function sendAlert(recipient, db_user_disg, userId, full_name) {
  console.log("ghs:", recipient, db_user_disg, userId, full_name);
  const newAlert = await Alerts.create({
    userId,
    breach_confirmed: true,
    date_sent: new Date(),
    recipient,
    db_user_disg,
  });
  console.log("sucAler:", newAlert);
  sendMail({
    email: recipient,
    subject: "Breach Alert!",
    context: {
      userName: full_name,
      message: " activate your account.",
      subject: "Account Verification Code",
    },
  });
}

module.exports = sendAlert;
