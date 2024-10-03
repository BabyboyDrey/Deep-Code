const nodemailer = require("nodemailer");
const fs = require("fs");
const path = require("path");

const sendMail = async (options) => {
  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: process.env.SMTP_PORT,
    service: process.env.SMTP_SERVICE,
    auth: {
      user: process.env.SMTP_MAIL,
      pass: process.env.SMTP_PASSWORD,
    },
  });

  let templatePath;
  if (options.context.type === "Alert") {
    templatePath = path.resolve("./views/sendAlert.html");
  } else if (options.context.type === "Team") {
    templatePath = path.resolve("./views/team_member_set_password.html");
  } else {
    templatePath = path.resolve("./views/activation_template.html");
  }
  let htmlTemplate = fs.readFileSync(templatePath, "utf8");
  console.log("options:", options.context);
  htmlTemplate = htmlTemplate
    .replace("{{userName}}", options.context.userName)
    .replace("{{activationCode}}", options.context.activationCode)
    .replace("{{message}}", options.context.message);

  console.log("options message:", options.context.message);
  console.log("Using template:", templatePath);
  console.log("Sending mail to:", options.email);
  const mailOptions = {
    from: process.env.SMTP_MAIL,
    to: options.email,
    subject: options.subject,
    html: htmlTemplate,
  };

  await transporter.sendMail(mailOptions);
};

module.exports = sendMail;
