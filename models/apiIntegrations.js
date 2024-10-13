const mongoose = require("mongoose");

const apiIntegrationSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: "User",
  },
  integrations: [
    {
      apiName: String,
      apiKey: String,
    },
  ],
});

module.exports = Apiintegration = mongoose.model(
  "Apiintegration",
  apiIntegrationSchema
);
