const asyncErrCatcher = require("../middlewares/asyncErrCatcher");
const userAuth = require("../middlewares/userAuth");
const axios = require("axios");
const express = require("express");
const breaches = require("../models/breaches");
const sme_users = require("../models/sme_users");
const indi_users = require("../models/individual_users");
const router = express.Router();
require("dotenv").config();
const sendAlert = require("../utils/sendAlert.js");

// router.get(
//   "/get-breached-data",
//   userAuth,
//   asyncErrCatcher(async (req, res, next) => {
//     console.log("route hit");
//     try {
//       console.log("API Key:", process.env.API_KEY);
//       console.log("Requesting domain:", "trashpanda.dev");

//       const apiResponse = await axios.get(
//         "https://us-central1.gcp.data.mongodb-api.com/app/development-qtrcffl/endpoint/v1/accounts?domain=trashpanda.dev",
//         {
//           headers: {
//             Accept: "*/*",
//             apiKey: process.env.API_KEY,
//           },
//         }
//       );

//       console.log({
//         api_hit_success: true,
//         batch_res: apiResponse.data.data,
//       });

//       res.status(200).json(apiResponse.data);
//     } catch (error) {
//       console.error("API request failed:", error.message);
//       next(error);
//     }
//   })
// );

// router.get(
//   "/get-breached-data",
//   userAuth,
//   asyncErrCatcher(async (req, res, next) => {
//     console.log("route hit");
//     try {
//       const { email_address, domain } = req.query;
//       console.log("API Key:", process.env.API_KEY, process.env.TRASHPANDA_URL);
//       console.log("Requesting domain:", "trashpanda.dev");
//       console.log(
//         "Final URL:",
//         `${process.env.TRASHPANDA_URL}?domain=trashpanda.dev`
//       );

//       const apiResponse = await axios.get(
//         `${process.env.TRASHPANDA_URL}?domain=trashpanda.dev`,
//         {
//           headers: {
//             Accept: "*/*",
//             apiKey: process.env.API_KEY,
//           },
//         }
//       );

//       console.log({
//         api_hit_success: true,
//         batch_res: apiResponse.data.data,
//       });

//       res.status(200).json(apiResponse.data);
//     } catch (error) {
//       console.error("API request failed:", error.message);
//       next(error);
//     }
//   })
// );
router.get(
  "/get-breached-data",
  userAuth,
  asyncErrCatcher(async (req, res, next) => {
    console.log("route hit");
    try {
      const { email_address, domain } = req.query;
      const Patch = domain ? sme_users : indi_users;
      console.log("fu1:", Patch);
      const foundUser = await Patch.findOne({
        _id: req.user.id,
      }).maxTimeMS(50000);
      if (!foundUser) {
        return res.status(404).json({
          error: true,
          message: "Wrong user credentials",
        });
      }
      console.log("e:", email_address, "e:", domain);

      console.log("fu2:", foundUser);
      const recipient = domain
        ? `${foundUser.company_email_address}`
        : `${email_address}`;
      if (!domain && !email_address) {
        return res.status(400).json({
          error: true,
          message: "No query provided",
        });
      }
      const user_dsg = (domain && "domain") || (email_address && "email");
      console.log("API Key:", process.env.API_KEY, process.env.TRASHPANDA_URL);
      console.log("e:", email_address, "d", domain);
      console.log(
        "Final URL:",
        `${process.env.TRASHPANDA_URL}?${user_dsg}=${domain || email_address}`
      );

      const apiResponse = await axios.get(
        `${process.env.TRASHPANDA_URL}?${user_dsg}=${domain || email_address}`,
        {
          headers: {
            apiKey: process.env.API_KEY,
          },
        }
      );

      const found_breach = await breaches.findOne({
        userId: req.user.id,
      });
      console.log("vvb:", found_breach);
      if (found_breach) {
        console.log("apiR:", apiResponse.data.data);

        const updateResult = await breaches.findOneAndUpdate(
          {
            userId: req.user.id,
          },
          {
            $push: {
              results: { $each: apiResponse.data.data },
            },
          },
          {
            upsert: true,
            new: true,
          }
        );
        updateResult.updatedAt = new Date();
        updateResult.save();
        console.log("==;:", updateResult);
        sendAlert(recipient, user_dsg, req.user.id, foundUser.full_name);
        return res.status(200).json({
          success: true,
          message: "Breached data successfully retieved!",
        });
      }

      console.log({
        api_hit_success: true,
        batch_res: apiResponse.data.data,
      });
      await breaches.create({
        db_user_disg: user_dsg,
        userId: req.user.id,
        results: apiResponse.data.data,
      });
      res.status(200).json({
        success: true,
        message: "New Breached data successfully retieved!",
      });
    } catch (error) {
      console.error("API request failed:", error.message);
      next(error);
    }
  })
);

module.exports = router;
