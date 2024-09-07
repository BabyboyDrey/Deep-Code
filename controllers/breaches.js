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
//       const { email_address, domain } = req.query;
//       const Patch = domain ? sme_users : indi_users;
//       console.log("fu1:", Patch);

//       const foundUser = await Patch.findOne({
//         _id: req.user.id,
//       }).maxTimeMS(50000);

//       if (!foundUser) {
//         return res.status(404).json({
//           error: true,
//           message: "Wrong user credentials",
//         });
//       }

//       const recipient = domain
//         ? foundUser.company_email_address
//         : email_address;
//       if (!domain && !email_address) {
//         return res.status(400).json({
//           error: true,
//           message: "No query provided",
//         });
//       }

//       const user_dsg = domain ? "domain" : "email";
//       console.log("API Key:", process.env.API_KEY, process.env.TRASHPANDA_URL);

//       const apiResponse = await axios.get(
//         `${process.env.TRASHPANDA_URL}?${user_dsg}=${domain || email_address}`,
//         { headers: { apiKey: process.env.API_KEY } }
//       );

//       const found_breach = await breaches.findOne({ userId: req.user.id });
//       let newResultsIds = []; // Initialize as an empty array to ensure it is always defined
//       console.log("found_breach", found_breach);
//       if (found_breach) {
//         const existingIds = new Set(
//           found_breach.results.map((item) => item._id.toString())
//         );

//         const newResults = apiResponse.data.data.filter(
//           (apiItem) => !existingIds.has(apiItem._id)
//         );
//         newResultsIds = newResults.map((item) => item._id); // IDs for new breach data
//         console.log("ids_br:", newResultsIds);

//         if (newResults.length > 0) {
//           await breaches.updateOne(
//             { userId: req.user.id },
//             { $push: { results: { $each: newResults } } },
//             { $set: { updatedAt: new Date() } }
//           );
//           console.log("Updated with new breach data:", newResults);
//           found_breach.updatedAt = new Date();
//           await found_breach.save();
//         } else {
//           console.log("No new breaches to update");
//           return res.status(404).json({
//             error: false,
//             message: "No new breached data",
//           });
//         }
//       }

//       // Ensure sendAlert is called with properly defined newResultsIds
//       sendAlert(
//         recipient,
//         user_dsg,
//         req.user.id,
//         foundUser.full_name,
//         newResultsIds
//       );
//       return res.status(200).json({
//         success: true,
//         message: "Breached data successfully retrieved and updated!",
//       });
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
      let newIds;
      if (found_breach) {
        let newResultsId = [];

        console.log("apiR:", apiResponse.data.data);
        const newResults = apiResponse.data.data.filter(
          (apiItem) =>
            !found_breach.results.some(
              (result) => result._id.toString() === apiItem._id
            )
        );
        console.log("newR:", newResults);
        if (newResults.length > 0) {
          console.log("new r hit");
          newResultsId = newResults.map((item) => {
            console.log(item);
            return item._id;
          });
          console.log("90:", newResultsId);
          await breaches.updateOne(
            { userId: req.user.id },
            { $push: { results: { $each: newResults } } }
          );
          console.log("Updated with new breach data:", newResults);
          found_breach.updatedAt = new Date();
          found_breach.save();
          sendAlert(
            recipient,
            user_dsg,
            req.user.id,
            foundUser.full_name,
            newResultsId
          );
          return res.status(200).json({
            success: true,
            message: "Breached data successfully retrieved and updated!",
          });
        } else {
          console.log("No new breaches to update");
          return res.status(203).json({
            error: false,
            message: "No new breached data",
          });
        }
      } else {
        newIds = apiResponse.data.data.map((item) => {
          console.log(item);
          return item._id;
        });
      }

      console.log({
        api_hit_success: true,
        batch_res: apiResponse.data.data,
      });
      sendAlert(recipient, user_dsg, req.user.id, foundUser.full_name, newIds);
      await breaches.create({
        db_user_disg: user_dsg,
        userId: req.user.id,
        results: apiResponse.data.data,
      });
      res.status(200).json({
        success: true,
        message: "New Breached data successfully retrieved!",
      });
    } catch (error) {
      console.error("API request failed:", error.message);
      next(error);
    }
  })
);

module.exports = router;
