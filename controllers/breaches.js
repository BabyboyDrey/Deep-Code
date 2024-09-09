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
      console.log("e:", email_address, "d:", domain);

      const recipient = domain
        ? `${foundUser.company_email_address}`
        : `${email_address}`;
      if (!domain && !email_address) {
        return res.status(400).json({
          error: true,
          message: "No query provided",
        });
      }
      const queryParam = domain || email_address;
      const foundQuery = foundUser.monitored_query_users.find(
        (e) => e === queryParam
      );

      console.log("foundQuery:", foundQuery);
      if (!foundQuery) {
        return res.status(404).json({
          error: true,
          message: "Provided query not found!",
        });
      }

      const user_dsg = (domain && "domain") || (email_address && "email");
      console.log("API Key:", process.env.API_KEY, process.env.TRASHPANDA_URL);
      console.log("e:", email_address, "d", domain);
      console.log(
        "Final URL:",
        `${process.env.TRASHPANDA_URL}?${user_dsg}=${queryParam}`
      );

      const apiResponse = await axios.get(
        `${process.env.TRASHPANDA_URL}?${user_dsg}=${queryParam}`,
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
            message: "Breached data successfully updated! Alert sent!",
          });
        } else {
          console.log("No new breaches to update");
          return res.status(200).json({
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
        message: "New Breached data successfully retrieved. Alert sent!",
      });
    } catch (error) {
      console.error("API request failed:", error.message);
      next(error);
    }
  })
);

router.get(
  "/get-all-breaches",
  userAuth,
  asyncErrCatcher(async (req, res) => {
    try {
      const all_breaches = await breaches.findOne({
        userId: req.user.id,
      });

      if (all_breaches.length === 0)
        return res.status(404).json({
          error: true,
          message: "No breach found",
        });

      const allbreaches = all_breaches.results;

      res.json({
        allbreaches,
        createdAt: all_breaches.createdAt,
        updatedAt: all_breaches.updatedAt,
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

module.exports = router;
