const asyncErrCatcher = require("../middlewares/asyncErrCatcher");
const userAuth = require("../middlewares/userAuth");
const Alerts = require("../models/alerts");
const breaches = require("../models/breaches");
const router = require("express").Router();
const mongoose = require("mongoose");

router.get(
  "/get-alert/:id",
  userAuth,
  asyncErrCatcher(async (req, res, next) => {
    try {
      const { id } = req.params;
      console;
      const foundAlert = await Alerts.findOne({
        _id: id,
        userId: req.user.id,
      });
      if (!foundAlert) {
        return res.status(404).json({
          error: true,
          message: "No alerts found",
        });
      }
      const foundBreach = await breaches.findOne({
        userId: req.user.id,
      });
      function findMatchingDocs(foundAlert, foundBreach) {
        const idsToMatch = foundAlert.breach_result_ids;

        const matchedResults = foundBreach.results.filter((result) =>
          idsToMatch.includes(result._id)
        );

        return matchedResults;
      }
      const matchedDocs = findMatchingDocs(foundAlert, foundBreach);
      res.json({
        matchedDocs,
      });
    } catch (err) {
      console.error(err.message);
      res.status(500).json({
        error: true,
        message: err.message,
      });
    }
  })
);

router.get(
  "/get-all-alerts",
  userAuth,
  asyncErrCatcher(async (req, res) => {
    try {
      const all_alerts = await Alerts.find({
        userId: req.user.id,
      }).sort({ date_sent: -1 });

      if (all_alerts.length === 0) {
        return res.status(404).json({
          error: true,
          message: "No alerts found",
        });
      }

      let breachResultIds = all_alerts.reduce((acc, alert) => {
        if (alert.breach_result_ids && alert.breach_result_ids.length > 0) {
          return acc.concat(
            alert.breach_result_ids.map((id) => new mongoose.Types.ObjectId(id))
          );
        }
        return acc;
      }, []);
      console.log("breach ids:", breachResultIds);
      breachResultIds = [...new Set(breachResultIds)];
      console.log("breach ids after:", breachResultIds);

      const breachData = await breaches.find({
        userId: req.user.id,
        "results._id": { $in: breachResultIds },
      });

      res.json({
        breachData,
        all_alerts,
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
