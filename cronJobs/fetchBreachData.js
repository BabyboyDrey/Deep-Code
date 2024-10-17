const redis = require("redis");
const redisClient = redis.createClient({
  host: "127.0.0.1",
  port: 6379,
});
const axios = require("axios");
const sme_users = require("../models/sme_users");
const individual_users = require("../models/individual_users");
const sendAlert = require("../utils/sendAlert");
const breaches = require("../models/breaches");
const schedule = require("node-schedule");
const mongoose = require("mongoose");

redisClient.on("error", (err) => {
  console.error("Redis error: ", err);
});

redisClient.on("connect", () => {
  console.log("Redis client connected");
});

redisClient.on("end", () => {
  console.log("Redis client disconnected. Attempting to reconnect...");
  redisClient.connect();
});

const delay = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

let isJobRunning = false;

const processSmeUsers = async () => {
  const allSmeUsers = await sme_users.find({});

  await Promise.all(
    allSmeUsers.map(async (smeUser, index) => {
      const monitoredDomains = smeUser.monitored_query_users || [];
      const currentSmeUserId = smeUser._id;
      const currentSmeUserName = smeUser.full_name;
      const currentSmeUserEmail = smeUser.company_email_address;

      await Promise.all(
        monitoredDomains.map(async (domain, i) => {
          if (i % 5 === 0) await delay(1000);

          const smeUrl = `${
            process.env.TRASHPANDA_URL
          }?domain=${encodeURIComponent(domain)}`;
          const lastScanDate = new Date();
          const nextScanDate = new Date(lastScanDate);
          nextScanDate.setHours(lastScanDate.getHours() + 24);

          try {
            const response = await axios.get(smeUrl, {
              headers: { apiKey: process.env.API_KEY },
            });

            const foundBreach = await breaches.findOne({
              userId: currentSmeUserId,
            });

            const infoEntry = smeUser.monitored_query_users_information.find(
              (info) => info.domain?.toLowerCase() === domain.toLowerCase()
            );
            console.log("infoEntry sme user:", infoEntry, "domain:", domain);

            if (infoEntry) {
              infoEntry.last_scan = lastScanDate;
              infoEntry.next_scan = nextScanDate;
            } else {
              const isDuplicate =
                smeUser.monitored_query_users_information.some(
                  (info) => info.domain?.toLowerCase() === domain.toLowerCase()
                );

              if (!isDuplicate) {
                smeUser.monitored_query_users_information.push({
                  domain: domain,
                  last_scan: lastScanDate,
                  next_scan: nextScanDate,
                });
              }
            }

            await smeUser.save();
            let newIds = [];
            const apiResults = response.data.data;
            if (foundBreach) {
              const newResults = apiResults.filter(
                (apiItem) =>
                  !foundBreach.results.some(
                    (result) => result._id.toString() === apiItem._id
                  )
              );

              if (newResults.length > 0) {
                newIds = newResults.map((item) => item._id);
                await breaches.updateOne(
                  { userId: currentSmeUserId },
                  {
                    $push: { results: { $each: newResults } },
                    updatedAt: new Date(),
                  }
                );
                sendAlert(
                  currentSmeUserEmail,
                  "domain",
                  currentSmeUserId,
                  currentSmeUserName,
                  newIds
                );
              }
            } else {
              newIds = apiResults.map((item) => item._id);
              await breaches.create({
                db_user_disg: "domain",
                userId: currentSmeUserId,
                results: apiResults,
              });
              sendAlert(
                currentSmeUserEmail,
                "domain",
                currentSmeUserId,
                currentSmeUserName,
                newIds
              );
            }
          } catch (error) {
            const infoEntry = smeUser.monitored_query_users_information.find(
              (info) => info.domain?.toLowerCase() === domain.toLowerCase()
            );
            console.log("infoEntry sme user:", infoEntry, "domain:", domain);

            if (infoEntry) {
              infoEntry.last_scan = lastScanDate;
              infoEntry.next_scan = nextScanDate;
            } else {
              const isDuplicate =
                smeUser.monitored_query_users_information.some(
                  (info) => info.domain?.toLowerCase() === domain.toLowerCase()
                );

              if (!isDuplicate) {
                smeUser.monitored_query_users_information.push({
                  domain: domain,
                  last_scan: lastScanDate,
                  next_scan: nextScanDate,
                });
              }
            }

            await smeUser.save();

            console.error(`Error fetching data for domain ${domain}:`, error);
          }
        })
      );
    })
  );
};

const processIndiUsers = async () => {
  const allIndiUsers = await individual_users.find({});

  await Promise.all(
    allIndiUsers.map(async (indiUser, index) => {
      const monitoredEmails = indiUser.monitored_query_users || [];
      const currentIndiUserId = indiUser._id;
      const currentIndiUserName = indiUser.full_name;
      const currentIndiUserEmail = indiUser.email_address;

      await Promise.all(
        monitoredEmails.map(async (email, i) => {
          if (i % 5 === 0) await delay(1000);

          const indiUrl = `${
            process.env.TRASHPANDA_URL
          }?email=${encodeURIComponent(email)}`;
          const lastScanDate = new Date();
          const nextScanDate = new Date(lastScanDate);
          nextScanDate.setHours(lastScanDate.getHours() + 24);

          try {
            const response = await axios.get(indiUrl, {
              headers: { apiKey: process.env.API_KEY },
            });

            const foundBreach = await breaches.findOne({
              userId: currentIndiUserId,
            });
            const infoEntry = indiUser.monitored_query_users_information.find(
              (info) => info.email?.toLowerCase() === email.toLowerCase()
            );
            console.log("infoEntry indi user:", infoEntry, "email:", email);

            if (infoEntry) {
              infoEntry.last_scan = lastScanDate;
              infoEntry.next_scan = nextScanDate;
            } else {
              const isDuplicate =
                indiUser.monitored_query_users_information.some(
                  (info) => info.email?.toLowerCase() === email.toLowerCase()
                );

              if (!isDuplicate) {
                indiUser.monitored_query_users_information.push({
                  email: email,
                  last_scan: lastScanDate,
                  next_scan: nextScanDate,
                });
              }
            }

            await indiUser.save();

            let newIds = [];
            const apiResults = response.data.data;
            if (foundBreach) {
              const newResults = apiResults.filter(
                (apiItem) =>
                  !foundBreach.results.some(
                    (result) => result._id.toString() === apiItem._id
                  )
              );

              if (newResults.length > 0) {
                newIds = newResults.map((item) => item._id);
                await breaches.updateOne(
                  { userId: currentIndiUserId },
                  {
                    $push: { results: { $each: newResults } },
                    updatedAt: new Date(),
                  }
                );
                sendAlert(
                  currentIndiUserEmail,
                  "email",
                  currentIndiUserId,
                  currentIndiUserName,
                  newIds
                );
              }
            } else {
              newIds = apiResults.map((item) => item._id);
              await breaches.create({
                db_user_disg: "email",
                userId: currentIndiUserId,
                results: apiResults,
              });
              sendAlert(
                currentIndiUserEmail,
                "email",
                currentIndiUserId,
                currentIndiUserName,
                newIds
              );
            }
          } catch (error) {
            const infoEntry = indiUser.monitored_query_users_information.find(
              (info) => info.email?.toLowerCase() === email.toLowerCase()
            );
            console.log("infoEntry indi user:", infoEntry, "email:", email);

            if (infoEntry) {
              infoEntry.last_scan = lastScanDate;
              infoEntry.next_scan = nextScanDate;
            } else {
              const isDuplicate =
                indiUser.monitored_query_users_information.some(
                  (info) => info.email?.toLowerCase() === email.toLowerCase()
                );

              if (!isDuplicate) {
                indiUser.monitored_query_users_information.push({
                  email: email,
                  last_scan: lastScanDate,
                  next_scan: nextScanDate,
                });
              }
            }

            await indiUser.save();

            console.error(`Error fetching data for email ${email}:`, error);
            console.log("updateEmailnOnError:", updateEmailnOnError);
          }
        })
      );
    })
  );
};

const fetchBreachedData = async () => {
  if (!redisClient.isOpen) {
    console.log("Redis client is closed. Attempting to reconnect...");
    await redisClient.connect();
  }

  const lockKey = "fetchBreachedDataLock";
  const lockTTL = 24 * 60 * 60;

  const acquiredLock = await redisClient.set(lockKey, "locked", {
    NX: true,
    EX: lockTTL,
  });

  if (!acquiredLock) {
    console.log("Another job is already running, skipping this execution.");
    return;
  }

  if (isJobRunning) {
    console.log("Job is already running, skipping this execution");
    return;
  }

  isJobRunning = true;
  console.log("Job started");

  try {
    await processIndiUsers().catch((err) => {
      console.error("Error in processIndiUsers:", err);
    });

    await processSmeUsers().catch((err) => {
      console.error("Error in processSmeUsers:", err);
    });
  } catch (error) {
    console.error("Error fetching users:", error);
  } finally {
    isJobRunning = false;
    console.log("Job finished");
    redisClient.del(lockKey);
  }
};

schedule.scheduleJob("0 0 * * *", fetchBreachedData);

console.log("Job scheduled to run every hour");
