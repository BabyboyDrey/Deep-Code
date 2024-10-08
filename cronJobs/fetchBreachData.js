const cron = require("node-cron");
const axios = require("axios");
const sme_users = require("../models/sme_users");
const individual_users = require("../models/individual_users");
const sendAlert = require("../utils/sendAlert");
const breaches = require("../models/breaches");

// const fetchBreachedData = async () => {
//   try {
//     const allSmeUsers = await sme_users.find({});

//     // Process SME Users
//     for (const smeUser of allSmeUsers) {
//       const monitoredDomains = smeUser.monitored_query_users || [];
//       const currentSmeUserId = smeUser._id;
//       const currentSmeUserName = smeUser.full_name;
//       const currentSmeUserEmail = smeUser.company_email_address;

//       for (const domain of monitoredDomains) {
//         const smeUrl = `${
//           process.env.TRASHPANDA_URL
//         }?domain=${encodeURIComponent(domain)}`;

//         try {
//           const response = await axios.get(smeUrl, {
//             headers: {
//               apiKey: process.env.API_KEY,
//             },
//           });

//           const foundBreach = await breaches.findOne({
//             userId: currentSmeUserId,
//           });
//           let newIds = [];

//           const lastScanDate = new Date();
//           const nextScanDate = new Date(lastScanDate);
//           nextScanDate.setHours(lastScanDate.getHours() + 24);

//           const infoEntry = smeUser.monitored_query_users_information.find(
//             (info) => info.domain === domain
//           );
//           console.log("infoEntry sme user:", infoEntry, "domain:", domain);
//           if (infoEntry) {
//             infoEntry.last_scan = lastScanDate;
//             infoEntry.next_scan = nextScanDate;
//           } else {
//             smeUser.monitored_query_users_information.push({
//               domain: domain,
//               last_scan: lastScanDate,
//               next_scan: nextScanDate,
//             });
//           }

//           await smeUser.save();

//           if (foundBreach) {
//             const newResults = response.data.data.filter(
//               (apiItem) =>
//                 !foundBreach.results.some(
//                   (result) => result._id.toString() === apiItem._id
//                 )
//             );

//             if (newResults.length > 0) {
//               newIds = newResults.map((item) => item._id);
//               await breaches.updateOne(
//                 { userId: currentSmeUserId },
//                 { $push: { results: { $each: newResults } } }
//               );

//               foundBreach.updatedAt = new Date();
//               await foundBreach.save();

//               sendAlert(
//                 currentSmeUserEmail,
//                 "domain",
//                 currentSmeUserId,
//                 currentSmeUserName,
//                 newIds
//               );
//               console.log(
//                 `New breach data successfully retrieved for ${currentSmeUserEmail}. Alert sent!`
//               );
//             } else {
//               console.log(
//                 `No new breaches to update for ${currentSmeUserEmail}`
//               );
//             }
//           } else {
//             newIds = response.data.data.map((item) => item._id);
//             await breaches.create({
//               db_user_disg: "domain",
//               userId: currentSmeUserId,
//               results: response.data.data,
//             });
//             sendAlert(
//               currentSmeUserEmail,
//               "domain",
//               currentSmeUserId,
//               currentSmeUserName,
//               newIds
//             );
//             console.log(
//               `New breaches successfully retrieved for ${currentSmeUserEmail}. Alert sent!`
//             );
//           }
//         } catch (error) {
//           console.error(`Error fetching data for domain ${domain}:`, error);

//           const lastScanDate = new Date();
//           const nextScanDate = new Date(lastScanDate);
//           nextScanDate.setHours(lastScanDate.getHours() + 24);

//           const infoEntry = smeUser.monitored_query_users_information.find(
//             (info) => info.domain === domain
//           );
//           console.log("infoEntry sme user:", infoEntry, "domain:", domain);
//           if (infoEntry) {
//             infoEntry.last_scan = lastScanDate;
//             infoEntry.next_scan = nextScanDate;
//           } else {
//             smeUser.monitored_query_users_information.push({
//               domain: domain,
//               last_scan: lastScanDate,
//               next_scan: nextScanDate,
//             });
//           }

//           await smeUser.save();
//         }
//       }
//     }

//     const allIndiUsers = await individual_users.find({});

//     // Process Individual Users
//     for (const indiUser of allIndiUsers) {
//       const monitoredEmails = indiUser.monitored_query_users || [];
//       const currentIndiUserId = indiUser._id;
//       const currentIndiUserName = indiUser.full_name;
//       const currentIndiUserEmail = indiUser.email_address;

//       for (const email of monitoredEmails) {
//         const indiUrl = `${
//           process.env.TRASHPANDA_URL
//         }?email=${encodeURIComponent(email)}`;

//         try {
//           const response = await axios.get(indiUrl, {
//             headers: {
//               apiKey: process.env.API_KEY,
//             },
//           });

//           const foundBreach = await breaches.findOne({
//             userId: currentIndiUserId,
//           });
//           let newIds = [];

//           const lastScanDate = new Date();
//           const nextScanDate = new Date(lastScanDate);
//           nextScanDate.setHours(lastScanDate.getHours() + 24);

//           const infoEntry = indiUser.monitored_query_users_information.find(
//             (info) => info.email === email
//           );
//           console.log("infoEntry indi user:", infoEntry, "email:", email);
//           if (infoEntry) {
//             infoEntry.last_scan = lastScanDate;
//             infoEntry.next_scan = nextScanDate;
//           } else {
//             indiUser.monitored_query_users_information.push({
//               email: email,
//               last_scan: lastScanDate,
//               next_scan: nextScanDate,
//             });
//           }

//           await indiUser.save();

//           if (foundBreach) {
//             const newResults = response.data.data.filter(
//               (apiItem) =>
//                 !foundBreach.results.some(
//                   (result) => result._id.toString() === apiItem._id
//                 )
//             );

//             if (newResults.length > 0) {
//               newIds = newResults.map((item) => item._id);
//               await breaches.updateOne(
//                 { userId: currentIndiUserId },
//                 { $push: { results: { $each: newResults } } }
//               );

//               foundBreach.updatedAt = new Date();
//               await foundBreach.save();

//               sendAlert(
//                 currentIndiUserEmail,
//                 "email",
//                 currentIndiUserId,
//                 currentIndiUserName,
//                 newIds
//               );
//               console.log(
//                 `New breach data successfully retrieved for ${currentIndiUserEmail}. Alert sent!`
//               );
//             } else {
//               console.log(
//                 `No new breaches to update for ${currentIndiUserEmail}`
//               );
//             }
//           } else {
//             newIds = response.data.data.map((item) => item._id);
//             await breaches.create({
//               db_user_disg: "email",
//               userId: currentIndiUserId,
//               results: response.data.data,
//             });
//             sendAlert(
//               currentIndiUserEmail,
//               "email",
//               currentIndiUserId,
//               currentIndiUserName,
//               newIds
//             );
//             console.log(
//               `New breaches successfully retrieved for ${currentIndiUserEmail}. Alert sent!`
//             );
//           }
//         } catch (error) {
//           console.error(`Error fetching data for email ${email}:`, error);

//           const lastScanDate = new Date();
//           const nextScanDate = new Date(lastScanDate);
//           nextScanDate.setHours(lastScanDate.getHours() + 24);

//           const infoEntry = indiUser.monitored_query_users_information.find(
//             (info) => info.email === email
//           );
//           console.log("infoEntry indi user:", infoEntry, "email:", email);
//           if (infoEntry) {
//             infoEntry.last_scan = lastScanDate;
//             infoEntry.next_scan = nextScanDate;
//           } else {
//             indiUser.monitored_query_users_information.push({
//               email: email,
//               last_scan: lastScanDate,
//               next_scan: nextScanDate,
//             });
//           }

//           await indiUser.save();
//         }
//       }
//     }
//   } catch (error) {
//     console.error("Error fetching users:", error);
//   }
// };

const fetchBreachedData = async () => {
  try {
    const allSmeUsers = await sme_users.find({});

    // Process SME Users
    for (const smeUser of allSmeUsers) {
      const monitoredDomains = smeUser.monitored_query_users || [];
      const currentSmeUserId = smeUser._id;
      const currentSmeUserName = smeUser.full_name;
      const currentSmeUserEmail = smeUser.company_email_address;

      for (const domain of monitoredDomains) {
        const smeUrl = `${
          process.env.TRASHPANDA_URL
        }?domain=${encodeURIComponent(domain)}`;

        try {
          const response = await axios.get(smeUrl, {
            headers: {
              apiKey: process.env.API_KEY,
            },
          });

          const foundBreach = await breaches.findOne({
            userId: currentSmeUserId,
          });
          let newIds = [];

          const lastScanDate = new Date();
          const nextScanDate = new Date(lastScanDate);
          nextScanDate.setHours(lastScanDate.getHours() + 24);

          const infoEntry = smeUser.monitored_query_users_information.find(
            (info) => info.domain?.toLowerCase() === domain.toLowerCase()
          );
          console.log("infoEntry sme user:", infoEntry, "domain:", domain);

          if (infoEntry) {
            infoEntry.last_scan = lastScanDate;
            infoEntry.next_scan = nextScanDate;
          } else {
            const isDuplicate = smeUser.monitored_query_users_information.some(
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

          if (foundBreach) {
            const newResults = response.data.data.filter(
              (apiItem) =>
                !foundBreach.results.some(
                  (result) => result._id.toString() === apiItem._id
                )
            );

            if (newResults.length > 0) {
              newIds = newResults.map((item) => item._id);
              await breaches.updateOne(
                { userId: currentSmeUserId },
                { $push: { results: { $each: newResults } } }
              );

              foundBreach.updatedAt = new Date();
              await foundBreach.save();

              sendAlert(
                currentSmeUserEmail,
                "domain",
                currentSmeUserId,
                currentSmeUserName,
                newIds
              );
              console.log(
                `New breach data successfully retrieved for ${currentSmeUserEmail}. Alert sent!`
              );
            } else {
              console.log(
                `No new breaches to update for ${currentSmeUserEmail}`
              );
            }
          } else {
            newIds = response.data.data.map((item) => item._id);
            await breaches.create({
              db_user_disg: "domain",
              userId: currentSmeUserId,
              results: response.data.data,
            });
            sendAlert(
              currentSmeUserEmail,
              "domain",
              currentSmeUserId,
              currentSmeUserName,
              newIds
            );
            console.log(
              `New breaches successfully retrieved for ${currentSmeUserEmail}. Alert sent!`
            );
          }
        } catch (error) {
          console.error(`Error fetching data for domain ${domain}:`, error);

          const lastScanDate = new Date();
          const nextScanDate = new Date(lastScanDate);
          nextScanDate.setHours(lastScanDate.getHours() + 24);

          const infoEntry = smeUser.monitored_query_users_information.find(
            (info) => info.domain?.toLowerCase() === domain.toLowerCase()
          );
          console.log("infoEntry sme user:", infoEntry, "domain:", domain);
          if (infoEntry) {
            infoEntry.last_scan = lastScanDate;
            infoEntry.next_scan = nextScanDate;
          } else {
            const isDuplicate = smeUser.monitored_query_users_information.some(
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
        }
      }
    }

    const allIndiUsers = await individual_users.find({});

    // Process Individual Users
    for (const indiUser of allIndiUsers) {
      const monitoredEmails = indiUser.monitored_query_users || [];
      const currentIndiUserId = indiUser._id;
      const currentIndiUserName = indiUser.full_name;
      const currentIndiUserEmail = indiUser.email_address;

      for (const email of monitoredEmails) {
        const indiUrl = `${
          process.env.TRASHPANDA_URL
        }?email=${encodeURIComponent(email)}`;

        try {
          const response = await axios.get(indiUrl, {
            headers: {
              apiKey: process.env.API_KEY,
            },
          });

          const foundBreach = await breaches.findOne({
            userId: currentIndiUserId,
          });
          let newIds = [];

          const lastScanDate = new Date();
          const nextScanDate = new Date(lastScanDate);
          nextScanDate.setHours(lastScanDate.getHours() + 24);

          const infoEntry = indiUser.monitored_query_users_information.find(
            (info) => info.email?.toLowerCase() === email.toLowerCase()
          );
          console.log("infoEntry indi user:", infoEntry, "email:", email);

          if (infoEntry) {
            infoEntry.last_scan = lastScanDate;
            infoEntry.next_scan = nextScanDate;
          } else {
            const isDuplicate = indiUser.monitored_query_users_information.some(
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

          if (foundBreach) {
            const newResults = response.data.data.filter(
              (apiItem) =>
                !foundBreach.results.some(
                  (result) => result._id.toString() === apiItem._id
                )
            );

            if (newResults.length > 0) {
              newIds = newResults.map((item) => item._id);
              await breaches.updateOne(
                { userId: currentIndiUserId },
                { $push: { results: { $each: newResults } } }
              );

              foundBreach.updatedAt = new Date();
              await foundBreach.save();

              sendAlert(
                currentIndiUserEmail,
                "email",
                currentIndiUserId,
                currentIndiUserName,
                newIds
              );
              console.log(
                `New breach data successfully retrieved for ${currentIndiUserEmail}. Alert sent!`
              );
            } else {
              console.log(
                `No new breaches to update for ${currentIndiUserEmail}`
              );
            }
          } else {
            newIds = response.data.data.map((item) => item._id);
            await breaches.create({
              db_user_disg: "email",
              userId: currentIndiUserId,
              results: response.data.data,
            });
            sendAlert(
              currentIndiUserEmail,
              "email",
              currentIndiUserId,
              currentIndiUserName,
              newIds
            );
            console.log(
              `New breaches successfully retrieved for ${currentIndiUserEmail}. Alert sent!`
            );
          }
        } catch (error) {
          console.error(`Error fetching data for email ${email}:`, error);

          const lastScanDate = new Date();
          const nextScanDate = new Date(lastScanDate);
          nextScanDate.setHours(lastScanDate.getHours() + 24);

          const infoEntry = indiUser.monitored_query_users_information.find(
            (info) => info.email?.toLowerCase() === email.toLowerCase()
          );
          console.log("infoEntry indi user:", infoEntry, "email:", email);

          if (infoEntry) {
            infoEntry.last_scan = lastScanDate;
            infoEntry.next_scan = nextScanDate;
          } else {
            const isDuplicate = indiUser.monitored_query_users_information.some(
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
        }
      }
    }
  } catch (error) {
    console.error("Error fetching users:", error);
  }
};
cron.schedule("0 0 * * *", fetchBreachedData);

console.log("Cron job scheduled to run every hour");
