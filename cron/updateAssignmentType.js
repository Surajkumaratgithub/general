// /cron/updateAssignmentStatus.js
import cron from "node-cron";
import Assignment from "../model/teaches/Assignment.js";

cron.schedule("0 0 * * *", async () => {
  console.log("Running cron job to update assignment deadlineStatus...");

  const now = new Date();

  try {
    const result = await Assignment.updateMany(
      {
        status: "public",
        dueDate: { $lt: now },
        deadlineStatus: { $ne: "expired" },
      },
      {
        $set: { deadlineStatus: "expired" },
      }
    );

    console.log(
      ` ${
        result.modifiedCount || result.nModified
      } assignment(s) marked as expired.`
    );
  } catch (err) {
    console.error(" Cron job error:", err.message);
  }
});
