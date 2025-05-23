import Query from "../model/queryModel.js";
import mongoose from "mongoose";
//    Create a new query
export const createQuery = async (req, res) => {
  try {
    const { firstName, lastName, query, contactNumber } = req.body;

    const newQuery = new Query({
      name: {
        firstName,
        lastName,
      },
      contactNumber,
      query,
    });

    await newQuery.save();

    res.status(201).json({ success: true, data: query });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Controller to update the status of a query

export const updateQueryStatus = async (req, res) => {
  try {
    const { queryId } = req.params;
    const { status } = req.body;

    // Validate ObjectId
    if (!mongoose.Types.ObjectId.isValid(queryId)) {
      return res.status(400).json({
        success: false,
        message: "Invalid query ID",
      });
    }

    // Validate status value
    const validStatuses = ["pending", "resolved"];
    if (!validStatuses.includes(status)) {
      return res.status(400).json({
        success: false,
        message: `Invalid status. Allowed values: ${validStatuses.join(", ")}`,
      });
    }

    // query not found
    const query = await Query.findById(queryId);
    if (!query) {
      return res.status(404).json({
        success: false,
        message: "Query not found",
      });
    }

    // Once resolve do not make it pending
    if (query.status === "resolved" && status === "pending") {
      return res.status(400).json({
        success: false,
        message: "Cannot change status from resolved back to pending.",
      });
    }

    // Prevent re-resolving
    if (query.status === "resolved" && status === "resolved") {
      return res.status(400).json({
        success: false,
        message: "Query is already resolved.",
      });
    }

    // Update status
    query.status = status;
    await query.save();

    res.status(200).json({
      success: true,
      message: "Query status updated successfully",
      data: query,
    });
  } catch (error) {
    console.error("Error updating query status:", error);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
};

// Get all queries
export const getAllQueries = async (req, res) => {
  try {
    const queries = await Query.find();
    res.json({ success: true, data: queries });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

// Get a single query by ID
// export const getQueryById = async (req, res) => {
//   try {
//     const query = await Query.findById(req.params.id).populate(
//       "student",
//       "name email phone"
//     );
//     if (!query)
//       return res
//         .status(404)
//         .json({ success: false, message: "Query not found" });

//     res.json({ success: true, data: query });
//   } catch (error) {
//     res.status(500).json({ success: false, message: error.message });
//   }
// };

// //  Delete a query
export const deleteQuery = async (req, res) => {
  try {
    const query = await Query.findByIdAndDelete(req.params.queryId);
    if (!query)
      return res
        .status(404)
        .json({ success: false, message: "Query not found" });

    res.json({ success: true, message: "Query deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
};

export const deleteResolvedQueries = async (req, res) => {
  try {
    // delete all queries "resolve"
    const result = await Query.deleteMany({ status: "resolved" });

    if (result.deletedCount > 0) {
      return res.status(200).json({
        message: `${result.deletedCount} queries with the status 'resolved' have been deleted.`,
      });
    } else {
      return res.status(404).json({
        message: 'No queries with the status "resolved" found.',
      });
    }
  } catch (error) {
    console.error(error);
    return res.status(500).json({
      message: "An error occurred while deleting resolved queries.",
      error: error.message,
    });
  }
};
