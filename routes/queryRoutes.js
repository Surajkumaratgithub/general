import express from "express";
import {
  createQuery,
  getAllQueries,
  deleteQuery,
  deleteResolvedQueries,
  updateQueryStatus,
} from "../controller/queryController.js";
import { accessToRole, isAuth } from "../middleware/authMiddleware.js";

const router = express.Router();

router.post("/create",isAuth,accessToRole(["student"]), createQuery);

router.get("/", getAllQueries);

// router.get('/:id', getQueryById);
router.delete("/deleteAllResolved", deleteResolvedQueries);

router.patch("/:queryId", updateQueryStatus);

router.delete("/:queryId", deleteQuery);

export default router;
