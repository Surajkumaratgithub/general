import express from "express";
import { createBranch, getAllBranches } from "../controller/branchController.js";
import { accessToRole, isAuth} from "../middleware/authMiddleware.js";

const router = express.Router();
// GET 
//Route to get all branches
router.get('/',getAllBranches)

router.post('/create',isAuth ,accessToRole(['superadmin']), createBranch)


export default router;