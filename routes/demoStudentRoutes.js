import express from "express";
import { demoLogin, registerForDemo } from "../controller/demoStudentController.js";


const router = express.Router();

router.post("/register", registerForDemo);
router.post("/login", demoLogin);

export default router;