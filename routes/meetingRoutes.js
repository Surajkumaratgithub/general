import express from 'express';
import { scheduleMeeting} from '../controller/meetingController.js';

const router = express.Router()

router.post('/schedule', scheduleMeeting);


export default router;