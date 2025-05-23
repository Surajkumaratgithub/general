import { Router } from 'express';
import { createAdmin } from '../controller/adminController.js';
// import all controllers

const router = new Router();

// Add router
router.get('/', );
router.post('/create',createAdmin);
// router.put('/', SessionController.store);
// router.delete('/', SessionController.store);

export default router;
