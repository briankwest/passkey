import { Router } from 'express';
import { PasskeyController } from '../controllers/passkey.controller';
import { authenticateToken } from '../middleware/auth.middleware';

const router = Router();
const passkeyController = new PasskeyController();

// All routes require authentication
router.use(authenticateToken);

router.get('/', passkeyController.listPasskeys);
router.put('/:id', passkeyController.renamePasskey);
router.delete('/:id', passkeyController.deletePasskey);

export default router;