import { Router } from 'express';

import {
    GetSecurityConfigHandler,
    UpdateSecurityConfigHandler,
    GenerateSecureTokenHandler,
    GetSecurityStatusHandler,
} from '@webapi/api/Security';

const router = Router();

// router: 获取安全配置
router.get('/config', GetSecurityConfigHandler);

// router: 更新安全配置
router.post('/config', UpdateSecurityConfigHandler);

// router: 生成安全令牌
router.post('/generate-token', GenerateSecureTokenHandler);

// router: 获取安全状态
router.get('/status', GetSecurityStatusHandler);

export { router as SecurityRouter };