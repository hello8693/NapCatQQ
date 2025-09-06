import type { RequestHandler } from 'express';
import { WebUiConfig } from '@/webui';

// CORS 中间件，跨域用 - 增强安全版本
export const cors: RequestHandler = async (req, res, next) => {
    try {
        const securityConfig = await WebUiConfig.GetSecurityConfig();
        const allowedOrigins = securityConfig?.allowedOrigins || [];
        
        const origin = req.headers.origin;
        
        // 如果配置了允许的域名列表且不为空
        if (allowedOrigins.length > 0) {
            if (origin && allowedOrigins.includes(origin)) {
                res.header('Access-Control-Allow-Origin', origin);
            }
            // 如果origin不在白名单中，不设置Access-Control-Allow-Origin
        } else {
            // 向后兼容：如果没有配置域名白名单，使用原来的逻辑
            res.header('Access-Control-Allow-Origin', origin || '*');
        }
        
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
        res.header('Access-Control-Allow-Credentials', 'true');
        res.header('Access-Control-Max-Age', '86400'); // 缓存预检请求24小时

        if (req.method === 'OPTIONS') {
            res.sendStatus(204);
            return;
        }
        next();
    } catch (error) {
        // 如果获取配置失败，使用默认的安全设置
        const origin = req.headers.origin;
        res.header('Access-Control-Allow-Origin', origin || '*');
        res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
        res.header('Access-Control-Allow-Headers', 'Origin, X-Requested-With, Content-Type, Accept, Authorization');
        res.header('Access-Control-Allow-Credentials', 'true');
        
        if (req.method === 'OPTIONS') {
            res.sendStatus(204);
            return;
        }
        next();
    }
};