import { NextFunction, Request, Response } from 'express';
import { WebUiConfig } from '@/webui';
import { sendError } from '@webapi/utils/response';
import store from '@/common/store';

// IP白名单中间件
export async function ipWhitelist(req: Request, res: Response, next: NextFunction) {
    try {
        const clientIP = req.ip || req.socket.remoteAddress || '';
        const isAllowed = await WebUiConfig.IsIPAllowed(clientIP);
        
        if (!isAllowed) {
            return sendError(res, 'Access denied from this IP address', true, 403);
        }
        
        next();
    } catch (error) {
        return sendError(res, 'Security check failed', true, 500);
    }
}

// 账户锁定中间件
export async function accountLockout(req: Request, res: Response, next: NextFunction) {
    // 仅对登录端点生效
    if (req.url !== '/auth/login') {
        return next();
    }

    try {
        const clientIP = req.ip || req.socket.remoteAddress || '';
        const securityConfig = await WebUiConfig.GetSecurityConfig();
        const lockoutKey = `lockout:${clientIP}`;
        const failedAttemptsKey = `failed_attempts:${clientIP}`;
        
        // 检查是否已被锁定
        if (store.exists(lockoutKey)) {
            return sendError(res, 'Account temporarily locked due to multiple failed login attempts', true, 429);
        }
        
        // 继续处理请求，在失败时会增加失败计数
        next();
    } catch (error) {
        return sendError(res, 'Security check failed', true, 500);
    }
}

// 记录失败的登录尝试
export async function recordFailedLogin(clientIP: string): Promise<void> {
    try {
        const securityConfig = await WebUiConfig.GetSecurityConfig();
        const failedAttemptsKey = `failed_attempts:${clientIP}`;
        const lockoutKey = `lockout:${clientIP}`;
        
        const failedAttempts = (store.get<number>(failedAttemptsKey) || 0) + 1;
        
        // 设置失败次数，1小时后过期
        store.set(failedAttemptsKey, failedAttempts, 3600);
        
        // 如果达到最大失败次数，锁定账户
        if (failedAttempts >= (securityConfig?.maxFailedAttempts || 5)) {
            const lockoutDuration = (securityConfig?.lockoutDuration || 30) * 60; // 转换为秒
            store.set(lockoutKey, true, lockoutDuration);
            
            // 清除失败计数
            store.del(failedAttemptsKey);
        }
    } catch (error) {
        console.error('记录失败登录时出错:', error);
    }
}

// 清除成功登录后的失败记录
export async function clearFailedLoginAttempts(clientIP: string): Promise<void> {
    try {
        const failedAttemptsKey = `failed_attempts:${clientIP}`;
        store.del(failedAttemptsKey);
    } catch (error) {
        console.error('清除失败登录记录时出错:', error);
    }
}

// 安全头中间件
export async function securityHeaders(req: Request, res: Response, next: NextFunction) {
    try {
        const securityConfig = await WebUiConfig.GetSecurityConfig();
        
        if (securityConfig?.enableSecurityHeaders !== false) {
            // 设置安全头
            res.header('X-Content-Type-Options', 'nosniff');
            res.header('X-Frame-Options', 'DENY');
            res.header('X-XSS-Protection', '1; mode=block');
            res.header('Referrer-Policy', 'strict-origin-when-cross-origin');
            res.header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
            
            // 如果是HTTPS，设置HSTS
            if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
                res.header('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
            }
            
            // 内容安全策略（根据需要调整）
            res.header('Content-Security-Policy', 
                "default-src 'self'; " +
                "script-src 'self' 'unsafe-inline' 'unsafe-eval'; " +
                "style-src 'self' 'unsafe-inline'; " +
                "img-src 'self' data: blob:; " +
                "font-src 'self' data:; " +
                "connect-src 'self' ws: wss:; " +
                "frame-ancestors 'none';"
            );
            
            // 隐藏服务器信息
            res.removeHeader('X-Powered-By');
            res.removeHeader('Server');
        }
        
        next();
    } catch (error) {
        // 如果安全头设置失败，仍然继续处理请求
        next();
    }
}