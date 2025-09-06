import { RequestHandler } from 'express';
import { WebUiConfig } from '@/webui';
import { sendSuccess, sendError } from '@webapi/utils/response';

// 获取安全配置
export const GetSecurityConfigHandler: RequestHandler = async (_, res) => {
    try {
        const securityConfig = await WebUiConfig.GetSecurityConfig();
        return sendSuccess(res, securityConfig);
    } catch (error) {
        return sendError(res, 'Failed to get security configuration');
    }
};

// 更新安全配置
export const UpdateSecurityConfigHandler: RequestHandler = async (req, res) => {
    try {
        const { 
            allowedIPs, 
            lockoutDuration, 
            maxFailedAttempts, 
            enableSecurityHeaders, 
            minTokenLength,
            forceHTTPS,
            allowedOrigins 
        } = req.body;

        const updates: any = {};
        
        if (allowedIPs !== undefined) updates.allowedIPs = allowedIPs;
        if (lockoutDuration !== undefined) updates.lockoutDuration = lockoutDuration;
        if (maxFailedAttempts !== undefined) updates.maxFailedAttempts = maxFailedAttempts;
        if (enableSecurityHeaders !== undefined) updates.enableSecurityHeaders = enableSecurityHeaders;
        if (minTokenLength !== undefined) updates.minTokenLength = minTokenLength;
        if (forceHTTPS !== undefined) updates.forceHTTPS = forceHTTPS;
        if (allowedOrigins !== undefined) updates.allowedOrigins = allowedOrigins;

        await WebUiConfig.UpdateSecurityConfig(updates);
        return sendSuccess(res, 'Security configuration updated successfully');
    } catch (error: any) {
        return sendError(res, `Failed to update security configuration: ${error.message}`);
    }
};

// 生成新的安全令牌
export const GenerateSecureTokenHandler: RequestHandler = async (_, res) => {
    try {
        const crypto = await import('crypto');
        const newToken = crypto.randomBytes(32).toString('hex');
        return sendSuccess(res, { token: newToken });
    } catch (error) {
        return sendError(res, 'Failed to generate secure token');
    }
};

// 获取安全状态概览
export const GetSecurityStatusHandler: RequestHandler = async (_, res) => {
    try {
        const config = await WebUiConfig.GetWebUIConfig();
        const securityConfig = await WebUiConfig.GetSecurityConfig();
        
        const status = {
            hasDefaultToken: config.defaultToken,
            tokenLength: config.token.length,
            hasIPWhitelist: securityConfig?.allowedIPs && securityConfig.allowedIPs.length > 0,
            hasOriginWhitelist: securityConfig?.allowedOrigins && securityConfig.allowedOrigins.length > 0,
            securityHeadersEnabled: securityConfig?.enableSecurityHeaders !== false,
            lockoutEnabled: (securityConfig?.maxFailedAttempts || 0) > 0,
            httpsForced: securityConfig?.forceHTTPS === true,
            minTokenLength: securityConfig?.minTokenLength || 16,
        };
        
        return sendSuccess(res, status);
    } catch (error) {
        return sendError(res, 'Failed to get security status');
    }
};