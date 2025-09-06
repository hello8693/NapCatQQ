import { webUiPathWrapper } from '@/webui';
import { Type, Static } from '@sinclair/typebox';
import Ajv from 'ajv';
import fs, { constants } from 'node:fs/promises';
import crypto from 'node:crypto';

import { resolve } from 'node:path';

import { deepMerge } from '../utils/object';
import { themeType } from '../types/theme';

// 生成安全的随机令牌
function generateSecureToken(): string {
    return crypto.randomBytes(32).toString('hex');
}

// 限制尝试端口的次数，避免死循环
// 定义配置的类型
const WebUiConfigSchema = Type.Object({
    host: Type.String({ default: '0.0.0.0' }),
    port: Type.Number({ default: 6099 }),
    // 使用安全的随机令牌代替可预测的时间戳
    token: Type.String({ default: generateSecureToken() }),
    loginRate: Type.Number({ default: 10 }),
    autoLoginAccount: Type.String({ default: '' }),
    theme: themeType,
    defaultToken: Type.Boolean({ default: true }),
    // 新增安全配置选项
    security: Type.Optional(Type.Object({
        // IP白名单，空数组表示允许所有IP
        allowedIPs: Type.Array(Type.String(), { default: [] }),
        // 失败尝试后的锁定时间（分钟）
        lockoutDuration: Type.Number({ default: 30 }),
        // 触发锁定的最大失败次数
        maxFailedAttempts: Type.Number({ default: 5 }),
        // 是否启用安全头
        enableSecurityHeaders: Type.Boolean({ default: true }),
        // 令牌最小长度要求
        minTokenLength: Type.Number({ default: 16 }),
        // 是否强制HTTPS（当有证书时）
        forceHTTPS: Type.Boolean({ default: false }),
        // CORS允许的域名列表，空数组表示允许所有域名
        allowedOrigins: Type.Array(Type.String(), { default: [] }),
    }, { default: {} })),
});

export type WebUiConfigType = Static<typeof WebUiConfigSchema>;

// 读取当前目录下名为 webui.json 的配置文件，如果不存在则创建初始化配置文件
export class WebUiConfigWrapper {
    WebUiConfigData: WebUiConfigType | undefined = undefined;

    private validateAndApplyDefaults(config: Partial<WebUiConfigType>): WebUiConfigType {
        new Ajv({ coerceTypes: true, useDefaults: true }).compile(WebUiConfigSchema)(config);
        return config as WebUiConfigType;
    }

    private validateTokenComplexity(token: string, minLength: number = 16): boolean {
        if (token.length < minLength) {
            return false;
        }
        
        // 检查是否包含至少一个数字、一个字母
        const hasNumber = /\d/.test(token);
        const hasLetter = /[a-zA-Z]/.test(token);
        
        // 如果是十六进制字符串（如随机生成的token），只需要检查长度
        const isHex = /^[a-fA-F0-9]+$/.test(token);
        if (isHex && token.length >= minLength) {
            return true;
        }
        
        return hasNumber && hasLetter;
    }

    private async ensureConfigFileExists(configPath: string): Promise<void> {
        const configExists = await fs
            .access(configPath, constants.F_OK)
            .then(() => true)
            .catch(() => false);
        if (!configExists) {
            await fs.writeFile(configPath, JSON.stringify(this.validateAndApplyDefaults({}), null, 4));
        }
    }

    private async readAndValidateConfig(configPath: string): Promise<WebUiConfigType> {
        const fileContent = await fs.readFile(configPath, 'utf-8');
        return this.validateAndApplyDefaults(JSON.parse(fileContent));
    }

    private async writeConfig(configPath: string, config: WebUiConfigType): Promise<void> {
        const hasWritePermission = await fs
            .access(configPath, constants.W_OK)
            .then(() => true)
            .catch(() => false);
        if (hasWritePermission) {
            await fs.writeFile(configPath, JSON.stringify(config, null, 4));
        } else {
            console.warn(`文件: ${configPath} 没有写入权限, 配置的更改部分可能会在重启后还原.`);
        }
    }

    async GetWebUIConfig(): Promise<WebUiConfigType> {
        if (this.WebUiConfigData) {
            return this.WebUiConfigData;
        }
        try {
            const configPath = resolve(webUiPathWrapper.configPath, './webui.json');
            await this.ensureConfigFileExists(configPath);
            const parsedConfig = await this.readAndValidateConfig(configPath);
            this.WebUiConfigData = parsedConfig;
            return this.WebUiConfigData;
        } catch (e) {
            console.log('读取配置文件失败', e);
            return this.validateAndApplyDefaults({});
        }
    }

    async UpdateWebUIConfig(newConfig: Partial<WebUiConfigType>): Promise<void> {
        const configPath = resolve(webUiPathWrapper.configPath, './webui.json');
        const currentConfig = await this.GetWebUIConfig();
        const mergedConfig = deepMerge({ ...currentConfig }, newConfig);
        const updatedConfig = this.validateAndApplyDefaults(mergedConfig);
        await this.writeConfig(configPath, updatedConfig);
        this.WebUiConfigData = updatedConfig;
    }

    async UpdateToken(oldToken: string, newToken: string): Promise<void> {
        const currentConfig = await this.GetWebUIConfig();
        if (currentConfig.token !== oldToken) {
            throw new Error('旧 token 不匹配');
        }
        
        // 验证新token的复杂度
        const minLength = currentConfig.security?.minTokenLength || 16;
        if (!this.validateTokenComplexity(newToken, minLength)) {
            throw new Error(`新 token 不符合安全要求：最少${minLength}个字符，且包含字母和数字`);
        }
        
        await this.UpdateWebUIConfig({ token: newToken, defaultToken: false });
    }

    // 获取日志文件夹路径
    async GetLogsPath(): Promise<string> {
        return resolve(webUiPathWrapper.logsPath);
    }

    // 获取日志列表
    async GetLogsList(): Promise<string[]> {
        const logsPath = resolve(webUiPathWrapper.logsPath);
        const logsExist = await fs
            .access(logsPath, constants.F_OK)
            .then(() => true)
            .catch(() => false);
        if (logsExist) {
            return (await fs.readdir(logsPath))
                .filter((file) => file.endsWith('.log'))
                .map((file) => file.replace('.log', ''));
        }
        return [];
    }

    // 获取指定日志文件内容
    async GetLogContent(filename: string): Promise<string> {
        const logPath = resolve(webUiPathWrapper.logsPath, `${filename}.log`);
        const logExists = await fs
            .access(logPath, constants.R_OK)
            .then(() => true)
            .catch(() => false);
        if (logExists) {
            return await fs.readFile(logPath, 'utf-8');
        }
        return '';
    }

    // 获取字体文件夹内的字体列表
    async GetFontList(): Promise<string[]> {
        const fontsPath = resolve(webUiPathWrapper.configPath, './fonts');
        const fontsExist = await fs
            .access(fontsPath, constants.F_OK)
            .then(() => true)
            .catch(() => false);
        if (fontsExist) {
            return (await fs.readdir(fontsPath)).filter((file) => file.endsWith('.ttf'));
        }
        return [];
    }

    // 判断字体是否存在（webui.woff）
    async CheckWebUIFontExist(): Promise<boolean> {
        const fontsPath = resolve(webUiPathWrapper.configPath, './fonts');
        return await fs
            .access(resolve(fontsPath, './webui.woff'), constants.F_OK)
            .then(() => true)
            .catch(() => false);
    }

    // 获取webui字体文件路径
    GetWebUIFontPath(): string {
        return resolve(webUiPathWrapper.configPath, './fonts/webui.woff');
    }

    getAutoLoginAccount(): string | undefined {
        return this.WebUiConfigData?.autoLoginAccount;
    }

    // 获取自动登录账号
    async GetAutoLoginAccount(): Promise<string> {
        return (await this.GetWebUIConfig()).autoLoginAccount;
    }

    // 更新自动登录账号
    async UpdateAutoLoginAccount(uin: string): Promise<void> {
        await this.UpdateWebUIConfig({ autoLoginAccount: uin });
    }

    // 获取主题内容
    async GetTheme(): Promise<WebUiConfigType['theme']> {
        const config = await this.GetWebUIConfig();

        return config.theme;
    }

    // 更新主题内容
    async UpdateTheme(theme: WebUiConfigType['theme']): Promise<void> {
        await this.UpdateWebUIConfig({ theme: theme });
    }

    // 获取安全配置
    async GetSecurityConfig(): Promise<WebUiConfigType['security']> {
        const config = await this.GetWebUIConfig();
        return config.security || {
            allowedIPs: [],
            lockoutDuration: 30,
            maxFailedAttempts: 5,
            enableSecurityHeaders: true,
            minTokenLength: 16,
            forceHTTPS: false,
            allowedOrigins: [],
        };
    }

    // 更新安全配置
    async UpdateSecurityConfig(securityConfig: Partial<NonNullable<WebUiConfigType['security']>>): Promise<void> {
        const currentConfig = await this.GetWebUIConfig();
        const currentSecurity = currentConfig.security || {
            allowedIPs: [],
            lockoutDuration: 30,
            maxFailedAttempts: 5,
            enableSecurityHeaders: true,
            minTokenLength: 16,
            forceHTTPS: false,
            allowedOrigins: [],
        };
        const updatedSecurity = { ...currentSecurity, ...securityConfig };
        await this.UpdateWebUIConfig({ security: updatedSecurity });
    }

    // 检查IP是否在白名单中
    async IsIPAllowed(ip: string): Promise<boolean> {
        const securityConfig = await this.GetSecurityConfig();
        if (!securityConfig || !securityConfig.allowedIPs || securityConfig.allowedIPs.length === 0) {
            return true; // 如果没有配置白名单，允许所有IP
        }
        
        // 支持IP段匹配（简单实现）
        return securityConfig.allowedIPs.some(allowedIP => {
            if (allowedIP.includes('/')) {
                // CIDR notation support could be added here
                return false;
            }
            if (allowedIP.includes('*')) {
                // 通配符支持
                const pattern = allowedIP.replace(/\*/g, '.*');
                return new RegExp(`^${pattern}$`).test(ip);
            }
            return allowedIP === ip;
        });
    }
}
