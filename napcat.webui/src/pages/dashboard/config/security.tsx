import { Button } from '@heroui/button'
import { Card, CardBody, CardHeader } from '@heroui/card'
import { Chip } from '@heroui/chip'
import { Input, Textarea } from '@heroui/input'
import { Switch } from '@heroui/switch'
import { useEffect, useState } from 'react'
import { Controller, useForm } from 'react-hook-form'
import toast from 'react-hot-toast'
import { IoShieldCheckmark, IoWarning, IoInformationCircle } from 'react-icons/io5'

import SaveButtons from '@/components/button/save_buttons'
import WebUIManager from '@/controllers/webui_manager'

interface SecurityConfig {
  allowedIPs: string[]
  lockoutDuration: number
  maxFailedAttempts: number
  enableSecurityHeaders: boolean
  minTokenLength: number
  forceHTTPS: boolean
  allowedOrigins: string[]
}

interface SecurityStatus {
  hasDefaultToken: boolean
  tokenLength: number
  hasIPWhitelist: boolean
  hasOriginWhitelist: boolean
  securityHeadersEnabled: boolean
  lockoutEnabled: boolean
  httpsForced: boolean
  minTokenLength: number
}

const SecurityConfigCard = () => {
  const [securityStatus, setSecurityStatus] = useState<SecurityStatus | null>(null)
  const [isLoading, setIsLoading] = useState(true)

  const {
    control,
    handleSubmit,
    formState: { isSubmitting },
    reset,
    watch
  } = useForm<SecurityConfig>({
    defaultValues: {
      allowedIPs: [],
      lockoutDuration: 30,
      maxFailedAttempts: 5,
      enableSecurityHeaders: true,
      minTokenLength: 16,
      forceHTTPS: false,
      allowedOrigins: []
    }
  })

  // 加载安全配置和状态
  useEffect(() => {
    const loadSecurityData = async () => {
      try {
        const [config, status] = await Promise.all([
          WebUIManager.getSecurityConfig(),
          WebUIManager.getSecurityStatus()
        ])
        
        reset(config)
        setSecurityStatus(status)
      } catch (error) {
        console.error('加载安全配置失败:', error)
        toast.error('加载安全配置失败')
      } finally {
        setIsLoading(false)
      }
    }

    loadSecurityData()
  }, [reset])

  const onSubmit = async (data: SecurityConfig) => {
    try {
      await WebUIManager.updateSecurityConfig(data)
      toast.success('安全配置已更新')
      
      // 刷新状态
      const status = await WebUIManager.getSecurityStatus()
      setSecurityStatus(status)
    } catch (error: any) {
      toast.error(`更新失败: ${error.message}`)
    }
  }

  const generateSecureToken = async () => {
    try {
      const result = await WebUIManager.generateSecureToken()
      navigator.clipboard.writeText(result.token)
      toast.success('已生成安全令牌并复制到剪贴板')
    } catch (error) {
      toast.error('生成安全令牌失败')
    }
  }

  const getSecurityLevel = () => {
    if (!securityStatus) return { level: 'unknown', color: 'default' as const }
    
    let score = 0
    if (!securityStatus.hasDefaultToken) score += 2
    if (securityStatus.tokenLength >= 32) score += 2
    if (securityStatus.hasIPWhitelist) score += 2
    if (securityStatus.securityHeadersEnabled) score += 1
    if (securityStatus.lockoutEnabled) score += 1
    if (securityStatus.httpsForced) score += 1
    if (securityStatus.hasOriginWhitelist) score += 1
    
    if (score >= 8) return { level: '高', color: 'success' as const }
    if (score >= 5) return { level: '中', color: 'warning' as const }
    return { level: '低', color: 'danger' as const }
  }

  if (isLoading) {
    return <div className="flex justify-center p-8">加载中...</div>
  }

  const securityLevel = getSecurityLevel()
  const allowedIPsText = watch('allowedIPs')?.join('\n') || ''
  const allowedOriginsText = watch('allowedOrigins')?.join('\n') || ''

  return (
    <div className="space-y-6">
      {/* 安全状态概览 */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <IoShieldCheckmark className="text-xl" />
            <h3 className="text-lg font-semibold">安全状态概览</h3>
          </div>
        </CardHeader>
        <CardBody>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            <div className="flex items-center justify-between">
              <span>安全等级</span>
              <Chip color={securityLevel.color} variant="flat">
                {securityLevel.level}
              </Chip>
            </div>
            <div className="flex items-center justify-between">
              <span>使用默认密码</span>
              <Chip color={securityStatus?.hasDefaultToken ? 'danger' : 'success'} variant="flat">
                {securityStatus?.hasDefaultToken ? '是' : '否'}
              </Chip>
            </div>
            <div className="flex items-center justify-between">
              <span>密码长度</span>
              <Chip color={securityStatus && securityStatus.tokenLength >= 16 ? 'success' : 'warning'} variant="flat">
                {securityStatus?.tokenLength} 字符
              </Chip>
            </div>
            <div className="flex items-center justify-between">
              <span>IP白名单</span>
              <Chip color={securityStatus?.hasIPWhitelist ? 'success' : 'default'} variant="flat">
                {securityStatus?.hasIPWhitelist ? '已启用' : '未启用'}
              </Chip>
            </div>
            <div className="flex items-center justify-between">
              <span>账户锁定</span>
              <Chip color={securityStatus?.lockoutEnabled ? 'success' : 'default'} variant="flat">
                {securityStatus?.lockoutEnabled ? '已启用' : '未启用'}
              </Chip>
            </div>
            <div className="flex items-center justify-between">
              <span>安全头</span>
              <Chip color={securityStatus?.securityHeadersEnabled ? 'success' : 'default'} variant="flat">
                {securityStatus?.securityHeadersEnabled ? '已启用' : '未启用'}
              </Chip>
            </div>
          </div>
        </CardBody>
      </Card>

      {/* 警告提示 */}
      {securityStatus?.hasDefaultToken && (
        <Card className="border-warning">
          <CardBody>
            <div className="flex items-start gap-2 text-warning">
              <IoWarning className="text-xl mt-0.5" />
              <div>
                <h4 className="font-semibold">安全警告</h4>
                <p className="text-sm mt-1">
                  您正在使用默认密码，这存在严重的安全风险。请立即前往"修改密码"页面更改密码。
                </p>
              </div>
            </div>
          </CardBody>
        </Card>
      )}

      {/* 基础安全设置 */}
      <Card>
        <CardHeader>
          <h3 className="text-lg font-semibold">基础安全设置</h3>
        </CardHeader>
        <CardBody className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <Controller
              name="maxFailedAttempts"
              control={control}
              render={({ field }) => (
                <Input
                  {...field}
                  type="number"
                  label="最大失败尝试次数"
                  description="达到此次数后临时锁定账户"
                  min={1}
                  max={20}
                  value={field.value.toString()}
                  onChange={(e) => field.onChange(parseInt(e.target.value) || 1)}
                />
              )}
            />
            <Controller
              name="lockoutDuration"
              control={control}
              render={({ field }) => (
                <Input
                  {...field}
                  type="number"
                  label="锁定持续时间（分钟）"
                  description="账户被锁定的时长"
                  min={1}
                  max={1440}
                  value={field.value.toString()}
                  onChange={(e) => field.onChange(parseInt(e.target.value) || 1)}
                />
              )}
            />
            <Controller
              name="minTokenLength"
              control={control}
              render={({ field }) => (
                <Input
                  {...field}
                  type="number"
                  label="最小密码长度"
                  description="新密码的最小字符数"
                  min={8}
                  max={128}
                  value={field.value.toString()}
                  onChange={(e) => field.onChange(parseInt(e.target.value) || 8)}
                />
              )}
            />
          </div>
          
          <div className="space-y-2">
            <Controller
              name="enableSecurityHeaders"
              control={control}
              render={({ field }) => (
                <Switch
                  isSelected={field.value}
                  onValueChange={field.onChange}
                >
                  启用安全头
                </Switch>
              )}
            />
            <Controller
              name="forceHTTPS"
              control={control}
              render={({ field }) => (
                <Switch
                  isSelected={field.value}
                  onValueChange={field.onChange}
                >
                  强制HTTPS（需要配置SSL证书）
                </Switch>
              )}
            />
          </div>
        </CardBody>
      </Card>

      {/* IP访问控制 */}
      <Card>
        <CardHeader>
          <div className="flex items-center gap-2">
            <h3 className="text-lg font-semibold">IP访问控制</h3>
            <IoInformationCircle className="text-default-400" />
          </div>
        </CardHeader>
        <CardBody>
          <Controller
            name="allowedIPs"
            control={control}
            render={({ field }) => (
              <Textarea
                label="允许的IP地址"
                placeholder="127.0.0.1&#10;192.168.1.*&#10;10.0.0.0/24"
                description="每行一个IP地址或IP段，支持通配符(*)。留空表示允许所有IP"
                value={allowedIPsText}
                onChange={(e) => {
                  const ips = e.target.value.split('\n').filter(ip => ip.trim())
                  field.onChange(ips)
                }}
                minRows={3}
                maxRows={10}
              />
            )}
          />
        </CardBody>
      </Card>

      {/* CORS设置 */}
      <Card>
        <CardHeader>
          <h3 className="text-lg font-semibold">跨域访问控制</h3>
        </CardHeader>
        <CardBody>
          <Controller
            name="allowedOrigins"
            control={control}
            render={({ field }) => (
              <Textarea
                label="允许的域名"
                placeholder="https://example.com&#10;https://sub.example.com"
                description="每行一个域名。留空表示允许所有域名（不推荐）"
                value={allowedOriginsText}
                onChange={(e) => {
                  const origins = e.target.value.split('\n').filter(origin => origin.trim())
                  field.onChange(origins)
                }}
                minRows={3}
                maxRows={10}
              />
            )}
          />
        </CardBody>
      </Card>

      {/* 工具 */}
      <Card>
        <CardHeader>
          <h3 className="text-lg font-semibold">安全工具</h3>
        </CardHeader>
        <CardBody>
          <Button
            color="primary"
            variant="bordered"
            onPress={generateSecureToken}
            className="max-w-xs"
          >
            生成安全令牌
          </Button>
          <p className="text-sm text-default-500 mt-2">
            生成一个64字符的安全随机令牌，可用于设置新密码
          </p>
        </CardBody>
      </Card>

      <SaveButtons 
        onSubmit={handleSubmit(onSubmit)}
        reset={() => reset()} 
        isSubmitting={isSubmitting}
      />
    </div>
  )
}

export default SecurityConfigCard