"use client";

import { useAsync } from '@/hooks/use-async';
import { api } from '@/lib/api';
import { Badge } from '@/components/ui/badge';
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from '@/components/ui/card';
import { AlertTriangle, Shield, CheckCircle, XCircle, Info, Settings } from 'lucide-react';
import { useState } from 'react';

interface SecurityStatus {
  bindings_ok: boolean;
  cors_ok: boolean;
  limits_ok: boolean;
  storage_ok: boolean;
  bind_address: string;
  allowed_origins: string[];
  limits?: {
    rate_limit_requests: number;
    rate_limit_window_seconds: number;
    max_concurrent_jobs: number;
  };
  storage_root?: string;
  reasons?: {
    binding?: string;
    cors?: string;
    limits?: string;
    storage?: string;
  };
}

export default function SecurityCenterPage() {
  const [showDetails, setShowDetails] = useState(false);
  const [autoCheckInterval, setAutoCheckInterval] = useState<NodeJS.Timeout | null>(null);
  
  const securityCheck = useAsync<SecurityStatus>(() => api.security.check(), []);

  // Автоматическая периодическая проверка
  useEffect(() => {
    // Запускаем проверку каждые 30 секунд
    const interval = setInterval(() => {
      securityCheck.reload();
    }, 30000);
    setAutoCheckInterval(interval);
    
    return () => {
      if (autoCheckInterval) {
        clearInterval(autoCheckInterval);
      }
    };
  }, []);

  const getStatusIcon = (status: boolean, type: 'good' | 'warning' | 'error' = 'good') => {
    if (!status) {
      return type === 'warning' ? 
        <AlertTriangle className="h-4 w-4 text-yellow-600" /> :
        <XCircle className="h-4 w-4 text-red-600" />;
    }
    return <CheckCircle className="h-4 w-4 text-green-600" />;
  };

  const getStatusColor = (status: boolean, type: 'good' | 'warning' | 'error' = 'good') => {
    if (!status) {
      return type === 'warning' ? 
        'border-yellow-200 bg-yellow-50 dark:bg-yellow-950/20' :
        'border-red-200 bg-red-50 dark:bg-red-950/20';
    }
    return 'border-green-200 bg-green-50 dark:bg-green-950/20';
  };

  const getStatusBadge = (status: boolean, type: 'good' | 'warning' | 'error' = 'good') => {
    if (!status) {
      return type === 'warning' ? 
        <Badge variant="secondary" className="text-yellow-700 dark:text-yellow-300">
          WARNING
        </Badge> :
        <Badge variant="destructive" className="text-red-700 dark:text-red-300">
          BLOCKED
        </Badge>;
    }
    return <Badge variant="default" className="text-green-700 dark:text-green-300">
      SECURE
    </Badge>;
  };

  return (
    <div className="space-y-6">
      {/* Заголовок страницы */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6" />
            Security Center
          </h1>
          <p className="text-muted-foreground mt-1">
            Живой мониторинг безопасности и конфигурации системы
          </p>
        </div>
        
        <div className="flex gap-2">
          <button
            onClick={() => setShowDetails(!showDetails)}
            className="px-4 py-2 border border-border rounded-md hover:bg-muted transition-colors flex items-center gap-2"
          >
            <Settings className="h-4 w-4" />
            {showDetails ? 'Скрыть детали' : 'Показать детали'}
          </button>
          
          <button
            onClick={securityCheck.reload}
            disabled={securityCheck.state === 'loading'}
            className="px-4 py-2 bg-primary text-primary-foreground rounded-md hover:bg-primary/90 disabled:opacity-50 transition-colors flex items-center gap-2"
          >
            {securityCheck.state === 'loading' ? 'Проверка...' : 'Проверить сейчас'}
          </button>
        </div>
      </div>

      {/* Информация о режиме */}
      {securityCheck.state === 'ready' && securityCheck.data && (
        <Card className="border-blue-200 bg-blue-50 dark:bg-blue-950/20">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <Info className="h-5 w-5 text-blue-600" />
                <div>
                  <span className="font-medium">Режим работы:</span>{' '}
                  <code className="bg-blue-100 dark:bg-blue-900 px-2 py-1 rounded">
                    {securityCheck.data.mode}
                  </code>
                </div>
              </div>
              <div className="text-sm text-muted-foreground">
                Обновлено: {new Date().toLocaleTimeString()}
              </div>
            </div>
            
            {showDetails && (
              <div className="mt-4 pt-4 border-t border-blue-200">
                <div className="grid grid-cols-2 gap-4 text-sm">
                  <div>
                    <span className="font-medium">Host:</span>{' '}
                    <code>{securityCheck.data.host}</code>
                  </div>
                  <div>
                    <span className="font-medium">Port:</span>{' '}
                    <code>{securityCheck.data.port}</code>
                  </div>
                  <div>
                    <span className="font-medium">Debug:</span>{' '}
                    <span>{securityCheck.data.debug ? 'включен' : 'отключен'}</span>
                  </div>
                  <div>
                    <span className="font-medium">Отладочные инструменты:</span>{' '}
                    <span>{securityCheck.data.debug ? 'доступны' : 'недоступны'}</span>
                  </div>
                </div>
              </div>
            )}
          </CardContent>
        </Card>
      )}

      {/* Состояние загрузки */}
      {securityCheck.state === 'loading' && (
        <Card>
          <CardContent className="pt-6">
            <div className="flex items-center justify-center py-8">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-primary"></div>
              <span className="ml-3">Проверка безопасности...</span>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Состояние ошибки */}
      {securityCheck.state === 'error' && (
        <Card className="border-red-200 bg-red-50 dark:bg-red-950/20">
          <CardContent className="pt-6">
            <div className="flex items-center gap-3">
              <XCircle className="h-5 w-5 text-red-600" />
              <div>
                <h3 className="font-medium text-red-800 dark:text-red-200">
                  Ошибка проверки безопасности
                </h3>
                <p className="text-sm text-red-600 dark:text-red-400 mt-1">
                  {securityCheck.error}
                </p>
              </div>
            </div>
            
            <button
              onClick={securityCheck.reload}
              className="mt-4 px-4 py-2 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors"
            >
              Повторить попытку
            </button>
          </CardContent>
        </Card>
      )}

      {/* Состояние ready */}
      {securityCheck.state === 'ready' && securityCheck.data && (
        <div className="space-y-6">
          {/* Основные статусы */}
          <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
            {/* Проверка привязки */}
            <Card className={getStatusColor(securityCheck.data.bindings_ok, 
                                           securityCheck.data.reasons?.binding ? 'warning' : 'good')}
                  onClick={() => setShowDetails(true)}
                  className="cursor-pointer hover:shadow-md transition-shadow">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  {getStatusIcon(securityCheck.data.bindings_ok, 
                               securityCheck.data.reasons?.binding ? 'warning' : 'good')}
                  Сетевая привязка
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Адрес:</span>
                    <code className="text-xs">{securityCheck.data.bind_address}</code>
                  </div>
                  {showDetails && securityCheck.data.reasons?.binding && (
                    <div className="text-xs text-amber-600 dark:text-amber-400">
                      {securityCheck.data.reasons.binding}
                    </div>
                  )}
                  <div className="pt-2">
                    {getStatusBadge(securityCheck.data.bindings_ok, 
                                   securityCheck.data.reasons?.binding ? 'warning' : 'good')}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Проверка CORS */}
            <Card className={getStatusColor(securityCheck.data.cors_ok,
                                           securityCheck.data.reasons?.cors ? 'warning' : 'good')}
                  onClick={() => setShowDetails(true)}
                  className="cursor-pointer hover:shadow-md transition-shadow">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  {getStatusIcon(securityCheck.data.cors_ok,
                               securityCheck.data.reasons?.cors ? 'warning' : 'good')}
                  CORS конфигурация
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Origins:</span>
                    <span className="font-mono text-xs">
                      {securityCheck.data.allowed_origins?.length || 0}
                    </span>
                  </div>
                  {showDetails && securityCheck.data.reasons?.cors && (
                    <div className="text-xs text-amber-600 dark:text-amber-400">
                      {securityCheck.data.reasons.cors}
                    </div>
                  )}
                  <div className="pt-2">
                    {getStatusBadge(securityCheck.data.cors_ok, 
                                   securityCheck.data.reasons?.cors ? 'warning' : 'good')}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Проверка лимитов */}
            <Card className={getStatusColor(securityCheck.data.limits_ok,
                                           securityCheck.data.reasons?.limits ? 'warning' : 'good')}
                  onClick={() => setShowDetails(true)}
                  className="cursor-pointer hover:shadow-md transition-shadow">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  {getStatusIcon(securityCheck.data.limits_ok,
                               securityCheck.data.reasons?.limits ? 'warning' : 'good')}
                  Лимиты ресурсов
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {securityCheck.data.limits && (
                    <>
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Rate:</span>
                        <code className="text-xs">
                          {securityCheck.data.limits.rate_limit_requests}/{
                            securityCheck.data.limits.rate_limit_window_seconds}s
                        </code>
                      </div>
                      <div className="flex justify-between text-sm">
                        <span className="text-muted-foreground">Jobs:</span>
                        <code className="text-xs">
                          {securityCheck.data.limits.max_concurrent_jobs}
                        </code>
                      </div>
                    </>
                  )}
                  {showDetails && securityCheck.data.reasons?.limits && (
                    <div className="text-xs text-amber-600 dark:text-amber-400">
                      {securityCheck.data.reasons.limits}
                    </div>
                  )}
                  <div className="pt-2">
                    {getStatusBadge(securityCheck.data.limits_ok,
                                   securityCheck.data.reasons?.limits ? 'warning' : 'good')}
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Проверка хранилища */}
            <Card className={getStatusColor(securityCheck.data.storage_ok,
                                           securityCheck.data.reasons?.storage ? 'warning' : 'good')}
                  onClick={() => setShowDetails(true)}
                  className="cursor-pointer hover:shadow-md transition-shadow">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  {getStatusIcon(securityCheck.data.storage_ok,
                               securityCheck.data.reasons?.storage ? 'warning' : 'good')}
                  Файловое хранилище
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  <div className="flex justify-between text-sm">
                    <span className="text-muted-foreground">Root:</span>
                    <code className="text-xs">
                      {securityCheck.data.storage_root || 'Не настроено'}
                    </code>
                  </div>
                  {showDetails && securityCheck.data.reasons?.storage && (
                    <div className="text-xs text-amber-600 dark:text-amber-400">
                      {securityCheck.data.reasons.storage}
                    </div>
                  )}
                  <div className="pt-2">
                    {getStatusBadge(securityCheck.data.storage_ok,
                                   securityCheck.data.reasons?.storage ? 'warning' : 'good')}
                  </div>
                </div>
              </CardContent>
            </Card>
          </div>

          {/* Детали безопасности */}
          {showDetails && (
            <Card>
              <CardHeader>
                <CardTitle>Детали конфигурации безопасности</CardTitle>
                <CardDescription>
                  Полный обзор текущих настроек безопасности и ограничения
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="space-y-4">
                  {/* Текущая конфигурация */}
                  <div>
                    <h4 className="font-medium mb-2">Текущая конфигурация</h4>
                    <div className="bg-muted/50 p-4 rounded-md font-mono text-sm space-y-2">
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Режим:</span>
                        <span>{securityCheck.data.mode}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Host:</span>
                        <span>{securityCheck.data.host}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Port:</span>
                        <span>{securityCheck.data.port}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Allowed hosts:</span>
                        <span>{securityCheck.data.allowed_hosts?.length || 0}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Frontend origins:</span>
                        <span>{securityCheck.data.frontend_origins?.length || 0}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-muted-foreground">Max body size:</span>
                        <span>{(securityCheck.data.limits?.max_json_body_bytes || 0) / 1024} KB</span>
                      </div>
                    </div>
                  </div>

                  {/* Состояние рисков */}
                  <div>
                    <h4 className="font-medium mb-2">Оценка рисков</h4>
                    <div className="space-y-2">
                      {[
                        {name: 'Network binding', status: securityCheck.data.bindings_ok, risk: !securityCheck.data.bindings_ok},
                        {name: 'CORS policy', status: securityCheck.data.cors_ok, risk: !securityCheck.data.cors_ok},
                        {name: 'Resource limits', status: securityCheck.data.limits_ok, risk: !securityCheck.data.limits_ok},
                        {name: 'File storage', status: securityCheck.data.storage_ok, risk: !securityCheck.data.storage_ok}
                      ].map((item, index) => (
                        <div key={index} className="flex items-center justify-between p-3 bg-muted/30 rounded-md">
                          <span className="font-medium">{item.name}</span>
                          <div className="flex items-center gap-2">
                            {item.status ? (
                              <CheckCircle className="h-4 w-4 text-green-600" />
                            ) : (
                              <AlertTriangle className="h-4 w-4 text-yellow-600" />
                            )}
                            <Badge variant={item.risk ? "destructive" : "default"}>
                              {item.risk ? "RISK" : "OK"}
                            </Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Предложения по улучшению */}
                  {(!securityCheck.data.bindings_ok || !securityCheck.data.cors_ok || 
                    !securityCheck.data.limits_ok || !securityCheck.data.storage_ok) && (
                    <div>
                      <h4 className="font-medium mb-2 text-amber-600 dark:text-amber-400">
                        Предложения по улучшению безопасности
                      </h4>
                      <div className="space-y-2 text-sm">
                        {!securityCheck.data.bindings_ok && (
                          <div className="flex items-start gap-2 p-3 bg-yellow-50 dark:bg-yellow-950/20 
                                       border border-yellow-200 dark:border-yellow-800 rounded-md">
                            <AlertTriangle className="h-4 w-4 text-yellow-600 mt-0.5" />
                            <div>
                              <p className="font-medium">Сетевая привязка небезопасна</p>
                              <p className="text-muted-foreground text-xs mt-1">
                                Рекомендуется использовать loopback-only адреса (127.0.0.1, ::1)
                                в режиме local_secure для предотвращения сетевой экспозиции.
                              </p>
                            </div>
                          </div>
                        )}
                        
                        {!securityCheck.data.cors_ok && (
                          <div className="flex items-start gap-2 p-3 bg-yellow-50 dark:bg-yellow-950/20 
                                       border border-yellow-200 dark:border-yellow-800 rounded-md">
                            <AlertTriangle className="h-4 w-4 text-yellow-600 mt-0.5" />
                            <div>
                              <p className="font-medium">CORS политика не соответствует политике</p>
                              <p className="text-muted-foreground text-xs mt-1">
                                Добавьте точные frontend origins ({securityCheck.data.frontend_origins?.join(', ') || 'не настроены'}) 
                                в whitelist чтобы предотвратить атаку через чужой сайт.
                              </p>
                            </div>
                          </div>
                        )}
                        
                        {!securityCheck.data.limits_ok && (
                          <div className="flex items-start gap-2 p-3 bg-yellow-50 dark:bg-yellow-950/20 
                                       border border-yellow-200 dark:border-yellow-800 rounded-md">
                            <AlertTriangle className="h-4 w-4 text-yellow-600 mt-0.5" />
                            <div>
                              <p className="font-medium">Недостаточные лимиты ресурсов</p>
                              <p className="text-muted-foreground text-xs mt-1">
                                Рассмотрите возможность повышения лимитов rate limiting и concurrent jobs 
                                чтобы предотвратить DoS атаки.
                              </p>
                            </div>
                          </div>
                        )}
                        
                        {!securityCheck.data.storage_ok && (
                          <div className="flex items-start gap-2 p-3 bg-yellow-50 dark:bg-yellow-950/20 
                                       border border-yellow-200 dark:border-yellow-800 rounded-md">
                            <AlertTriangle className="h-4 w-4 text-yellow-600 mt-0.5" />
                            <div>
                              <p className="font-medium">Хранилище файлов небезопасно</p>
                              <p className="text-muted-foreground text-xs mt-1">
                                Настройте защищенный storage root и убедитесь, что он не доступен извне.
                              </p>
                            </div>
                          </div>
                        )}
                      </div>
                    </div>
                  )}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}
    </div>
  );
}