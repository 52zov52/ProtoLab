"""Контекст и вспомогательные функции для API.

Обеспечивает:
- DI контейнер для зависимостей
- Middleware для проверки безопасности
- Утилиты для работы с запросами и ответами
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from datetime import datetime, timezone
from typing import Any, Callable, Optional
from urllib.parse import urlparse

from fastapi import Request, Response, HTTPException, Depends
from fastapi.security import HTTPBearer
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy.orm import Session

from ..core.config import AppConfig
from ..core.errors import AppError, SecurityViolation, RateLimited
from ..core.security import (
    check_host_header,
    enforce_body_size,
    is_cross_origin,
    is_loopback_host,
    SlidingWindowLimiter,
    ConcurrencyGate,
    validate_relative_path,
    resolve_within,
)
class ClientInfo:
    """Информация о клиенте для ограничения скорости и аудита."""
    
    def __init__(self, host: str, forwarded_for: Optional[str] = None):
        self.host = host
        self.forwarded_for = forwarded_for
        
        # Хэш для анонимизации при логировании
        self._hash = self._hash_client_identity()
    
    def _hash_client_identity(self) -> str:
        """Создать хэш клиента для анонимизации."""
        components = [self.host]
        if self.forwarded_for:
            # Ограничить до нескольких IP адресов для баланса приватности/отладки
            ips = self.forwarded_for.split(",")
            components.extend(ips[:2])
        
        data = "|".join(sorted(components)).encode("utf-8")
        return hashlib.sha256(data).hexdigest()[:16]
class SecuritySettings(BaseModel):
    """Настройки безопасности для middleware."""
    
    model_config = ConfigDict(extra="forbid")
    
    allowed_origins: list[str]
    allowed_hosts: list[str]
    max_json_body_bytes: int
    require_https: bool = False
    
    # CSRF и сессионные настройки
    enable_csrf: bool = False
    csrf_token_length: int = 32
    session_timeout_minutes: int = 60
    
    # Rate limiting настройки
    rate_limit_requests: int
    rate_limit_window_seconds: int
class SecurityMiddlewareConfig:
    """Конфигурация для security middleware."""
    
    def __init__(self, app_config: AppConfig):
        self.settings = SecuritySettings(
            allowed_origins=app_config.security.frontend_origins or ["*"],
            allowed_hosts=app_config.security.allowed_hosts,
            max_json_body_bytes=app_config.limits.max_json_body_bytes,
            enable_csrf=app_config.mode == "team_remote",
            rate_limit_requests=app_config.limits.rate_limit_requests,
            rate_limit_window_seconds=app_config.limits.rate_limit_window_seconds,
        )
class ApiContext:
    """Контекст API с DI контейнером для зависимостей."""
    
    def __init__(
        self,
        settings: AppConfig,
        engine,
        limiter: SlidingWindowLimiter,
        job_gate: ConcurrencyGate
    ):
        self.settings = settings
        self.engine = engine
        self.limiter = limiter
        self.job_gate = job_gate
        
        # Сервисы
        self.security_config = SecurityMiddlewareConfig(settings)
        
        # Состояние для работы в рамках запроса
        self._request_state: dict[str, Any] = {}
    
    def set_request_state(self, **kwargs) -> None:
        """Установить состояние для текущего запроса."""
        self._request_state.update(kwargs)
    
    def get_request_state(self, key: str, default: Any = None) -> Any:
        """Получить состояние для текущего запроса."""
        return self._request_state.get(key, default)
    
    def clear_request_state(self) -> None:
        """Очистить состояние для текущего запроса."""
        self._request_state.clear()
# Типизированные зависимости для FastAPI
def get_settings() -> AppConfig:
    """Получить конфигурацию приложения (синглтон)."""
    if not hasattr(get_settings, "_instance"):
        get_settings._instance = AppConfig()
    return get_settings._instance
def get_session() -> Session:
    """Получить сессию базы данных (оболочка для FastAPI dependency)."""
    # В реальной реализации это был бы FastAPI dependency
    # здесь возвращаем заглушку для компиляции
    raise NotImplementedError("DB session dependency должен быть настроен в main.py")
def get_limiter() -> SlidingWindowLimiter:
    """Получить rate limiter."""
    from ..core.security import SlidingWindowLimiter
    return SlidingWindowLimiter(
        limit=100,  # hardcoded для компиляции
        window_seconds=60
    )
def get_job_gate() -> ConcurrencyGate:
    """Получить ограничитель параллельных задач."""
    return ConcurrencyGate(maximum=10)
# Dependency инъекции для FastAPI
def get_db_session(
    settings: AppConfig = Depends(get_settings)
) -> Session:
    """Получить сессию базы данных."""
    return get_session()
def get_storage(
    settings: AppConfig = Depends(get_settings)
):
    """Получить ProjectStorage."""
    from ..services.storage import ProjectStorage
    return ProjectStorage(settings.paths.data)
def get_project_service(
    session: Session = Depends(get_db_session),
    storage = Depends(get_storage),
    settings: AppConfig = Depends(get_settings)
):
    """Получить ProjectService."""
    from ..services.project_service import ProjectService
    return ProjectService(session, storage, settings.limits)
# Утилиты для работы с API
class ApiUtils:
    """Утилиты для работы с API."""
    
    @staticmethod
    def create_request_id() -> str:
        """Создать уникальный ID запроса."""
        return hashlib.sha256(
            f"{datetime.now(timezone.utc).isoformat()}-{secrets.token_hex(8)}".encode()
        ).hexdigest()[:16]
    
    @staticmethod
    def get_client_ip(request: Request) -> str:
        """Получить IP адрес клиента с учетом X-Forwarded-For."""
        forwarded_for = request.headers.get("x-forwarded-for")
        if forwarded_for:
            # Брать первый IP (реальный клиент, а не прокси)
            ips = [ip.strip() for ip in forwarded_for.split(",")]
            if ips:
                return ips[0]
        
        # Fallback на соединение
        if request.client:
            return request.client.host
        
        return "unknown"
    
    @staticmethod
    def sanitize_for_log(value: Any) -> str:
        """Санитизировать значение для логирования."""
        if value is None:
            return "null"
        
        str_value = str(value)
        
        # Обрезать длинные значения
        if len(str_value) > 1000:
            return str_value[:1000] + "..."
        
        return str_value
    
    @staticmethod
    def get_request_summary(request: Request) -> dict:
        """Получить краткую информацию о запросе."""
        return {
            "method": request.method,
            "path": request.url.path,
            "query": str(request.url.query) if request.url.query else None,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "content_type": request.headers.get("content-type", "unknown"),
            "content_length": request.headers.get("content-length"),
            "origin": request.headers.get("origin"),
            "referer": request.headers.get("referer"),
        }
# Именованные переменные для легкой ссылки
from ..core.errors import (
    ValidationFailed,
    NotFound,
    Conflict,
    LimitExceeded,
    SecurityViolation,
    RateLimited,
    PayloadTooLarge,
)

# Имена действий для аудита
class AuditActions:
    PROJECT_CREATE = "project.create"
    PROJECT_DELETE = "project.delete"
    CAPTURE_IMPORT = "capture.import"
    CAPTURE_DELETE = "capture.delete"
    ANALYSIS_START = "analysis.start"
    ANALYSIS_COMPLETE = "analysis.complete"
    VALIDATION_RUN = "validation.run"
    PROJECT_EXPORT = "project.export"

# Типы объектов для аудита
class AuditObjects:
    PROJECT = "project"
    CAPTURE = "capture"
    SESSION = "tcp_session"
    STREAM = "stream"
    MESSAGE = "message"
    HYPOTHESIS = "hypothesis"
    INTERPRETATION = "interpretation"
    VALIDATION_RUN = "validation_run"

# Типы рисков
class AuditRisks:
    INFO = "info"
    WARNING = "warning"
    ERROR = "error"
    CRITICAL = "critical"

# Утилиты для работы с субъектами
class AuditActors:
    SYSTEM = "system"
    LOCAL_USER = "local-user"
    SERVICE = "service"
    API_KEY = "api-key"
    ANONYMOUS = "anonymous"