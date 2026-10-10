"""Конфигурация приложения Madrigal Protocol Lab.

Обеспечивает:
- Чтение настроек из переменных окружения
- Валидация и нормализация настроек
- Конфигурируемые пути хранения данных
- Безопасность хранения конфигурации
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any, Dict, Optional
from pydantic import BaseModel, Field, ConfigDict, validator
from dataclasses import dataclass
from enum import Enum
class SecurityMode(str, Enum):
    """Режимы работы приложения"""
    LOCAL_SECURE = "local_secure"
    TEAM_REMOTE = "team_remote"
    DEMO = "demo"
class Environment(str, Enum):
    """Среды развертывания"""
    DEVELOPMENT = "development"
    TESTING = "testing"
    PRODUCTION = "production"
class SecurityConfig(BaseModel):
    """СекURITY конфигурация"""
    
    model_config = ConfigDict(extra="forbid")
    
    # Основные настройки
    mode: SecurityMode = Field(default=SecurityMode.LOCAL_SECURE)
    environment: Environment = Field(default=Environment.DEVELOPMENT)
    
    # Сетевая конфигурация
    host: str = Field(default="127.0.0.1")
    port: int = Field(default=8010)
    debug: bool = Field(default=False)
    
    # CORS и безопасность
    allowed_hosts: list[str] = Field(default_factory=lambda: ["127.0.0.1", "localhost"])
    frontend_origins: list[str] = Field(default_factory=list)
    
    # TLS/SSL (для remote режима)
    enable_tls: bool = Field(default=False)
    cert_file: Optional[str] = None
    key_file: Optional[str] = None
    
    @validator("host")
    def validate_host(cls, v: str, values: Dict[str, Any]) -> str:
        """Валидация хоста в зависимости от режима"""
        if values.get("mode") == SecurityMode.LOCAL_SECURE:
            # В local_secure режиме разрешены только loopback адреса
            if v not in ["127.0.0.1", "::1", "localhost", "localhost.localdomain"]:
                raise ValueError(
                    "В режиме local_secure разрешены только loopback адреса "
                    "(127.0.0.1, ::1, localhost)"
                )
        return v
    
    @validator("frontend_origins")
    def validate_frontend_origins(cls, v: list[str], values: Dict[str, Any]) -> list[str]:
        """Валидация frontend origins"""
        if v and not values.get("allowed_hosts"):
            raise ValueError("frontend_origins требует настроенного allowed_hosts")
        
        # Проверка URL формат
        for origin in v:
            if not (origin.startswith("http://") or origin.startswith("https://")):
                raise ValueError(f"Неверный формат frontend origin: {origin}")
        
        return v
class LimitsConfig(BaseModel):
    """Конфигурация ограничений и лимитов"""
    
    model_config = ConfigDict(extra="forbid")
    
    # Лимиты запросов
    rate_limit_requests: int = Field(default=100)
    rate_limit_window_seconds: int = Field(default=60)
    
    # Лимиты ресурсов
    max_concurrent_jobs: int = Field(default=10)
    max_project_files: int = Field(default=100)
    max_capture_bytes: int = Field(default=100 * 1024 * 1024)  # 100 MB
    max_project_total_bytes: int = Field(default=1024 * 1024 * 1024)  # 1 GB
    max_json_body_bytes: int = Field(default=100 * 1024 * 1024)  # 100 MB
    
    # Размер пагинации
    max_page_size: int = Field(default=100)
    default_page_size: int = Field(default=20)
class StorageConfig(BaseModel):
    """Конфигурация файлового хранилища"""
    
    model_config = ConfigDict(extra="forbid")
    
    # Основные директории
    root: str = Field(default=".")
    data_dir: str = Field(default="data")
    backups_dir: str = Field(default="backups")
    temp_dir: str = Field(default="temp")
    logs_dir: str = Field(default="logs")
    
    # Безопасность хранилища
    enforce_permissions: bool = Field(default=True)
    restrict_symlinks: bool = Field(default=True)
    max_file_age_days: Optional[int] = None
    
    @validator("root")
    def resolve_absolute_path(cls, v: str) -> str:
        """Преобразовать относительный путь в абсолютный"""
        if not os.path.isabs(v):
            return os.path.abspath(v)
        return v
@dataclass
class SecurityPaths:
    """Безопасные пути к директориям"""
    
    root: Path
    data: Path
    backups: Path
    temp: Path
    logs: Path
    
    def ensure_directories(self) -> None:
        """Создать все необходимые директории с правильными правами"""
        self.root.mkdir(parents=True, exist_ok=True)
        self.data.mkdir(parents=True, exist_ok=True)
        self.backups.mkdir(parents=True, exist_ok=True)
        self.temp.mkdir(parents=True, exist_ok=True)
        self.logs.mkdir(parents=True, exist_ok=True)
        
        # Установка безопасных прав доступа (только владелец может записывать)
        if os.name != "nt":  # Не Windows
            import stat
            self.data.chmod(0o700)
            self.backups.chmod(0o700)
            self.temp.chmod(0o700)
            self.logs.chmod(0o700)
class AppConfig:
    """Основная конфигурация приложения Madrigal Protocol Lab"""
    
    model_config = ConfigDict(extra="forbid")
    
    def __init__(self):
        # Загрузка конфигурации из переменных окружения
        self._load_from_environment()
        
        # Инициализация путей
        self._init_paths()
        
        # Создание необходимых директорий
        self.paths.ensure_directories()
    
    def _load_from_environment(self):
        """Загрузка конфигурации из переменных окружения"""
        self.security = SecurityConfig(
            mode=SecurityMode(os.environ.get("MPLAB_MODE", "local_secure")),
            environment=Environment(os.environ.get("MPLAB_ENV", "development")),
            host=os.environ.get("MPLAB_HOST", "127.0.0.1"),
            port=int(os.environ.get("MPLAB_PORT", "8010")),
            debug=os.environ.get("MPLAB_DEBUG", "false").lower() == "true",
            allowed_hosts=os.environ.get("MPLAB_ALLOWED_HOSTS", "127.0.0.1,localhost,::1").split(","),
            frontend_origins=os.environ.get("MPLAB_FRONTEND_ORIGINS", "").split(","),
            enable_tls=os.environ.get("MPLAB_ENABLE_TLS", "false").lower() == "true",
            cert_file=os.environ.get("MPLAB_CERT_FILE"),
            key_file=os.environ.get("MPLAB_KEY_FILE"),
        )
        
        # Загрузка конфигурации ограничений
        self.limits = LimitsConfig(
            rate_limit_requests=int(os.environ.get("MPLAB_RATE_LIMIT_REQUESTS", "100")),
            rate_limit_window_seconds=int(os.environ.get("MPLAB_RATE_LIMIT_WINDOW", "60")),
            max_concurrent_jobs=int(os.environ.get("MPLAB_MAX_CONCURRENT_JOBS", "10")),
            max_project_files=int(os.environ.get("MPLAB_MAX_PROJECT_FILES", "100")),
            max_capture_bytes=int(os.environ.get("MPLAB_MAX_CAPTURE_BYTES", str(100 * 1024 * 1024))),
            max_project_total_bytes=int(os.environ.get("MPLAB_MAX_PROJECT_TOTAL_BYTES", str(1024 * 1024 * 1024))),
            max_json_body_bytes=int(os.environ.get("MPLAB_MAX_JSON_BODY_BYTES", str(100 * 1024 * 1024))),
            max_page_size=int(os.environ.get("MPLAB_MAX_PAGE_SIZE", "100")),
            default_page_size=int(os.environ.get("MPLAB_DEFAULT_PAGE_SIZE", "20")),
        )
        
        # Загрузка конфигурации хранилища
        self.storage = StorageConfig(
            root=os.environ.get("MPLAB_STORAGE_ROOT", "."),
            data_dir=os.environ.get("MPLAB_DATA_DIR", "data"),
            backups_dir=os.environ.get("MPLAB_BACKUPS_DIR", "backups"),
            temp_dir=os.environ.get("MPLAB_TEMP_DIR", "temp"),
            logs_dir=os.environ.get("MPLAB_LOGS_DIR", "logs"),
            enforce_permissions=os.environ.get("MPLAB_ENFORCE_PERMISSIONS", "true").lower() == "true",
            restrict_symlinks=os.environ.get("MPLAB_RESTRICT_SYMLINKS", "true").lower() == "true",
            max_file_age_days=int(os.environ.get("MPLAB_MAX_FILE_AGE_DAYS", "0")) or None,
        )
    
    def _init_paths(self):
        """Инициализация путей на основе конфигурации"""
        self.paths = SecurityPaths(
            root=Path(self.storage.root),
            data=self.storage.root / self.storage.data_dir,
            backups=self.storage.root / self.storage.backups_dir,
            temp=self.storage.root / self.storage.temp_dir,
            logs=self.storage.root / self.storage.logs_dir,
        )
    
    def ensure_directories(self) -> SecurityPaths:
        """Создать все необходимые директории и вернуть пути"""
        self.paths.ensure_directories()
        return self.paths
    
    def get_security_settings(self) -> Dict[str, Any]:
        """Получить словарь настроек безопасности"""
        return {
            "mode": self.security.mode,
            "environment": self.security.environment,
            "host": self.security.host,
            "port": self.security.port,
            "debug": self.security.debug,
            "allowed_hosts": self.security.allowed_hosts,
            "frontend_origins": self.security.frontend_origins,
            "enable_tls": self.security.enable_tls,
        }
    
    def validate_configuration(self) -> Dict[str, Any]:
        """Валидация всей конфигурации"""
        validation_result = {
            "valid": True,
            "errors": [],
            "warnings": [],
            "info": []
        }
        
        # Проверка безопасности
        if self.security.mode == SecurityMode.LOCAL_SECURE:
            if not self._is_loopback_host(self.security.host):
                validation_result["valid"] = False
                validation_result["errors"].append(
                    f"В режиме local_secure разрешены только loopback адреса, получен: {self.security.host}"
                )
        
        # Проверка frontend origins
        if self.security.frontend_origins and not self.security.allowed_hosts:
            validation_result["warnings"].append(
                "frontend_origins настроены но allowed_hosts пуст. CORS может работать некорректно."
            )
        
        # Проверка frontend origins против allowed hosts
        for origin in self.security.frontend_origins:
            if not self._origin_matches_any_host(origin, self.security.allowed_hosts):
                validation_result["warnings"].append(
                    f"Frontend origin '{origin}' не соответствует allowed hosts."
                )
        
        # Проверка TLS настроек
        if self.security.enable_tls:
            if not self.security.cert_file or not self.security.key_file:
                validation_result["warnings"].append(
                    "TLS включен но сертификат или ключ не настроены."
                )
        
        # Проверка лимитов
        if self.limits.max_concurrent_jobs <= 0:
            validation_result["errors"].append("max_concurrent_jobs должен быть положительным числом")
        
        if self.limits.rate_limit_requests <= 0:
            validation_result["errors"].append("rate_limit_requests должен быть положительным числом")
        
        if self.limits.max_capture_bytes <= 0:
            validation_result["errors"].append("max_capture_bytes должен быть положительным числом")
        
        return validation_result
    
    def _is_loopback_host(self, host: str) -> bool:
        """Проверить, является ли хост loopback"""
        loopback_hosts = ["127.0.0.1", "::1", "localhost", "localhost.localdomain"]
        return host in loopback_hosts
    
    def _origin_matches_any_host(self, origin: str, hosts: list[str]) -> bool:
        """Проверить, совпадает ли origin с любым хостом"""
        if not origin.startswith(("http://", "https://")):
            return False
        
        try:
            parsed = self._parse_url(origin)
            if not parsed.get("host"):
                return False
            
            return parsed["host"] in hosts
        except Exception:
            return False
    
    def _parse_url(self, url: str) -> Dict[str, str]:
        """Парсить URL"""
        parsed = {}
        if url.startswith("https://"):
            parsed["protocol"] = "https"
            parsed["host"] = url[8:]
        elif url.startswith("http://"):
            parsed["protocol"] = "http"
            parsed["host"] = url[7:]
        else:
            parsed["protocol"] = "unknown"
            parsed["host"] = url
        
        # Удаление порта
        if ":" in parsed["host"]:
            parsed["host"], parsed["port"] = parsed["host"].split(":", 1)
        else:
            parsed["port"] = "80" if parsed["protocol"] == "http" else "443"
        
        return parsed