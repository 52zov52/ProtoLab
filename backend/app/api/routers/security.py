"""Endpoints проверки безопасности и конфигурации.

Предоставляет возможность проверки состояния безопасности,
конфигурации и рекомендации для улучшения безопасности.
"""

from __future__ import annotations

from typing import Annotated
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from ..core.errors import AppError, SecurityViolation
from ..core.security import (
    check_host_header,
    enforce_body_size,
    is_cross_origin,
    is_loopback_host,
)
from ..db.base import DatabaseError
from ..core.config import get_settings
from .context import SessionDep, SettingsDep

router = APIRouter()
class SecurityService:
    """Сервис проверки безопасности."""

    def __init__(self, session: Session, settings) -> None:
        self.db = session
        self.settings = settings

    def check(self) -> dict:
        """Проверить состояние безопасности и конфигурации.

        Возвращает детальный отчет о безопасности, включая:
        - Состояние сетевой привязки
        - Состояние CORS
        - Состояние лимитов
        - Состояние хранилища
        - Причины любых проблем
        """
        report = {
            "mode": self.settings.mode,
            "host": self.settings.host,
            "port": self.settings.port,
            "debug": self.settings.debug,
            "allowed_hosts": self.settings.allowed_hosts,
            "frontend_origins": self.settings.frontend_origins,
            "limits": {
                "rate_limit_requests": self.settings.limits.rate_limit_requests,
                "rate_limit_window_seconds": self.settings.limits.rate_limit_window_seconds,
                "max_concurrent_jobs": self.settings.limits.max_concurrent_jobs,
                "max_json_body_bytes": self.settings.limits.max_json_body_bytes,
            },
            "storage_root": self.settings.ensure_directories().root,
            "bindings_ok": is_loopback_host(self.settings.host),
            "cors_ok": self._check_cors_configuration(),
            "limits_ok": self._check_limits_configuration(),
            "storage_ok": self._check_storage_configuration(),
            "reasons": {},
        }

        # Сбор причин проблем
        reasons = {}

        if not report["bindings_ok"]:
            reasons["binding"] = (
                "API привязан к ненуллу loopback адресу, что делает его доступным"
                " извне в режиме local_secure. Рекомендуется использовать 127.0.0.1"
            )

        if not report["cors_ok"]:
            missing = set(self.settings.frontend_origins)
            if not missing:
                reasons["cors"] = (
                    "Не настроено frontend origins. Защитите API от атак через чужой сайт."
                )
            else:
                reasons["cors"] = (
                    f"Frontend origins не разрешены. Allowed hosts: {self.settings.allowed_hosts}"
                )

        if not report["limits_ok"]:
            limits = report["limits"]
            if limits["rate_limit_requests"] >= 1000:
                reasons["limits"] = (
                    "Rate limit слишком высокий, что может привести к DoS уязвимости."
                    " Рекомендуется более строгий лимит."
                )
            else:
                reasons["limits"] = "Some limits may need adjustment."

        if not report["storage_ok"]:
            storage_root = report["storage_root"]
            if not storage_root or not storage_root.strip():
                reasons["storage"] = "Storage root не настроен."
            elif not self._is_storage_path_safe(storage_root):
                reasons["storage"] = "Storage root может быть небезопасным."

        report["reasons"] = reasons
        return report

    def _check_cors_configuration(self) -> bool:
        """Проверить, соответствует ли CORS конфигурация политике безопасности."""
        if not self.settings.frontend_origins:
            return False

        for origin in self.settings.frontend_origins:
            if not is_cross_origin(origin, None, self.settings.allowed_hosts):
                return False

        return True

    def _check_limits_configuration(self) -> bool:
        """Проверить, соответствуют ли лимиты рекомендациям безопасности."""
        limits = self.settings.limits

        if limits.rate_limit_requests >= 1000:
            return False

        if limits.max_concurrent_jobs >= 100:
            return False

        return True

    def _check_storage_configuration(self) -> bool:
        """Проверить, безопасна ли конфигурация хранилища."""
        try:
            storage_root = self.settings.ensure_directories().root
            return self._is_storage_path_safe(storage_root)
        except Exception:
            return False

    def _is_storage_path_safe(self, path: str) -> bool:
        """Проверить, безопасен ли storage path."""
        if not path or not path.strip():
            return False

        from pathlib import Path

        storage_path = Path(path).resolve()

        # Проверить, что storage path существует и является каталогом
        if not storage_path.exists() or not storage_path.is_dir():
            return False

        # Проверить, что storage path не является корневым каталогом системы
        import os

        system_root = Path(os.path.abspath(os.path.sep))
        if storage_path == system_root or storage_path.parents[0] == system_root:
            return False

        return True

    def validate_security_configuration(self) -> dict:
        """Проверить и вернуть детальный отчет о состоянии безопасности."""
        settings = self.settings

        validation = {
            "mode_validation": {
                "status": "ok",
                "message": "",
                "recommendations": []
            },
            "network_validation": {
                "status": "ok",
                "message": "",
                "recommendations": []
            },
            "cors_validation": {
                "status": "ok",
                "message": "",
                "recommendations": []
            },
            "limits_validation": {
                "status": "ok",
                "message": "",
                "recommendations": []
            },
            "storage_validation": {
                "status": "ok",
                "message": "",
                "recommendations": []
            }
        }

        # Проверка режима
        if settings.mode == "local_secure":
            if not is_loopback_host(settings.host):
                validation["network_validation"]["status"] = "error"
                validation["network_validation"]["message"] = (
                    f"API настроен на {settings.host}, который не является loopback-only "
                    "в режиме local_secure"
                )
                validation["network_validation"]["recommendations"].append(
                    "Измените MPLAB_HOST на 127.0.0.1 или ::1"
                )
            else:
                validation["network_validation"]["message"] = "Сетевая привязка безопасна"

        # Проверка CORS
        if not settings.frontend_origins:
            validation["cors_validation"]["status"] = "warning"
            validation["cors_validation"]["message"] = "Не настроено frontend origins"
            validation["cors_validation"]["recommendations"].append(
                "Настройте MPLAB_FRONTEND_ORIGINS для защиты от атак через чужой сайт"
            )
        else:
            validation["cors_validation"]["message"] = "CORS конфигурация настроена"

        # Проверка лимитов
        limits = settings.limits
        if limits.rate_limit_requests >= 1000:
            validation["limits_validation"]["status"] = "warning"
            validation["limits_validation"]["message"] = (
                f"Rate limit ({limits.rate_limit_requests}/окно) может быть слишком высоким"
            )
            validation["limits_validation"]["recommendations"].append(
                "Рассмотрите возможность снижения лимита до <= 1000"
            )

        # Проверка хранилища
        try:
            storage_root = settings.ensure_directories().root
            if not self._is_storage_path_safe(storage_root):
                validation["storage_validation"]["status"] = "error"
                validation["storage_validation"]["message"] = "Storage path может быть небезопасным"
                validation["storage_validation"]["recommendations"].append(
                    "Настройте безопасный storage root"
                )
            else:
                validation["storage_validation"]["message"] = "File storage безопасен"
        except Exception as e:
            validation["storage_validation"]["status"] = "error"
            validation["storage_validation"]["message"] = f"Ошибка при проверке хранилища: {str(e)}"

        # Определить общий статус
        overall_status = "ok"
        for check in validation.values():
            if check["status"] == "error":
                overall_status = "error"
                break
            elif check["status"] == "warning" and overall_status == "ok":
                overall_status = "warning"

        validation["overall_status"] = overall_status

        return validation
@router.get("/security", tags=["security"])
def get_security_status(
    session: SessionDep,
    settings: SettingsDep
) -> dict:
    """Получить текущий статус безопасности."""
    service = SecurityService(session, settings)
    return service.check()
@router.get("/security/validate", tags=["security"])
def validate_security_configuration(
    session: SessionDep,
    settings: SettingsDep
) -> dict:
    """Проверить конфигурацию безопасности и вернуть рекомендации."""
    service = SecurityService(session, settings)
    return service.validate_security_configuration()
@router.post("/security/host-header", tags=["security"], status_code=200)
def validate_host_header(
    host_header: str,
    session: SessionDep,
    settings: SettingsDep
) -> dict:
    """Проверить конкретный Host header на соответствие политике."""
    try:
        check_host_header(host_header, settings.allowed_hosts)
        return {
            "valid": True,
            "host": host_header,
            "message": "Host header соответствует политике безопасности"
        }
    except SecurityViolation as e:
        return {
            "valid": False,
            "host": host_header,
            "message": str(e),
            "code": "security_violation"
        }
@router.post("/security/cors", tags=["security"], status_code=200)
def validate_cors(
    origin: str,
    referer: str | None = None,
    session: SessionDep = None,
    settings: SettingsDep = None
) -> dict:
    """Проверить Origin header на соответствие CORS политике."""
    if not settings:
        # Для backward compatibility, если настройки не переданы
        from ..core.config import get_settings
        settings = get_settings()

    if not is_cross_origin(origin, referer, settings.allowed_hosts):
        return {
            "valid": False,
            "origin": origin,
            "referer": referer,
            "message": "Cross-origin запрос отклонен",
            "code": "cors_violation"
        }
    else:
        return {
            "valid": True,
            "origin": origin,
            "referer": referer,
            "message": "Origin header соответствует CORS политике"
        }