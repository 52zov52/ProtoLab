"""Система обработки ошибок Madrigal Protocol Lab

Комплексная система исключений с:
- Стандартизированными кодами ошибок
- Детализированной диагностикой
- Безопасным раскрытием информации
- Восстановлением работы приложения
"""

from __future__ import annotations

import logging
import traceback
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, Optional
from fastapi import HTTPException
from fastapi.responses import JSONResponse
from sqlalchemy.exc import SQLAlchemyError

# Настройка логгера
logger = logging.getLogger(__name__)
class ErrorCode(str, Enum):
    """Коды ошибок API"""
    
    # Клиентские ошибки (4xx)
    VALIDATION_FAILED = "validation_failed"
    NOT_FOUND = "not_found"
    CONFLICT = "conflict"
    RATE_LIMITED = "rate_limited"
    PAYLOAD_TOO_LARGE = "payload_too_large"
    UNSUPPORTED_MEDIA_TYPE = "unsupported_media_type"
    METHOD_NOT_ALLOWED = "method_not_allowed"
    SECURITY_VIOLATION = "security_violation"
    CAPTURE_READ_ERROR = "capture_read_error"
    FILE_UPLOAD_ERROR = "file_upload_error"
    PROJECT_NOT_FOUND = "project_not_found"
    CAPTURE_NOT_FOUND = "capture_not_found"
    SESSION_NOT_FOUND = "session_not_found"
    STREAM_NOT_FOUND = "stream_not_found"
    MESSAGE_NOT_FOUND = "message_not_found"
    
    # Ошибки сервера (5xx)
    INTERNAL_ERROR = "internal_error"
    DATABASE_ERROR = "database_error"
    ANALYSIS_ERROR = "analysis_error"
    TRANSPORTATION_ERROR = "transportation_error"
    SERVICE_UNAVAILABLE = "service_unavailable"
    TIMEOUT_ERROR = "timeout_error"
    NOT_IMPLEMENTED = "not_implemented"
    
    # Ошибки анализа
    TCP_REASSEMBLY_ERROR = "tcp_reassembly_error"
    FRAMING_ERROR = "framing_error"
    PROTOCOL_DETECTION_ERROR = "protocol_detection_error"
    FIELD_INFERENCE_ERROR = "field_inference_error"
    VALIDATION_ERROR = "validation_error"
    ANOMALY_DETECTION_ERROR = "anomaly_detection_error"
    SPECIFICATION_ERROR = "specification_error"
class ErrorContext:
    """Контекст ошибки для расширенной диагностики"""
    
    def __init__(
        self,
        request_id: Optional[str] = None,
        project_id: Optional[str] = None,
        capture_id: Optional[str] = None,
        session_id: Optional[str] = None,
        stream_id: Optional[str] = None,
        message_id: Optional[str] = None,
        operation: Optional[str] = None,
        timestamp: Optional[datetime] = None
    ):
        self.request_id = request_id
        self.project_id = project_id
        self.capture_id = capture_id
        self.session_id = session_id
        self.stream_id = stream_id
        self.message_id = message_id
        self.operation = operation
        self.timestamp = timestamp or datetime.now(timezone.utc)
    
    def to_dict(self) -> Dict[str, Any]:
        return {
            "request_id": self.request_id,
            "project_id": self.project_id,
            "capture_id": self.capture_id,
            "session_id": self.session_id,
            "stream_id": self.stream_id,
            "message_id": self.message_id,
            "operation": self.operation,
            "timestamp": self.timestamp.isoformat()
        }
class AppError(Exception):
    """Базовый класс для всех ошибок приложения"""
    
    def __init__(
        self,
        message: str,
        code: ErrorCode = ErrorCode.INTERNAL_ERROR,
        status_code: Optional[int] = None,
        details: Optional[Dict[str, Any]] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None,
        user_message: Optional[str] = None,
        recovery_suggestion: Optional[str] = None
    ):
        super().__init__(message)
        self.message = message
        self.code = code
        self.status_code = status_code or self._get_default_status_code(code)
        self.details = details or {}
        self.context = context or ErrorContext()
        self.cause = cause
        self.user_message = user_message or message
        self.recovery_suggestion = recovery_suggestion
        self.timestamp = datetime.now(timezone.utc)
        self.request_id = context.request_id if context else None
        
        # Логирование ошибки
        self._log_error()
    
    def _get_default_status_code(self, code: ErrorCode) -> int:
        status_mapping = {
            ErrorCode.VALIDATION_FAILED: 400,
            ErrorCode.NOT_FOUND: 404,
            ErrorCode.CONFLICT: 409,
            ErrorCode.RATE_LIMITED: 429,
            ErrorCode.PAYLOAD_TOO_LARGE: 413,
            ErrorCode.UNSUPPORTED_MEDIA_TYPE: 415,
            ErrorCode.METHOD_NOT_ALLOWED: 405,
            ErrorCode.SECURITY_VIOLATION: 403,
            ErrorCode.CAPTURE_READ_ERROR: 400,
            ErrorCode.FILE_UPLOAD_ERROR: 400,
            ErrorCode.PROJECT_NOT_FOUND: 404,
            ErrorCode.CAPTURE_NOT_FOUND: 404,
            ErrorCode.SESSION_NOT_FOUND: 404,
            ErrorCode.STREAM_NOT_FOUND: 404,
            ErrorCode.MESSAGE_NOT_FOUND: 404,
            ErrorCode.INTERNAL_ERROR: 500,
            ErrorCode.DATABASE_ERROR: 503,
            ErrorCode.ANALYSIS_ERROR: 422,
            ErrorCode.TRANSPORTATION_ERROR: 502,
            ErrorCode.SERVICE_UNAVAILABLE: 503,
            ErrorCode.TIMEOUT_ERROR: 504,
            ErrorCode.NOT_IMPLEMENTED: 501,
            ErrorCode.TCP_REASSEMBLY_ERROR: 400,
            ErrorCode.FRAMING_ERROR: 400,
            ErrorCode.PROTOCOL_DETECTION_ERROR: 422,
            ErrorCode.FIELD_INFERENCE_ERROR: 422,
            ErrorCode.VALIDATION_ERROR: 422,
            ErrorCode.ANOMALY_DETECTION_ERROR: 422,
            ErrorCode.SPECIFICATION_ERROR: 400,
        }
        return status_mapping.get(code, 500)
    
    def _log_error(self):
        """Логирование ошибки с контекстом"""
        log_data = {
            "error_code": self.code,
            "message": self.message,
            "user_message": self.user_message,
            "request_id": self.request_id,
            "timestamp": self.timestamp.isoformat(),
        }
        
        if self.code.value.startswith("4"):
            logger.warning("Client error", extra=log_data)
        else:
            logger.error("Server error", extra=log_data, exc_info=self.cause)
    
    def to_payload(self, include_cause: bool = False) -> Dict[str, Any]:
        """Преобразование ошибки в JSON ответ API"""
        payload = {
            "error": {
                "code": self.code,
                "message": self.user_message,
                "timestamp": self.timestamp.isoformat(),
                "request_id": self.request_id,
            }
        }
        
        if include_cause and self.cause:
            payload["error"]["debug_info"] = {
                "cause_type": type(self.cause).__name__,
                "cause_message": str(self.cause),
            }
        
        if self.details:
            payload["error"]["details"] = self.details
        
        if self.recovery_suggestion:
            payload["error"]["recovery_suggestion"] = self.recovery_suggestion
        
        return payload
class ValidationError(AppError):
    """Ошибка валидации данных"""
    
    def __init__(
        self,
        message: str,
        field: Optional[str] = None,
        value: Optional[Any] = None,
        context: Optional[ErrorContext] = None
    ):
        details = {}
        if field:
            details["field"] = field
        if value is not None:
            details["value"] = str(value)
        
        super().__init__(
            message=f"Ошибка валидации: {message}",
            code=ErrorCode.VALIDATION_FAILED,
            details=details,
            context=context,
            user_message=f"Недопустимые данные: {message}",
            recovery_suggestion="Проверьте введенные данные."
        )
class NotFoundError(AppError):
    """Ошибка - объект не найден"""
    
    def __init__(
        self,
        object_type: str,
        object_id: str,
        context: Optional[ErrorContext] = None
    ):
        super().__init__(
            message=f"{object_type} с ID '{object_id}' не найден",
            code=ErrorCode.NOT_FOUND,
            details={"object_type": object_type, "object_id": object_id},
            context=context,
            user_message=f"{object_type} не найден.",
            recovery_suggestion=f"Проверьте правильность ID {object_type}."
        )
class CaptureReadError(AppError):
    """Ошибка чтения capture файла"""
    
    def __init__(
        self,
        message: str,
        capture_id: Optional[str] = None,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        details = {}
        if capture_id:
            details["capture_id"] = capture_id
        
        super().__init__(
            message=f"Ошибка чтения capture: {message}",
            code=ErrorCode.CAPTURE_READ_ERROR,
            details=details,
            context=context,
            cause=cause,
            user_message=f"Не удалось прочитать capture файл.",
            recovery_suggestion="Проверьте целостность файла или перезагрузите capture."
        )
class TcpReassemblyError(AppError):
    """Ошибка реконструкции TCP-соединения"""
    
    def __init__(
        self,
        session_id: str,
        message: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        details = {"session_id": session_id}
        
        super().__init__(
            message=f"Ошибка реконструкции TCP-соединения {session_id}: {message}",
            code=ErrorCode.TCP_REASSEMBLY_ERROR,
            details=details,
            context=context,
            cause=cause,
            user_message=f"Ошибка реконструкции TCP-потока.",
            recovery_suggestion="Проверьте capture на предмет поврежденных пакетов."
        )
class FramingError(AppError):
    """Ошибка фрейминга сообщений"""
    
    def __init__(
        self,
        stream_id: str,
        message: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        details = {"stream_id": stream_id}
        
        super().__init__(
            message=f"Ошибка фрейминга в потоке {stream_id}: {message}",
            code=ErrorCode.FRAMING_ERROR,
            details=details,
            context=context,
            cause=cause,
            user_message=f"Не удалось выделить сообщения.",
            recovery_suggestion="Попробуйте другое правило фрейминга."
        )
class AnalysisError(AppError):
    """Общая ошибка анализа"""
    
    def __init__(
        self,
        message: str,
        context: Optional[ErrorContext] = None,
        cause: Optional[Exception] = None
    ):
        error_code = ErrorCode.ANALYSIS_ERROR
        if isinstance(cause, SQLAlchemyError):
            error_code = ErrorCode.DATABASE_ERROR
        
        super().__init__(
            message=f"Ошибка анализа: {message}",
            code=error_code,
            context=context,
            cause=cause,
            user_message=f"Ошибка во время анализа: {message}",
            recovery_suggestion="Попробуйте выполнить операцию снова."
        )
# Фабрика ошибок
def create_error(error_type: str, message: str, **kwargs) -> AppError:
    """Создать ошибку по типу"""
    error_mapping = {
        "validation": ValidationError,
        "not_found": NotFoundError,
        "capture_read": CaptureReadError,
        "tcp_reassembly": TcpReassemblyError,
        "framing": FramingError,
        "analysis": AnalysisError,
    }
    
    if error_type not in error_mapping:
        raise ValueError(f"Неизвестный тип ошибки: {error_type}")
    
    error_class = error_mapping[error_type]
    return error_class(message, **kwargs)

# Утилиты для работы с ошибками
def safe_execute(func, error_type: str = "analysis", context: Optional[ErrorContext] = None, default_return: Any = None):
    """Безопасное выполнение функции с обработкой исключений"""
    try:
        return func()
    except AppError:
        raise
    except Exception as e:
        raise AnalysisError(f"Непредвидимая ошибка: {str(e)}", operation=func.__name__, context=context, cause=e) from e
    return default_return

def format_error_response(error: AppError, debug: bool = False) -> JSONResponse:
    """Форматирование ошибки в JSONResponse"""
    return JSONResponse(
        status_code=error.status_code,
        content=error.to_payload(include_cause=debug),
        headers={"Cache-Control": "no-store"}
    )