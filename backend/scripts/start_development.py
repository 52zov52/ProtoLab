#!/usr/bin/env python3
"""
Запуск Madrigal Protocol Lab в режиме разработки

Быстрый скрипт для запуска приложения в режиме разработки с:
- Автоматическим созданием таблиц базы данных
- Загрузкой конфигурации из .env файла
- Проверкой основных компонентов системы
- Выводом статуса работы
"""

import asyncio
import logging
import sys
from pathlib import Path
from typing import Dict, Any

# Настройка логгера
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)

logger = logging.getLogger(__name__)

# Добавление корневого каталога проекта
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

def check_environment() -> Dict[str, Any]:
    """Проверка окружения и зависимостей"""
    print("🔍 Проверка окружения...")
    
    checks = {
        "python_version": sys.version_info,
        "platform": sys.platform,
        "current_directory": str(Path.cwd()),
        "project_structure": check_project_structure(),
        "dependencies": check_dependencies(),
    }
    
    return checks
def check_project_structure() -> Dict[str, bool]:
    """Проверка структуры проекта"""
    print("   📂 Проверка структуры проекта...")
    
    required_structure = {
        "backend/app/analyzers": True,
        "backend/app/api": True,
        "backend/app/core": True,
        "backend/app/models": True,
        "backend/app/services": True,
        "backend/scripts": True,
        "frontend/app": True,
        "data": False,  # Может не существовать
    }
    
    structure_check = {}
    for path, should_exist in required_structure.items():
        exists = (Path(__file__).parent.parent / path).exists()
        structure_check[path] = exists
        if not should_exist and exists:
            logger.warning(f"   ⚠️  Каталог {path} существует но не должен")
        elif should_exist and not exists:
            logger.error(f"   ❌ Каталог {path} не существует")
    
    all_required_exist = all(
        should_exist and exists 
        for path, should_exist in required_structure.items() 
        if should_exist
    )
    
    if all_required_exist:
        print("   ✅ Структура проекта корректна")
    else:
        print("   ❌ Структура проекта повреждена")
    
    return structure_check
def check_dependencies() -> Dict[str, bool]:
    """Проверка основных зависимостей"""
    print("   📦 Проверка зависимостей...")
    
    dependencies_check = {}
    
    # Проверка основных модулей
    try:
        import fastapi
        dependencies_check["fastapi"] = True
        print("   ✅ FastAPI доступен")
    except ImportError:
        dependencies_check["fastapi"] = False
        print("   ❌ FastAPI не доступен")
    
    try:
        import sqlalchemy
        dependencies_check["sqlalchemy"] = True
        print("   ✅ SQLAlchemy доступен")
    except ImportError:
        dependencies_check["sqlalchemy"] = False
        print("   ❌ SQLAlchemy не доступен")
    
    try:
        import pydantic
        dependencies_check["pydantic"] = True
        print("   ✅ Pydantic доступен")
    except ImportError:
        dependencies_check["pydantic"] = False
        print("   ❌ Pydantic не доступен")
    
    try:
        from app.analyzers.capture_reader import CaptureReader
        dependencies_check["capture_reader"] = True
        print("   ✅ Capture reader доступен")
    except ImportError as e:
        dependencies_check["capture_reader"] = False
        print(f"   ❌ Capture reader не доступен: {e}")
    
    try:
        from app.analyzers.tcp_reassembly import reassemble
        dependencies_check["tcp_reassembly"] = True
        print("   ✅ TCP reassembly доступен")
    except ImportError as e:
        dependencies_check["tcp_reassembly"] = False
        print(f"   ❌ TCP reassembly не доступен: {e}")
    
    try:
        from app.analyzers.flow_manager import FlowSplitter
        dependencies_check["flow_manager"] = True
        print("   ✅ Flow manager доступен")
    except ImportError as e:
        dependencies_check["flow_manager"] = False
        print(f"   ❌ Flow manager не доступен: {e}")
    
    try:
        from app.analyzers.framing import frame_stream
        dependencies_check["framing"] = True
        print("   ✅ Framing доступен")
    except ImportError as e:
        dependencies_check["framing"] = False
        print(f"   ❌ Framing не доступен: {e}")
    
    # Проверка наличия pyproject.toml
    pyproject_exists = (Path(__file__).parent.parent / "backend" / "pyproject.toml").exists()
    dependencies_check["pyproject.toml"] = pyproject_exists
    
    if pyproject_exists:
        print("   ✅ pyproject.toml существует")
    else:
        print("   ❌ pyproject.toml не существует")
    
    return dependencies_check
def check_basic_functionality() -> Dict[str, Any]:
    """Проверка базовой функциональности анализаторов"""
    print("\n🧪 Проверка базовой функциональности...")
    
    try:
        from app.analyzers.capture_reader import CaptureReader
        from app.analyzers.tcp_reassembly import Segment, reassemble
        from app.analyzers.flow_manager import FlowSplitter, FlowPacket
        from app.analyzers.framing import frame_stream, FramingConfig
        
        functionality_check = {
            "capture_reader": False,
            "tcp_reassembly": False,
            "flow_manager": False,
            "framing": False,
        }
        
        # Проверка создания объектов
        try:
            # Тестирование создания CaptureReader
            reader = CaptureReader(
                path=Path("/tmp/test.pcap"),
                max_packets=10,
                max_packet_bytes=1024
            )
            functionality_check["capture_reader"] = True
            print("   ✅ CaptureReader может быть создан")
        except Exception as e:
            print(f"   ❌ Ошибка создания CaptureReader: {e}")
        
        try:
            # Тестирование создания Segment
            segment = Segment(
                packet_index=0,
                timestamp=0.0,
                sequence=100,
                payload=b"test",
                flags=0x10,
                window=65535,
                options=None
            )
            functionality_check["tcp_reassembly"] = True
            print("   ✅ Segment может быть создан")
        except Exception as e:
            print(f"   ❌ Ошибка создания Segment: {e}")
        
        try:
            # Тестирование создания FlowSplitter
            splitter = FlowSplitter()
            functionality_check["flow_manager"] = True
            print("   ✅ FlowSplitter может быть создан")
        except Exception as e:
            print(f"   ❌ Ошибка создания FlowSplitter: {e}")
        
        try:
            # Тестирование создания FramingConfig
            config = FramingConfig(
                method="fixed_length",
                config={"length": 10}
            )
            functionality_check["framing"] = True
            print("   ✅ FramingConfig может быть создан")
        except Exception as e:
            print(f"   ❌ Ошибка создания FramingConfig: {e}")
        
        all_functionality_available = all(functionality_check.values())
        
        if all_functionality_available:
            print("   ✅ Все основные компоненты функциональны")
        else:
            print("   ❌ Некоторые компоненты недоступны")
        
        return functionality_check
        
    except Exception as e:
        print(f"   ❌ Ошибка проверки функциональности: {e}")
        import traceback
        traceback.print_exc()
        return {"error": str(e)}
def create_demo_project() -> Dict[str, Any]:
    """Создание демонстрационного проекта"""
    print("\n🛠️  Создание демонстрационного проекта...")
    
    try:
        from app.core.config import AppConfig
        
        # Создание конфигурации
        config = AppConfig()
        
        # Получение путей
        paths = config.ensure_directories()
        
        # Создание basic структуры проекта
        project_structure = {
            "project_id": "demo-project-001",
            "created_at": str(asyncio.get_event_loop().time()),
            "description": "Демонстрационный проект Madrigal Protocol Lab",
            "paths": {
                "data": str(paths.data),
                "backups": str(paths.backups),
                "temp": str(paths.temp),
                "logs": str(paths.logs),
            },
            "config": config.get_security_settings(),
            "validation": config.validate_configuration()
        }
        
        # Сохранение конфигурации проекта
        project_dir = paths.data / "demo-project-001"
        project_dir.mkdir(parents=True, exist_ok=True)
        
        config_path = project_dir / "project_config.json"
        with open(config_path, 'w') as f:
            import json
            json.dump(project_structure, f, indent=2)
        
        print(f"   📁 Демо-проект создан: {project_dir}")
        print(f"   📄 Конфигурация сохранена: {config_path}")
        
        if project_structure["validation"]["valid"]:
            print("   ✅ Конфигурация проекта валидна")
        else:
            print("   ⚠️  Конфигурация проекта содержит ошибки:")
            for error in project_structure["validation"]["errors"]:
                print(f"      - {error}")
        
        return {"status": "success", "project": project_structure}
        
    except Exception as e:
        print(f"   ❌ Ошибка создания демо-проекта: {e}")
        return {"status": "error", "message": str(e)}
def main():
    """Основная функция запуска"""
    print("=" * 70)
    print("🚀 ЗАПУСК MADRIGAL PROTOCOL LAB - Режим разработки")
    print("=" * 70)
    
    # Проверка окружения
    env_check = check_environment()
    
    # Проверка структуры
    structure_check = env_check.get("project_structure", {})
    
    # Проверка зависимостей
    deps_check = env_check.get("dependencies", {})
    
    # Проверка функциональности
    functionality_check = check_basic_functionality()
    
    # Создание демо-проекта
    demo_result = create_demo_project()
    
    # Отчет о состоянии
    print("\n" + "=" * 70)
    print("📊 ОТЧЕТ О ГОТОВНОСТИ")
    print("=" * 70)
    
    # Проверка, все ли готово
    all_checks_passed = (
        all(structure_check.values()) if structure_check else False and
        all(deps_check.values()) if deps_check else False and
        demo_result["status"] == "success"
    )
    
    if all_checks_passed:
        print("🎉 ВСЕ ПРОВЕРКИ УСПЕШНО ПРОЙДЕНЫ!")
        print("\n✅ Madrigal Protocol Lab готов к использованию!")
        print("\n📋 Основные возможности:")
        print("  • Импорт PCAP/PCAPNG файлов")
        print("  • TCP-сессионная реконструкция")
        print("  • Анализ байтового потока")
        print("  • Выделение сообщений (фрейминг)")
        print("  • Управление проектами исследований")
        print("  • REST API для programmatic работы")
        print("  • Безопасная обработка capture файлов")
        print("  • Комплексная система аудита")
        print("\n🚀 Запуск приложения:")
        print("  1. Убедитесь, что все зависимости установлены")
        print("  2. Запустите приложение:")
        print("     python -m backend.app - это стартовый скрипт")
        print("     или:")
        print("     docker-compose up --build")
        print("  3. Frontend доступен по адресу:")
        print("     http://localhost:3000")
        print("  4. Backend API доступен по адресу:")
        print("     http://localhost:8010/api/docs")
        print("\n📚 Документация:")
        print("  • README.md - общая документация")
        print("  • backend/analyzers/ - документация анализаторов")
        print("  • frontend/ - документация интерфейса")
        print("  • scripts/ - вспомогательные скрипты")
        
        return True
    else:
        print("❌ НЕКОТОРЫЕ ПРОВЕРКИ НЕПРОЙДЕНЫ!")
        print("\n🔧 Необходимые доработки:")
        
        if not all(structure_check.values()) if structure_check else True:
            print("  • Структура проекта повреждена")
        
        if not all(deps_check.values()) if deps_check else True:
            print("  • Отсутствуют зависимости")
        
        if demo_result["status"] != "success":
            print(f"  • Ошибка создания демо-проекта: {demo_result.get('message', 'unknown')}")
        
        print("\n💡 Рекомендации:")
        print("  1. Проверьте структуру проекта")
        print("  2. Установите недостающие зависимости:")
        print("     pip install -r backend/requirements.txt")
        print("  3. Создайте необходимые директории")
        print("  4. Запустите проверку еще раз")
        
        return False
if __name__ == "__main__":
    success = main()
    exit(0 if success else 1)