#!/usr/bin/env python3
"""
Генератор демо-данных Madrigal Protocol Lab

Создает реалистичный тестовый набор PCAP/PCAPNG файлов и лог действий
для проверки основных функций приложения.
"""

import argparse
import hashlib
import json
import struct
import random
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta

# Импорт существующих анализаторов
import sys
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from app.analyzers.capture_reader import CaptureReader
from app.analyzers.tcp_reassembly import Segment, reassemble
from app.analyzers.flow_manager import FlowSplitter, FlowPacket
from app.analyzers.framing import frame_stream, FramingConfig

# Константы для генерации
IP_POOL = ['192.168.1.100', '10.0.0.1', '172.16.0.1', '203.0.113.1']
MESSAGE_TYPES = {
    0x01: 'SET_PARAMETER',
    0x02: 'GET_PARAMETER', 
    0x03: 'EXECUTE_COMMAND',
    0x04: 'MEASUREMENT_DATA',
    0x05: 'STATUS_RESPONSE',
    0x0A: 'ERROR_RESPONSE'
}

class DemoGenerator:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.captures = []
        self.actions = []
        self.ports = list(range(8000, 9000))
        
    def generate_all(self) -> Dict[str, Path]:
        """Генерация всех демо-файлов"""
        print("Генерация демо-данных Madrigal Protocol Lab...")
        
        # 1. Базовое соединение (обмен параметрами)
        print("  1. Генерация базового соединения...")
        basic_pcap = self.generate_basic_connection()
        
        # 2. Соединение с измерениями
        print("  2. Генерация соединения с измерениями...")
        measurements_pcap = self.generate_measurement_connection()
        
        # 3. Соединение с ретрансмиссиями
        print("  3. Генерация соединения с ретрансмиссиями...")
        retransmission_pcap = self.generate_retransmission_connection()
        
        # 4. Соединение с неизвестным протоколом
        print("  4. Генерация соединения с неизвестным протоколом...")
        unknown_pcap = self.generate_unknown_protocol_connection()
        
        # Сохранение демо-действий
        actions_path = Path(f"data/demo/demo.actions.json")
        actions_path.parent.mkdir(parents=True, exist_ok=True)
        
        self.generate_demo_actions()
        self.save_actions(actions_path)
        
        return {
            'basic': basic_pcap,
            'measurements': measurements_pcap,
            'retransmission': retransmission_pcap,
            'unknown': unknown_pcap,
            'actions': actions_path
        }
    
    def generate_basic_connection(self) -> Path:
        """Генерация демо-соединения для чтения/изменения параметров"""
        packets = []
        base_time = datetime.now().timestamp()
        
        # Client: GET_PARAMETER (тип 0x02)
        client_ip, server_ip = random.sample(IP_POOL, 2)
        client_port, server_port = random.sample(self.ports, 2)
        
        # Генерация нескольких сообщений
        for i in range(15):
            timestamp = base_time + i * 0.2
            
            # Клиентское сообщение (запрос параметра)
            param_id = i % 5
            payload = struct.pack('>BHBB', 
                                 0x01,  # message_type: GET_PARAMETER
                                 param_id,  # parameter_id (1 байт)
                                 0x00 if i % 2 == 0 else 0x01)  # flags
            
            packets.append({
                'packet_index': len(packets),
                'timestamp': timestamp,
                'source_ip': client_ip,
                'source_port': client_port,
                'dest_ip': server_ip,
                'dest_port': server_port,
                'seq': i * 100,
                'payload': payload,
                'flags': 0x10  # ACK
            })
            
            # Серверское сообщение (ответ)
            timestamp += 0.05
            payload = struct.pack('>BHBB', 
                                 0x05,  # message_type: STATUS_RESPONSE
                                 param_id,
                                 0x80 if i % 3 == 0 else 0x00)  # additional flags
            # Добавление значения параметра
            payload += struct.pack('>I', i * 10)
            
            packets.append({
                'packet_index': len(packets),
                'timestamp': timestamp,
                'source_ip': server_ip,
                'source_port': server_port,
                'dest_ip': client_ip,
                'dest_port': client_port,
                'seq': i * 100 + len(payload),
                'payload': payload,
                'flags': 0x10
            })
        
        return self.write_pcapng(f"data/demo/basic.pcapng", packets)
    
    def generate_measurement_connection(self) -> Path:
        """Генерация соединения с данными измерений"""
        packets = []
        base_time = datetime.now().timestamp()
        
        client_ip, server_ip = '192.168.1.100', '10.0.0.1'
        client_port, server_port = 8080, 9090
        
        # Генерация структуры данных измерений
        for i in range(20):
            timestamp = base_time + i * 0.15
            
            # Запрос измерения
            payload = struct.pack('>BBHBB',
                                 0x04,  # message_type: MEASUREMENT_DATA
                                 0x01,  # measurement_type: temperature
                                 i * 100,  # measurement_id
                                 0x01,  # interval_ms
                                 0x00)  # sensor_status
            
            packets.append({
                'packet_index': len(packets),
                'timestamp': timestamp,
                'source_ip': client_ip,
                'source_port': client_port,
                'dest_ip': server_ip,
                'dest_port': server_port,
                'seq': i * 200,
                'payload': payload,
                'flags': 0x10
            })
            
            # Ответ с данными измерений
            timestamp += 0.03
            # Структура данных измерений: header + набор значений
            header = struct.pack('>BBHBB',
                                0x05,  # message_type: STATUS_RESPONSE
                                0x01,  # measurement_type
                                i * 100,
                                0x01,
                                0x80)  # данных доступны
            
            # 5 значений с плавающей точкой (фиксированная длина для демо)
            values = struct.pack('>fffff', 
                               20.5 + random.random(),
                               21.1 + random.random(),
                               20.8 + random.random(),
                               21.2 + random.random(),
                               20.9 + random.random())
            
            payload = header + values
            packets.append({
                'packet_index': len(packets),
                'timestamp': timestamp,
                'source_ip': server_ip,
                'source_port': server_port,
                'dest_ip': client_ip,
                'dest_port': client_port,
                'seq': i * 200 + len(payload),
                'payload': payload,
                'flags': 0x10
            })
        
        return self.write_pcapng(f"data/demo/measurements_64.pcapng", packets)
    
    def generate_retransmission_connection(self) -> Path:
        """Генерация соединения с ретрансмиссиями и out-of-order пакетами"""
        packets = []
        base_time = datetime.now().timestamp()
        
        client_ip, server_ip = '172.16.0.1', '203.0.113.1'
        client_port, server_port = 8000, 8001
        
        # Создание более сложного паттерна для тестирования ретрансмиссий
        messages = []
        for i in range(10):
            # Оригинальное сообщение
            timestamp = base_time + i * 0.3
            payload = struct.pack('>HBBBB', 
                                 0x0A00,  # length_prefix
                                 0x03,    # message_type: EXECUTE_COMMAND
                                 0x01,    # command_id
                                 0xAA,    # parameter1
                                 0xBB)    # parameter2
            
            messages.append(('original', timestamp, payload))
            
            # Ретрансмиссия (чуть позже)
            retx_timestamp = timestamp + 0.05
            messages.append(('retransmission', retx_timestamp, payload))
            
            # Out-of-order (быстрее)
            ooo_timestamp = timestamp - 0.02
            if ooo_timestamp > base_time:
                messages.append(('out_of_order', ooo_timestamp, payload))
        
        # Сортировка по времени
        messages.sort(key=lambda x: x[1])
        
        # Запись пакетов
        for idx, (msg_type, timestamp, payload) in enumerate(messages):
            source_ip = client_ip if idx % 2 == 0 else server_ip
            source_port = client_port if idx % 2 == 0 else server_port
            dest_ip = server_ip if idx % 2 == 0 else client_ip
            dest_port = server_port if idx % 2 == 0 else client_port
            
            packets.append({
                'packet_index': idx,
                'timestamp': timestamp,
                'source_ip': source_ip,
                'source_port': source_port,
                'dest_ip': dest_ip,
                'dest_port': dest_port,
                'seq': idx * 150,
                'payload': payload,
                'flags': 0x10
            })
        
        return self.write_pcapng(f"data/demo/retransmissions.pcapng", packets)
    
    def generate_unknown_protocol_connection(self) -> Path:
        """Генерация соединения с неизвестным/бинарным протоколом"""
        packets = []
        base_time = datetime.now().timestamp()
        
        client_ip, server_ip = '10.0.0.1', '192.168.1.100'
        client_port, server_port = 9000, 9001
        
        # Генерация случайных бинарных данных для неизвестного протокола
        for i in range(25):
            timestamp = base_time + i * 0.1
            
            # Случайная длина сообщения (от 8 до 64 байт)
            msg_len = random.randint(8, 64)
            payload = bytes(random.randint(0, 255) for _ in range(msg_len))
            
            # Добавление некоторых повторяющихся паттернов для эмуляции структуры
            if i % 5 == 0 and msg_len >= 4:
                payload = struct.pack('>BB', 0xFF, 0xAA) + payload[2:]
            
            packets.append({
                'packet_index': i,
                'timestamp': timestamp,
                'source_ip': client_ip,
                'source_port': client_port,
                'dest_ip': server_ip,
                'dest_port': server_port,
                'seq': i * 75,
                'payload': payload,
                'flags': 0x10 if i % 3 != 0 else 0x11  # occasional SYN
            })
        
        return self.write_pcapng(f"data/demo/unknown_status.pcapng", packets)
    
    def generate_demo_actions(self):
        """Генерация демо-действий пользователя"""
        base_time = datetime.now().timestamp()
        
        actions_templates = [
            {
                'action': 'set_parameter',
                'parameter': 'measurement_interval',
                'value': 60,
                'expected_result': 'success'
            },
            {
                'action': 'get_parameter',
                'parameter': 'device_id',
                'value': None,
                'expected_result': 'success'
            },
            {
                'action': 'set_parameter',
                'parameter': 'threshold',
                'value': 85.5,
                'expected_result': 'success'
            },
            {
                'action': 'execute_command',
                'parameter': 'start_measurement',
                'value': None,
                'expected_result': 'ack'
            },
            {
                'action': 'get_measurement',
                'parameter': 'current_reading',
                'value': 42.3,
                'expected_result': 'success'
            }
        ]
        
        for i in range(self.config['action_count']):
            template = random.choice(actions_templates)
            action_time = base_time + i * 0.5
            
            action = {
                'timestamp': action_time,
                'action': template['action'],
                'parameter': template['parameter'],
                'value': template['value'],
                'expected_result': template['expected_result']
            }
            
            # Добавление дополнительных полей для реалистичности
            if action['action'] in ['set_parameter', 'get_parameter']:
                action['device_id'] = f'device_{random.randint(1, 3)}'
                action['user_id'] = f'user_{random.randint(1, 5)}'
            
            self.actions.append(action)
    
    def write_pcapng(self, filename: str, packets: List[Dict]) -> Path:
        """Запись пакетов в PCAPNG формат"""
        path = Path(filename)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'wb') as f:
            # Заголовок секции PCAPNG
            f.write(struct.pack('<I', 0x0A0D0D0A))  # SHB type
            f.write(struct.pack('<I', 0x1A2B3C4D))  # byte-order magic
            f.write(struct.pack('<HHBB', 2, 2, 0x0F, 0))  # version, resolution
            f.write(struct.pack('<IIII', 0, 0, 65535, 1))  # section length, snaplen, link type
            
            # Interface Description Block
            f.write(struct.pack('<I', 0x00000001))  # IDB type
            f.write(struct.pack('<I', 44))  # total length
            f.write(struct.pack('<HIIBH', 1, 0, 0, 0, 0, 0))  # IDB fields
            
            # Enhanced Packet Blocks
            for pkt in packets:
                self.write_enhanced_packet(f, pkt)
            
            # Section Header Block (конец файла)
            f.write(struct.pack('<I', 0x0A0D0D0A))  # SHB type
            f.write(struct.pack('<I', 16))  # total length
            f.write(struct.pack('<IIII', 0, 0, 0xFFFFFFFFFFFFFFFF, 0))  # section length
        
        return path
    
    def write_enhanced_packet(self, file_handle, packet: Dict):
        """Запись одного Enhanced Packet Block"""
        # Вычисление длины
        payload = packet['payload']
        cap_len = len(payload)
        
        # Enhanced Packet Block заголовок
        block_type = 0x00000006  # EPB type
        block_body_len = 24 + cap_len  # EPB header + data
        timestamp_high = int(packet['timestamp']) >> 32
        timestamp_low = int(packet['timestamp']) & 0xFFFFFFFF
        
        file_handle.write(struct.pack('<I', block_type))
        file_handle.write(struct.pack('<I', block_body_len + 4))  # включая trailer
        file_handle.write(struct.pack('<IIIHH', 
                                    0,  # interface_id
                                    timestamp_high, timestamp_low,
                                    cap_len, len(payload)))
        
        # Данные пакета
        file_handle.write(payload)
        
        # Выравнивание до 4 байтов
        padding = (4 - (block_body_len + 4) % 4) % 4
        if padding:
            file_handle.write(b'\x00' * padding)
        
        # Трейлер (копия длины)
        file_handle.write(struct.pack('<I', block_body_len + 4))
    
    def save_actions(self, path: Path):
        """Сохранение действий в JSON"""
        # Конвертация timestamp в ISO формат для читаемости
        for action in self.actions:
            dt = datetime.fromtimestamp(action['timestamp'])
            action['timestamp_iso'] = dt.isoformat()
        
        with open(path, 'w') as f:
            json.dump(self.actions, f, indent=2, ensure_ascii=False)
    
    def generate_grounds_truth(self) -> Dict[str, Any]:
        """Генерация файла ground truth для тестирования"""
        truth = {
            'captures': {},
            'actions': self.actions,
            'analysis_timestamp': datetime.now().isoformat(),
            'demo_version': '1.0.0'
        }
        
        # Add basic information about each capture
        capture_configs = [
            ('basic', 'basic.pcapng', 0),
            ('measurements', 'measurements_64.pcapng', 1),
            ('retransmission', 'retransmissions.pcapng', 2),
            ('unknown', 'unknown_status.pcapng', 3)
        ]
        
        for name, filename, idx in capture_configs:
            truth['captures'][name] = {
                'file': filename,
                'description': f'Demo capture {name} for testing',
                'expected_sessions': idx + 2,
                'expected_messages': idx * 5 + 10,
                'protocol_type': 'unknown' if idx == 3 else 'parameter_exchange',
                'has_retransmissions': idx == 2,
                'has_unknown_protocol': idx == 3
            }
        
        # Сохранение ground truth
        truth_path = Path('data/demo/ground_truth.json')
        with open(truth_path, 'w') as f:
            json.dump(truth, f, indent=2)
        
        return truth

def choose_action(action_index: int) -> Dict[str, Any]:
    """Выбор действия из шаблона"""
    templates = [
        {
            'action': 'set_parameter',
            'parameter': 'measurement_interval',
            'value': 20 + (action_index % 5) * 10,
            'expected_result': 'success'
        },
        {
            'action': 'get_parameter',
            'parameter': 'device_id',
            'value': None,
            'expected_result': 'success'
        },
        {
            'action': 'set_parameter',
            'parameter': 'threshold',
            'value': 60.0 + action_index,
            'expected_result': 'success'
        },
        {
            'action': 'execute_command',
            'parameter': 'start_measurement',
            'value': None,
            'expected_result': 'ack'
        },
        {
            'action': 'get_measurement',
            'parameter': 'current_reading',
            'value': 20.0 + (action_index % 3) * 5,
            'expected_result': 'success'
        }
    ]
    return templates[action_index % len(templates)]

if __name__ == '__main__':
    import sys
    
    # Парсинг аргументов командной строки
    parser = argparse.ArgumentParser(
        description='Генератор демо-данных Madrigal Protocol Lab'
    )
    parser.add_argument(
        '--output',
        default='./data/demo',
        help='Выходной каталог (по умолчанию: ./data/demo)'
    )
    parser.add_argument(
        '--messages', 
        type=int, 
        default=100,
        help='Общее количество сообщений во всех captures'
    )
    parser.add_argument(
        '--actions',
        type=int,
        default=50,
        help='Количество действий пользователя'
    )
    parser.add_argument(
        '--count-only',
        action='store_true',
        help='Только сгенерировать файлы, не записывать действия'
    )
    
    args = parser.parse_args()
    
    # Создание генератора
    config = {
        'message_count': args.messages,
        'action_count': args.actions if not args.count_only else 0
    }
    
    generator = DemoGenerator(config)
    
    try:
        # Генерация capture файлов
        captures = generator.generate_all()
        
        # Генерация ground truth
        truth = generator.generate_grounds_truth()
        
        print("\n✅ Демо-данные успешно сгенерированы!")
        print(f"📁 Файлы сохранены в: {args.output}")
        print(f"📄 Capture файлы: {[Path(k).name for k in captures.keys() if k != 'actions']}")
        print(f"📄 Файл действий: {Path(captures['actions']).name}")
        print(f"📄 Ground truth: data/demo/ground_truth.json")
        
        print("\n🎯 Демонстрационный стенд готов к использованию!")
        print("\nОсновной сценарий демонстрации:")
        print("1. Импортировать базовую запись (basic.pcapng)")
        print("2. Выбрать TCP-сессию")
        print("3. Восстановить поток")
        print("4. Выделить сообщения (framing по length_prefix)")
        print("5. Сравнить обмены для разных типов действий")
        print("6. Найти поле параметра (смещение 4)")
        print("7. Создать правило интерпретации")
        print("8. Применить к базовому корпусу")
        print("9. Обнаружить контрпример в measurements.pcapng")
        print("10. Исправить правило")
        print("11. Повторно применить к дополнительному capture")
        print("12. Сформировать отчет")
        print("13. Экспортировать переносимый проект")
        
    except Exception as e:
        print(f"\n❌ Ошибка генерации: {e}")
        import traceback
        traceback.print_exc()
        sys.exit(1)