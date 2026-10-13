import type { TranslationFragment } from "@/lib/i18n/locales/types";

/**
 * Russian translations for the packet-inspection pages:
 * Captures, Packets, TCP Sessions and TLS Analysis.
 *
 * Keys are the English source strings used in those pages. See `ru.ts` for how
 * the fragments are merged and `tests/i18n.test.tsx` for the coverage check.
 */
export const RU_PAGES_A: TranslationFragment = {
  // --------------------------------------------------------------------------
  // Captures
  // --------------------------------------------------------------------------
  "No project selected": "Проект не выбран",
  "Open a project on the Overview page first.":
    "Сначала откройте проект на странице «Обзор».",
  Captures: "Захваты",
  "Imported files are immutable. Analysis reads them and writes derived artefacts alongside; the original bytes are never rewritten.":
    "Импортированные файлы неизменяемы. Анализ читает их и записывает производные артефакты рядом; исходные байты никогда не перезаписываются.",
  "Importing…": "Импорт…",
  "Import PCAP": "Импортировать PCAP",
  "Project totals": "Итоги проекта",
  captures: "захваты",
  packets: "пакеты",
  "tcp sessions": "TCP-сессии",
  messages: "сообщения",
  "bytes stored": "байт сохранено",
  "Captures in this project": "Захваты в этом проекте",
  "No captures yet": "Захватов пока нет",
  "Import a PCAP or PCAPNG file to begin. The original bytes are stored immutably and hashed.":
    "Чтобы начать, импортируйте файл PCAP или PCAPNG. Исходные байты хранятся неизменно и хэшируются.",
  "Selected capture": "Выбранный захват",
  "No capture selected": "Захват не выбран",
  "Import a file to begin.": "Чтобы начать, импортируйте файл.",
  name: "имя",
  format: "формат",
  size: "размер",
  sha256: "sha256",
  imported: "импортирован",
  status: "статус",
  "Analysis finished.": "Анализ завершён.",
  "Analysing…": "Идёт анализ…",
  "Run analysis": "Запустить анализ",
  "Queued as a background job.": "Поставлено в очередь как фоновое задание.",
  "Queue in background": "Выполнить в фоне",
  'Delete "{name}" and everything derived from it?':
    "Удалить «{name}» и всё, что из него получено?",
  "This cannot be undone.": "Это действие необратимо.",
  "Capture deleted.": "Захват удалён.",
  Delete: "Удалить",
  "Analysis result": "Результат анализа",
  "Not analysed yet": "Анализ ещё не выполнен",
  "Run the analysis to index packets, split TCP sessions and reconstruct the byte streams.":
    "Запустите анализ, чтобы проиндексировать пакеты, разделить TCP-сессии и пересобрать байтовые потоки.",
  sessions: "сессии",
  streams: "потоки",
  "sessions with problems": "сессии с проблемами",
  "Reader diagnostics": "Диагностика чтения",
  "No read errors.": "Ошибок чтения нет.",
  "Analysis options (recorded for reproducibility)":
    "Параметры анализа (записаны для воспроизводимости)",
  "These counts come from the options recorded above. Re-running with a different framing rule or conflict policy produces a different set of rows from the same bytes.":
    "Эти числа получены с параметрами, записанными выше. Повторный запуск с другим правилом кадрирования или политикой разрешения конфликтов даёт другой набор строк из тех же байтов.",
  "TCP sessions in this capture": "TCP-сессии в этом захвате",
  Identity: "Идентичность",
  Endpoints: "Узлы",
  Completeness: "Полнота",
  "Role basis": "Основание роли",
  "No sessions": "Сессий нет",
  "This capture contains no TCP conversations.": "В этом захвате нет TCP-бесед.",

  // --------------------------------------------------------------------------
  // Packets
  // --------------------------------------------------------------------------
  "The packet table lists the packets of one capture. Pick a capture first.":
    "Таблица пакетов показывает пакеты одного захвата. Сначала выберите захват.",
  "Go to Captures": "Перейти к захватам",
  Packets: "Пакеты",
  "The packets of this capture as imported (offsets, flags, lengths). Rows are only rendered while visible; click a packet to see its original bytes.":
    "Пакеты этого захвата в исходном виде (смещения, флаги, длины). Строки отрисовываются, только пока видны; щёлкните пакет, чтобы увидеть его исходные байты.",
  "search address…": "поиск адреса…",
  "any transport": "любой транспорт",
  TCP: "TCP",
  UDP: "UDP",
  ICMP: "ICMP",
  IGMP: "IGMP",
  other: "другое",
  "min payload": "мин. полезная нагрузка",
  "{count} packet(s) · page {page}/{pageCount}": "{count} пакет(ов) · стр. {page}/{pageCount}",
  Prev: "Назад",
  Next: "Вперёд",
  "Packet table": "Таблица пакетов",
  "{count} rendered": "отрисовано: {count}",
  "Packet bytes": "Байты пакета",
  "No packet selected": "Пакет не выбран",
  "Click a row to fetch the original on-disk bytes of that packet from the immutable capture file.":
    "Щёлкните строку, чтобы получить исходные байты этого пакета из неизменяемого файла захвата.",
  "Packet #{index} · {count} byte(s)": "Пакет №{index} · {count} байт(ов)",

  // --------------------------------------------------------------------------
  // TCP Sessions
  // --------------------------------------------------------------------------
  "Pick a capture on the Captures page first; TCP sessions are derived from it.":
    "Сначала выберите захват на странице «Захваты»; TCP-сессии строятся из него.",
  "TCP Sessions": "TCP-сессии",
  "A 4-tuple is not a session. Port reuse and a new SYN split the flow; the splitting policy is recorded on every session so a result can be explained later.":
    "Четвёрка (4-tuple) — это ещё не сессия. Повторное использование порта и новый SYN разделяют поток; политика разделения записывается для каждой сессии, чтобы результат можно было объяснить позже.",
  Sessions: "Сессии",
  "No TCP sessions": "TCP-сессий нет",
  "This capture has not been analysed, or contains no TCP traffic.":
    "Этот захват не проанализирован или не содержит TCP-трафика.",
  "Select a session": "Выберите сессию",
  "The timeline shows only what the capture observed. It is not a reconstruction of either TCP stack.":
    "Временная шкала показывает только то, что наблюдалось в захвате. Это не воссоздание ни одного из стеков TCP.",
  "Observed state diagram": "Наблюдаемая диаграмма состояний",
  "R retransmission · O out of order · Z zero window":
    "R — повтор · O — нарушение порядка · Z — нулевое окно",
  "Connection state (observed)": "Состояние соединения (наблюдаемое)",
  "SYN {state}": "SYN {state}",
  "FIN {state}": "FIN {state}",
  "RST {state}": "RST {state}",
  seen: "виден",
  "not seen": "не виден",
  Time: "Время",
  Dir: "Напр.",
  Source: "Источник",
  Flags: "Флаги",
  Seq: "Seq",
  Ack: "Ack",
  Win: "Win",
  Payload: "Полезн.",
  Options: "Опции",
  "Reconstruction diagnostics": "Диагностика пересборки",
  "No diagnostics": "Диагностика отсутствует",
  "No stream payload was observed for this session.":
    "Для этой сессии полезная нагрузка потока не наблюдалась.",
  "conflict policy: {policy}": "политика конфликтов: {policy}",
  retransmissions: "повторы",
  "exact duplicates": "точные дубликаты",
  "out of order": "нарушение порядка",
  holes: "разрывы",
  "byte conflicts": "конфликты байтов",
  "zero window": "нулевое окно",
  "gap {start}..{end} ({reason})": "разрыв {start}..{end} ({reason})",
  "offsets {start}..{end}: kept {kept} / rejected {rejected} ({resolution})":
    "смещения {start}..{end}: принято {kept} / отклонено {rejected} ({resolution})",
  "What these labels mean": "Что означают эти метки",

  // --------------------------------------------------------------------------
  // TLS Analysis
  // --------------------------------------------------------------------------
  "TLS Analysis fingerprints the handshakes inside one capture. Pick a capture first; fingerprinting reads the plaintext handshake, so it works on encrypted sessions and needs no keys.":
    "Анализ TLS снимает отпечатки рукопожатий внутри одного захвата. Сначала выберите захват; снятие отпечатков читает открытый текст рукопожатия, поэтому работает с зашифрованными сессиями и не требует ключей.",
  "TLS Analysis": "Анализ TLS",
  "JA3 and JA3S fingerprints of the handshakes in this capture, matched against a small, locally maintained table. A match identifies a known client family — it is not proof of the implementation language and never an indication of maliciousness.":
    "Отпечатки JA3 и JA3S рукопожатий в этом захвате, сопоставленные с небольшой локальной таблицей. Совпадение указывает на известное семейство клиентов — это не доказательство языка реализации и никогда не признак вредоносности.",
  Verdict: "Вердикт",
  "client fingerprints: {count}": "отпечатки клиентов: {count}",
  "non-browser matches: {count}": "совпадения не-браузерных клиентов: {count}",
  "unreliable handshakes: {count}": "ненадёжные рукопожатия: {count}",
  "streams scanned: {scanned}/{total}": "просканировано потоков: {scanned}/{total}",
  "{label}: {count}": "{label}: {count}",
  "fingerprint database: {database}": "база отпечатков: {database}",
  Fingerprints: "Отпечатки",
  "only non-browser clients": "только не-браузерные клиенты",
  "No fingerprints": "Отпечатков нет",
  "No TLS handshake was found at the head of any stream. That means this capture has no TLS handshake, not that the traffic was not encrypted.":
    "В начале ни одного потока не найдено рукопожатие TLS. Это значит, что в этом захвате нет рукопожатия TLS, а не то, что трафик не зашифрован.",
  "No fingerprint matches the current filter.":
    "Ни один отпечаток не соответствует текущему фильтру.",
  Kind: "Тип",
  Fingerprint: "Отпечаток",
  "Client family": "Семейство клиента",
  Class: "Класс",
  Confidence: "Уверенность",
  Seen: "Наблюдений",
  "SNI / ALPN": "SNI / ALPN",
  browser: "браузер",
  "library / script": "библиотека / скрипт",
  "bot / automation": "бот / автоматизация",
  server: "сервер",
  unmatched: "не сопоставлено",
  "no local match": "нет локального совпадения",
  "source: {source}": "источник: {source}",
  "{count} stream(s)": "{count} поток(ов)",
  "sni: {value}": "sni: {value}",
  "alpn: {value}": "alpn: {value}",
  "tls: {value}": "tls: {value}",
  "A fingerprint names a client library or family, not a human or a piece of malware. The same library produces the same hash for legitimate and abusive traffic alike, so this table is a lead to investigate, never a verdict on its own.":
    "Отпечаток указывает на клиентскую библиотеку или семейство, а не на человека или вредоносную программу. Одна и та же библиотека даёт один и тот же хэш и для легитимного, и для нежелательного трафика, поэтому эта таблица — зацепка для расследования, а не самостоятельный вердикт.",
};
