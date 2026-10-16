/**
 * Russian translations, keyed by the English source string.
 *
 * English is the identity translation (the key itself), so any message missing
 * here degrades to readable English rather than to a raw key. That also means
 * this file is the full list of translated messages; `tests/i18n.test.tsx`
 * asserts that every `t("…")` literal in the source has an entry so nothing is
 * silently left in English.
 */
import { RU_PAGES_A } from "@/lib/i18n/locales/pagesA";
import { RU_PAGES_B } from "@/lib/i18n/locales/pagesB";
import { RU_PAGES_C } from "@/lib/i18n/locales/pagesC";

export const RU_MESSAGES: Record<string, string> = {
  // ------------------------------------------------------------------------
  // Shared shell
  // ------------------------------------------------------------------------
  Overview: "Обзор",
  "Project metrics and health": "Метрики проекта и состояние",
  Captures: "Захваты",
  "Imported packet captures": "Импортированные захваты пакетов",
  Packets: "Пакеты",
  "Virtualised packet table": "Виртуализированная таблица пакетов",
  "TCP Sessions": "TCP-сессии",
  "Conversations and reassembly": "Беседы и пересборка",
  "Stream Explorer": "Потоки",
  "Bytes, hex and provenance": "Байты, hex и происхождение",
  "TLS Analysis": "Анализ TLS",
  "JA3/JA3S fingerprints and client families": "Отпечатки JA3/JA3S и семейства клиентов",
  "Protocol Workbench": "Верстак протокола",
  "Framing, comparison, fields": "Кадрирование, сравнение, поля",
  "Hypotheses & Rules": "Гипотезы и правила",
  "Specs, validation, counterexamples": "Спецификации, проверка, контрпримеры",
  "Capture Diff": "Сравнение захватов",
  "Compare two recordings": "Сравнить две записи",
  "Network Graph": "Граф сети",
  "Observed interactions": "Наблюдаемые взаимодействия",
  "Anomaly Detection": "Поиск аномалий",
  "Baseline outlier scoring": "Оценка выбросов относительно базы",
  "Investigation Assistant": "Помощник расследования",
  "Typed natural-language search": "Типизированный поиск на естественном языке",
  Reports: "Отчёты",
  "Evidence-linked investigation report": "Отчёт со ссылками на доказательства",
  "Security Center": "Центр безопасности",
  "Real configuration checks": "Реальные проверки конфигурации",
  "Project Settings": "Настройки проекта",
  "Project options and AI consent": "Параметры проекта и согласие на ИИ",
  Project: "Проект",
  "none selected": "не выбран",
  "Local secure mode. Every conclusion links to the bytes it came from.":
    "Локальный защищённый режим. Каждый вывод ссылается на байты, из которых он получен.",
  "Current project": "Текущий проект",
  "Open the project list": "Открыть список проектов",
  "no project": "нет проекта",
  "capture {id}": "захват {id}",
  "no capture selected": "захват не выбран",
  "Search the investigation": "Поиск по расследованию",
  "Search: responses longer than 1000 bytes": "Поиск: ответы длиннее 1000 байт",
  "backend up": "backend доступен",
  "backend down": "backend недоступен",
  "Backend reachable": "Backend доступен",
  "Background jobs in flight": "Фоновые задания в работе",
  "Import .mplab": "Импорт .mplab",
  Export: "Экспорт",
  Exporting: "Экспорт…",
  "Export the project as a portable .mplab archive":
    "Экспортировать проект в переносимый архив .mplab",
  "Archive written: {archive} ({bytes} bytes)": "Архив записан: {archive} ({bytes} байт)",
  "Imported {summary}; {count} hash mismatch(es)":
    "Импортировано {summary}; несовпадений хэшей: {count}",
  "{count} job(s)": "{count} задание(й)",
  "Language": "Язык",
  Dismiss: "Закрыть",

  // ------------------------------------------------------------------------
  // Shared primitives
  // ------------------------------------------------------------------------
  "Request failed": "Запрос не выполнен",
  Retry: "Повторить",
  Loading: "Загрузка",
  Cancel: "Отмена",
  "No project selected": "Проект не выбран",
  "No capture selected": "Захват не выбран",
  "No captures yet": "Захватов пока нет",

  // ------------------------------------------------------------------------
  // Project / capture pickers
  // ------------------------------------------------------------------------
  "Investigation project": "Проект расследования",
  "loading…": "загрузка…",
  Refresh: "Обновить",
  "No projects yet": "Проектов пока нет",
  "Create an investigation project, then import a PCAP capture to begin.":
    "Создайте проект расследования, затем импортируйте захват PCAP.",
  "{captures} capture(s) · {messages} message(s) · {hypotheses} hypothesis/hypotheses":
    "{captures} захват(ов) · {messages} сообщени(й) · {hypotheses} гипотез(ы)",
  current: "текущий",
  "New project": "Новый проект",
  "Project name": "Название проекта",
  "What is the investigation trying to establish?": "Что должно установить расследование?",
  "Creating…": "Создание…",
  "Create project": "Создать проект",
  "The capture could not be imported. See the Security Center for the active limits.":
    "Не удалось импортировать захват. Активные лимиты смотрите в Центре безопасности.",
  "Selected capture": "Выбранный захват",
  "Import a PCAP or PCAPNG file to start. The original bytes are stored immutably and hashed.":
    "Импортируйте файл PCAP или PCAPNG. Исходные байты хранятся неизменно и хэшируются.",
  "Importing…": "Импорт…",
  "Import PCAP": "Импортировать PCAP",
  name: "имя",
  format: "формат",
  size: "размер",
  sha256: "sha256",
  imported: "импортирован",
  analysis: "анализ",
  "{count} TCP session(s) in this capture.": "{count} TCP-сессий в этом захвате.",
  "Import another capture": "Импортировать ещё захват",

  // ------------------------------------------------------------------------
  // Packet table, hex viewer, TCP state diagram
  // ------------------------------------------------------------------------
  "No packets match the current filters.": "Нет пакетов, соответствующих текущим фильтрам.",
  Time: "Время",
  Source: "Источник",
  Destination: "Назначение",
  Proto: "Прото",
  Flags: "Флаги",
  Len: "Длина",
  Payload: "Полезн.",
  State: "Состояние",
  "Packet #{index}": "Пакет №{index}",
  truncated: "обрезан",
  ok: "ок",
  "No bytes to display at this offset.": "Нет байтов для отображения по этому смещению.",
  "Copied offset shown in the toolbar": "Скопированное смещение показано на панели",
  "Select this row": "Выбрать эту строку",
  "Bytes missing from the capture": "Байты, потерянные при захвате",
  "offset {offset} (0x{hex})": "смещение {offset} (0x{hex})",
  "{changed} of {total} offsets differ": "отличается {changed} из {total} смещений",
  "only differing offsets": "только различающиеся смещения",
  Offset: "Смещение",
  "absent: this message is shorter than this offset (not zero)":
    "отсутствует: это сообщение короче данного смещения (не ноль)",
  "— absent —": "— отсутствует —",
  "differs / absent": "отличается / отсутствует",
  differs: "отличается",
  identical: "идентично",
  "No TCP packets were observed for this session, so there is no state diagram to draw.":
    "Для этой сессии TCP-пакеты не наблюдались, поэтому диаграмму состояния построить не из чего.",
  "Observed TCP state timeline": "Наблюдаемая временная шкала состояний TCP",
  "#{index} {time} {flags} seq={seq} ack={ack} win={win} payload={payload}":
    "#{index} {time} {flags} seq={seq} ack={ack} win={win} payload={payload}",
  "Packet #{index}: {reason}": "Пакет №{index}: {reason}",
  "time (s, capture order left → right)": "время (с, порядок захвата слева → справа)",
  retransmission: "повтор",
  "exact duplicate": "точный дубликат",
  "out of order": "нарушение порядка",
  "zero window": "нулевое окно",
  "SYN / SYN-ACK": "SYN / SYN-ACK",
  ACK: "ACK",
  DATA: "DATA",
  FIN: "FIN",
  RST: "RST",
  handshake: "рукопожатие",
  data: "данные",
  teardown: "закрытие",

  // ------------------------------------------------------------------------
  // Overview
  // ------------------------------------------------------------------------
  "Every number below is computed from the current project state. Nothing here is seeded, estimated or carried over from a demo dataset.":
    "Каждое число ниже вычислено по текущему состоянию проекта. Здесь нет заготовленных, оценённых или перенесённых из демо-набора данных.",
  "Start an investigation": "Начать расследование",
  "A project holds the imported captures, the reconstructed streams, the hypotheses you form and the evidence that supports or contradicts them. Create one, or open an existing one, then import a PCAP.":
    "Проект хранит импортированные захваты, пересобранные потоки, сформулированные гипотезы и доказательства, которые их подтверждают или опровергают. Создайте проект или откройте существующий, затем импортируйте PCAP.",
  "TCP sessions": "TCP-сессии",
  "5-tuple aware": "с учётом 5-кортежа",
  Streams: "Потоки",
  "both directions": "оба направления",
  Messages: "Сообщения",
  "depends on a framing rule": "зависит от правила кадрирования",
  "Bytes on disk": "Байтов на диске",
  Hypotheses: "Гипотезы",
  Interpretations: "Интерпретации",
  "executable rules": "исполняемые правила",
  "Validation runs": "Прогоны проверок",
  Counterexamples: "Контрпримеры",
  "messages that break a rule": "сообщения, нарушающие правило",
  "Problem sessions": "Проблемные сессии",
  "incomplete or conflicting": "неполные или конфликтующие",
  "Anomaly detection": "Поиск аномалий",
  available: "доступно",
  unavailable: "недоступно",
  "Source integrity": "Целостность источников",
  "all captures match their recorded hashes":
    "все захваты совпадают с записанными хэшами",
  "hash mismatch detected": "обнаружено несовпадение хэшей",
  "SHA-256 detects unintended modification when a trusted reference exists. It does not prove where a file came from and provides no confidentiality.":
    "SHA-256 обнаруживает непреднамеренное изменение при наличии доверенного эталона. Он не доказывает происхождение файла и не обеспечивает конфиденциальности.",
  "No integrity data": "Нет данных о целостности",
  "Analyzer versions in use": "Используемые версии анализаторов",
  "Run an analysis to record which analyzer version produced these results.":
    "Запустите анализ, чтобы зафиксировать версию анализатора, давшего эти результаты.",
  "Results are only reproducible with the same analyzer version and the same recorded options. Both are stored with every run.":
    "Результаты воспроизводимы только при той же версии анализатора и тех же записанных параметрах. И то и другое сохраняется при каждом прогоне.",
  "Research path": "Путь исследования",
  "Import a capture": "Импортировать захват",
  "Reconstruct the TCP session": "Пересобрать TCP-сессию",
  "Inspect the byte stream": "Изучить байтовый поток",
  "Frame messages and compare them": "Разметить сообщения и сравнить их",
  "Write an interpretation and validate it": "Написать интерпретацию и проверить её",
  "Export the investigation": "Экспортировать расследование",

  // ------------------------------------------------------------------------
  // Project settings (identity, protocols, AI consent, danger zone)
  // ------------------------------------------------------------------------
  "Project Settings apply to one project. Create or select a project first.":
    "Настройки проекта относятся к одному проекту. Сначала создайте или выберите проект.",
  "Go to Overview": "Перейти к обзору",
  "Identity, integrity and the per-project consent that governs optional external AI. Nothing here changes how packets are analysed.":
    "Идентификация, целостность и согласие проекта, управляющее необязательным внешним ИИ. Ничто здесь не меняет способ анализа пакетов.",
  Identity: "Идентификация",
  "Project saved.": "Проект сохранён.",
  Name: "Название",
  Description: "Описание",
  "Saving…": "Сохранение…",
  Save: "Сохранить",
  "id: {id}": "id: {id}",
  "schema v{version}": "схема v{version}",
  "updated {time}": "обновлено {time}",
  Protocols: "Протоколы",
  "Show all": "Показать все",
  "Detected protocol labels you have hidden. They are removed from the network graph and the stream list. Hiding changes what is shown, not what was analysed — the data stays available by showing the label again.":
    "Определённые метки протоколов, которые вы скрыли. Они убираются из графа сети и списка потоков. Скрытие меняет отображение, а не сам анализ — данные остаются доступны, если снова показать метку.",
  "No protocols hidden.": "Нет скрытых протоколов.",
  "Show this protocol again": "Снова показать этот протокол",
  "External AI": "Внешний ИИ",
  "server: {state}": "сервер: {state}",
  "external AI enabled": "внешний ИИ включён",
  "external AI disabled": "внешний ИИ выключен",
  "this project: consent {state}": "этот проект: согласие {state}",
  given: "дано",
  "not given": "не дано",
  "provider: {provider}": "провайдер: {provider}",
  "External AI is off by default. Report generation can only use a model when the server operator has enabled it and this project records consent. Even then the model only narrates already-validated findings; it never runs queries, reads files, or sees raw packet bytes or secrets.":
    "Внешний ИИ по умолчанию выключен. Генерация отчёта может использовать модель только когда оператор сервера включил её и для проекта зафиксировано согласие. Даже тогда модель лишь описывает уже проверенные выводы; она не выполняет запросы, не читает файлы и не видит сырые байты пакетов или секреты.",
  "Consent recorded for this project.": "Согласие для этого проекта зафиксировано.",
  "Consent withdrawn for this project.": "Согласие для этого проекта отозвано.",
  "Allow external AI for this project": "Разрешить внешний ИИ для этого проекта",
  "The server-level switch is off, so this consent alone cannot send anything anywhere. Set MPLAB_ALLOW_EXTERNAL_AI=true (and run a local Ollama) to make the consent effective.":
    "Серверный переключатель выключен, поэтому одного этого согласия недостаточно, чтобы что-то куда-то отправить. Установите MPLAB_ALLOW_EXTERNAL_AI=true (и запустите локальный Ollama), чтобы согласие заработало.",
  "Capture integrity": "Целостность захватов",
  "Re-verify": "Перепроверить",
  "hashes verified": "хэши подтверждены",
  "needs attention": "требует внимания",
  "No integrity result": "Нет результата проверки целостности",
  "Danger zone": "Опасная зона",
  "Deleting a project removes its captures, packets, sessions, hypotheses and reports from this workspace. This cannot be undone.":
    "Удаление проекта убирает его захваты, пакеты, сессии, гипотезы и отчёты из этого рабочего пространства. Действие необратимо.",
  "Delete project": "Удалить проект",
  "Delete project permanently?": "Удалить проект безвозвратно?",
  "Deleting…": "Удаление…",
  "Project deleted.": "Проект удалён.",

  // ------------------------------------------------------------------------
  // Project picker: deletion
  // ------------------------------------------------------------------------
  Delete: "Удалить",
  "Delete project?": "Удалить проект?",
  'Project "{name}" deleted.': "Проект «{name}» удалён.",
  'Project "{name}" created.': "Проект «{name}» создан.",

  // ------------------------------------------------------------------------
  // Network graph
  // ------------------------------------------------------------------------
  "Edges exist only where traffic was actually observed. Node size reflects observed volume; centrality is a triage aid, not an accusation.":
    "Рёбра существуют только там, где трафик действительно наблюдался. Размер узла отражает наблюдаемый объём; центральность — подспорье для отбора, а не обвинение.",
  "Min traffic": "Мин. трафик",
  bytes: "байт",
  "{shown} of {total} endpoints shown · {shownEdges} of {totalEdges} interactions":
    "показано {shown} из {total} узлов · {shownEdges} из {totalEdges} взаимодействий",
  "Clear filter": "Сбросить фильтр",
  "Show {count} hidden protocol(s)": "Показать скрытые протоколы: {count}",
  "Filtering hides endpoints below the threshold, and any interaction with them. It does not change the underlying analysis.":
    "Фильтрация скрывает узлы ниже порога и любые взаимодействия с ними. Она не меняет сам анализ.",
  "Interaction graph": "Граф взаимодействий",
  "Zoom out": "Уменьшить",
  "Zoom in": "Увеличить",
  reset: "сброс",
  "Network graph with {nodes} nodes and {edges} edges":
    "Граф сети: узлов {nodes}, рёбер {edges}",
  "nodes: {nodes} · edges: {edges} · {bytes} bytes observed":
    "узлов: {nodes} · рёбер: {edges} · наблюдается {bytes} байт",
  "{count} hub candidate(s)": "кандидатов в узлы-концентраторы: {count}",
  "clear selection": "снять выделение",
  "No analysed captures": "Нет проанализированных захватов",
  "Run an analysis on at least one capture to build the graph.":
    "Запустите анализ хотя бы одного захвата, чтобы построить граф.",
  "Node: {label}": "Узел: {label}",
  peers: "соседи",
  degree: "степень",
  betweenness: "посредничество",
  "not computed": "не вычислено",
  "hub candidate": "кандидат в концентраторы",
  "Observed connections": "Наблюдаемые связи",
  "{bytes} B": "{bytes} Б",
  "Centrality ranking": "Рейтинг центральности",
  "No centrality computed": "Центральность не вычислена",
  hub: "концентратор",
  "deg {value}": "степ. {value}",
  "betweenness n/a": "посредничество н/д",
  "betweenness {value}": "посредничество {value}",
  "Show this protocol": "Показать этот протокол",
  "Hide this protocol": "Скрыть этот протокол",

  // ------------------------------------------------------------------------
  // Stream explorer
  // ------------------------------------------------------------------------
  "The reconstructed byte stream, its coverage map and the packets that produced each byte. Missing ranges are shown as gaps and are never filled with zeros.":
    "Пересобранный байтовый поток, карта его покрытия и пакеты, породившие каждый байт. Пропущенные диапазоны показаны как разрывы и никогда не заполняются нулями.",
  "The Stream Explorer works on one reconstructed direction of one TCP session. Open TCP Sessions to choose the connection, or import and analyse a capture first.":
    "Explorer потоков работает с одним пересобранным направлением одной TCP-сессии. Откройте TCP-сессии, чтобы выбрать соединение, или сначала импортируйте и проанализируйте захват.",
  "No TCP session selected": "TCP-сессия не выбрана",
  "No stream selected": "Поток не выбран",
  "Go to TCP Sessions": "Перейти к TCP-сессиям",
  "{present}/{total} B": "{present}/{total} Б",
  "All streams are hidden by the protocol filter.":
    "Все потоки скрыты фильтром протоколов.",
  "protocol: {label} ({confidence})": "протокол: {label} ({confidence})",
  "← prev": "← назад",
  "offset {start} … {end}": "смещение {start} … {end}",
  "next →": "вперёд →",
  "Reconstructed bytes": "Пересобранные байты",
  "highlighting message {label}": "подсвечено сообщение {label}",
  "select a message below": "выберите сообщение ниже",
  "Coverage gaps": "Разрывы покрытия",
  "{start} … {end} ({length} bytes)": "{start} … {end} ({length} байт)",
  "These bytes were never captured. They are not recoverable from this file, and nothing in the analysis substitutes a guess for them.":
    "Эти байты никогда не были захвачены. Их нельзя восстановить из этого файла, и ничто в анализе не подменяет их догадкой.",
  "TLS fingerprints (JA3 / JA3S)": "Отпечатки TLS (JA3 / JA3S)",
  reliable: "надёжно",
  unreliable: "ненадёжно",
  "no hash computed": "хэш не вычислен",
  "sni: {value}": "sni: {value}",
  "alpn: {value}": "alpn: {value}",
  "groups: {value}": "группы: {value}",
  "Framing candidates for this stream": "Кандидаты кадрирования для этого потока",
  "score {value}": "оценка {value}",
  "Framing rule applied; messages regenerated.":
    "Правило кадрирования применено; сообщения перестроены.",
  "Apply and re-frame": "Применить и перекадрировать",
  "No candidates": "Нет кандидатов",
  "Framed messages": "Размеченные сообщения",
  Range: "Диапазон",
  Declared: "Заявл.",
  complete: "полное",
  partial: "частичное",
  "No messages framed": "Сообщения не размечены",
  "Apply a framing rule to split the byte stream into messages.":
    "Примените правило кадрирования, чтобы разбить байтовый поток на сообщения.",
  "Packets behind the current window": "Пакеты за текущим окном",
  Packet: "Пакет",
  "Stream offsets": "Смещения в потоке",
  "No packets in this window": "В этом окне нет пакетов",
  "Bytes with no packet behind them are holes.":
    "Байты, за которыми нет пакета, — это разрывы.",

  // ------------------------------------------------------------------------
  // Protocol labels shown in the graph legend
  // ------------------------------------------------------------------------
  "unknown (length-prefixed)": "неизвестно (с префиксом длины)",
  "unknown / binary": "неизвестно / бинарные",
  unknown: "неизвестно",

  // ------------------------------------------------------------------------
  // Anomaly detection: scoring against a baseline model
  // ------------------------------------------------------------------------
  "Score a capture against the baseline": "Оценить захват по базовой линии",
  Model: "Модель",
  "Select a model": "Выберите модель",
  "Report at most": "Показать не более",
  "Scoring…": "Оценка…",
  "Score captures": "Оценить захваты",
  "Captures to score": "Захваты для оценки",
  "Train a baseline first; the server refuses a capture that cannot supply every feature the model was trained on.":
    "Сначала обучите базовую линию: сервер откажет захвату, который не может дать каждый признак, на котором обучена модель.",
  "Scored result": "Результат оценки",
  "{count} entity(ies) reported · scope {scope}":
    "сообщено сущностей: {count} · scope {scope}",
  "Outlier score per entity": "Оценка выброса по сущностям",
  "Nothing scored": "Нечего оценивать",
  "No entity was reported for this scope.":
    "Для этого scope не сообщено ни одной сущности.",
  Entity: "Сущность",
  Score: "Оценка",
  "What pushed the score": "Что повысило оценку",
  // ------------------------------------------------------------------------
  // Assistant: narration provider
  // ------------------------------------------------------------------------
  "Narration endpoint: {provider}": "Эндпоинт для формулировок: {provider}",
  "External AI is allowed, but no endpoint is configured; narration stays off.":
    "Внешний ИИ разрешён, но эндпоинт не настроен — формулировки остаются выключены.",
  "allowed, endpoint not configured":
    "разрешён, эндпоинт не настроен",

  // ------------------------------------------------------------------------
  // Prose the API hands the UI verbatim. Keys are the English source strings
  // declared in backend/app/prose.py; backend/tests/test_prose_localization.py
  // fails when one is changed without its translation here.
  // ------------------------------------------------------------------------
  "Requests are compiled into a typed query plan, schema-validated, checked against a field/operator allowlist, and executed through a fixed analytics API. No SQL, shell command or Python is ever generated from user text or from model output.":
    "Запрос компилируется в типизированный план запроса, проверяется по схеме, сверяется с белым списком полей и операторов и выполняется через фиксированный аналитический API. Ни SQL, ни команда оболочки, ни код на Python не генерируются — ни из текста пользователя, ни из ответа модели.",
  "External AI is off by default. Even when enabled it may only narrate already-validated results; it cannot execute queries, write files, or alter the investigation. Report generation additionally requires per-project consent in Project Settings. A hosted endpoint receives only redacted, aggregated findings - never packet bytes, never a capture file, never a key log.":
    "Внешний ИИ по умолчанию выключен. Даже когда он включён, он лишь описывает уже проверенные результаты: не выполняет запросы, не пишет файлы и не меняет ход исследования. Для генерации отчёта дополнительно требуется согласие проекта в настройках проекта. Внешний эндпоинт получает только обезличенные сводные выводы — никогда байты пакетов, никогда файл захвата, никогда журнал ключей.",
  "Searches run against plaintext payloads only; encrypted TLS content is not scanned unless a matching key log was supplied and decryption ran.":
    "Поиск идёт только по открытому тексту; содержимое TLS не просматривается, если не был передан подходящий журнал ключей и не выполнялась расшифровка.",
  "Request/response pairing is inferred from ordering, not from a request identifier, unless the interpretation defines one.":
    "Сопоставление запроса и ответа выводится из порядка следования, а не из идентификатора запроса, если только интерпретация не задаёт такой идентификатор.",
  "A JWT that decodes is not a JWT that is authentic; signatures are not verified here.":
    "JWT, который декодируется, не обязательно является подлинным: подписи здесь не проверяются.",
  "scikit-learn is installed, so a corpus of 50 or more messages trains an Isolation Forest. A smaller corpus trains a robust per-feature profile instead, and the training summary says so.":
    "scikit-learn установлен, поэтому корпус из 50 и более сообщений обучает Isolation Forest. Корпус меньшего размера обучает устойчивый профиль по признакам, о чём сказано в итогах обучения.",
  "scikit-learn is not installed in this deployment, so every baseline is trained as a robust per-feature profile (median and MAD). Install the 'analytics' extra for the Isolation Forest.":
    "scikit-learn не установлен в этом развёртывании, поэтому любая базовая модель обучается как устойчивый профиль по признакам (медиана и MAD). Установите дополнение 'analytics', чтобы получить Isolation Forest.",
  "Scores are relative outlier measures within this baseline corpus. A higher score means 'less typical than the training data'. It is not a probability of compromise and carries no severity ranking.":
    "Оценки — относительная мера выброса внутри этого корпуса. Чем выше оценка, тем меньше сущности похожи на обучающие данные. Это не вероятность компрометации и не ранжирование по критичности.",
  "The score is a distance from the baseline profile, measured in robust units per feature and averaged. A higher score means 'further from what this corpus usually looks like'. It is not a probability of compromise, carries no severity ranking, and is only comparable within this one baseline.":
    "Оценка — расстояние до базового профиля в устойчивых единицах по каждому признаку, усреднённое по признакам. Чем выше оценка, тем дальше сущность от обычного вида этого корпуса. Это не вероятность компрометации, не ранжирование по критичности, и сравнивать оценки можно только внутри одной и той же базовой модели.",
  "This baseline was trained without scikit-learn, so it uses a robust per-feature profile (median and MAD) instead of an Isolation Forest. Install the 'analytics' extra to train the forest model instead.":
    "Эта базовая модель обучена без scikit-learn, поэтому используется устойчивый профиль по признакам (медиана и MAD) вместо Isolation Forest. Установите дополнение 'analytics', чтобы обучать лесную модель.",
  "Only {count} training samples were available. A stable baseline needs several hundred; treat these scores as noisy.":
    "Объём обучающей выборки мал: {count}. Для устойчивой базовой модели нужно несколько сотен; относитесь к этим оценкам как к шумным.",
  "Only {count} training samples were available. A stable baseline needs several hundred; treat these scores as noisy. :: one":
    "Доступен лишь {count} обучающий пример. Для устойчивой базовой модели нужно несколько сотен; относитесь к этим оценкам как к шумным.",
  "Only {count} training samples were available. A stable baseline needs several hundred; treat these scores as noisy. :: few":
    "Доступно лишь {count} обучающих примера. Для устойчивой базовой модели нужно несколько сотен; относитесь к этим оценкам как к шумным.",
  "Only {count} training samples were available. A stable baseline needs several hundred; treat these scores as noisy. :: many":
    "Доступно лишь {count} обучающих примеров. Для устойчивой базовой модели нужно несколько сотен; относитесь к этим оценкам как к шумным.",
  "Only {count} samples were available, and an Isolation Forest needs 50 before its scores mean anything, so a robust per-feature profile was trained instead. Treat these scores as noisy: add captures to the corpus and retrain for the forest.":
    "Объём выборки — {count}, а Isolation Forest требует 50, прежде чем его оценки что-то значат, поэтому вместо него обучен устойчивый профиль по признакам. Относитесь к этим оценкам как к шумным: добавьте захваты в корпус и переобучите модель для леса.",
  "Only {count} samples were available, and an Isolation Forest needs 50 before its scores mean anything, so a robust per-feature profile was trained instead. Treat these scores as noisy: add captures to the corpus and retrain for the forest. :: one":
    "Доступен лишь {count} пример, а Isolation Forest требует 50, прежде чем его оценки что-то значат, поэтому вместо него обучен устойчивый профиль по признакам. Относитесь к этим оценкам как к шумным: добавьте захваты в корпус и переобучите модель для леса.",
  "Only {count} samples were available, and an Isolation Forest needs 50 before its scores mean anything, so a robust per-feature profile was trained instead. Treat these scores as noisy: add captures to the corpus and retrain for the forest. :: few":
    "Доступно лишь {count} примера, а Isolation Forest требует 50, прежде чем его оценки что-то значат, поэтому вместо него обучен устойчивый профиль по признакам. Относитесь к этим оценкам как к шумным: добавьте захваты в корпус и переобучите модель для леса.",
  "Only {count} samples were available, and an Isolation Forest needs 50 before its scores mean anything, so a robust per-feature profile was trained instead. Treat these scores as noisy: add captures to the corpus and retrain for the forest. :: many":
    "Доступно лишь {count} примеров, а Isolation Forest требует 50, прежде чем его оценки что-то значат, поэтому вместо него обучен устойчивый профиль по признакам. Относитесь к этим оценкам как к шумным: добавьте захваты в корпус и переобучите модель для леса.",
  "These features were constant across the baseline corpus and carry no information: {features}.":
    "Эти признаки были постоянными по всему корпусу базовой модели и не несут информации: {features}.",

  // ------------------------------------------------------------------------
  // Investigation Assistant: what it says when it refuses, and why.
  // ------------------------------------------------------------------------
  "Interpreted as: on {body}.": "Истолковано как: {body}.",
  "leading {width} byte(s) are equal across messages":
    "начальные {width} байт(ов) совпадают во всех сообщениях",
  "messages where a response followed a request within {seconds}s":
    "сообщения, где ответ пришёл на запрос быстрее чем за {seconds} с",
  "The assistant refused to guess. Narrow the request to one of the supported patterns, or use the structured query API directly.":
    "Ассистент отказался угадывать. Сузьте запрос до одного из поддерживаемых шаблонов или используйте структурированный API запросов.",
  "Dry run: the plan was compiled and validated but not executed.":
    "Пробный запуск: план запроса скомпилирован и проверен, но не выполнен.",
  "This was a dry run, so nothing was executed and there are no results to describe. Untick the dry run and ask again for an answer about the traffic.":
    "Это был пробный запуск: ничего не выполнялось, поэтому описывать нечего. Снимите галочку пробного запуска и повторите вопрос — тогда будет ответ о трафике.",
  "External AI is disabled. Set MPLAB_ALLOW_EXTERNAL_AI=true and point MPLAB_LLM_BASE_URL / MPLAB_LLM_API_KEY / MPLAB_LLM_MODEL at an endpoint (or run a local Ollama) to permit an optional narration pass.":
    "Внешний ИИ выключен. Задайте MPLAB_ALLOW_EXTERNAL_AI=true и укажите эндпоинт в MPLAB_LLM_BASE_URL / MPLAB_LLM_API_KEY / MPLAB_LLM_MODEL (либо запустите локальный Ollama), чтобы разрешить необязательный проход с формулировками.",
  "The request is empty.": "Запрос пуст.",
  "The request could not be mapped to a supported query. Supported patterns include size comparisons ('responses longer than 1000 bytes'), leading-byte equality, request/response timing, and entropy thresholds.":
    "Запрос не удалось сопоставить ни с одним поддерживаемым. Поддерживаются: сравнение по размеру («ответы длиннее 1000 байт»), равенство начальных байтов, тайминг запроса и ответа, пороги энтропии.",
  "The query plan was rejected:": "План запроса отклонён:",
  "Only 1 to 8 leading bytes can be compared; a wider comparison needs a rule the assistant does not have.":
    "Сравнивать можно от 1 до 8 начальных байт; для более широкого сравнения нужен правило, которого у ассистента нет.",
  "This groups messages that share a leading byte pattern; it does not assert that those bytes mean the same thing.":
    "Это группирует сообщения с одинаковым шаблоном начальных байт; оно не утверждает, что эти байты означают одно и то же.",
  "Request/response pairing is inferred from ordering and direction only; no request identifier is checked.":
    "Сопоставление запроса и ответа выводится только из порядка и направления; идентификатор запроса не проверяется.",
  "Decoding a JWT proves nothing about authenticity. The signature was not verified and the token must be treated as untrusted input.":
    "Декодирование JWT ничего не говорит о подлинности. Подпись не проверялась, токен следует считать недоверенным вводом.",
  "A POST search only works when HTTP content is visible. It cannot find requests inside TLS unless the session was decrypted.":
    "Поиск POST работает только когда содержимое HTTP видно. Запросы внутри TLS он не найдёт, если сессия не была расшифрована.",
  "JWT search runs only over plaintext payloads. Encrypted TLS payloads are never scanned for tokens.":
    "Поиск JWT идёт только по открытому тексту. Содержимое TLS никогда не сканируется на токены.",
  "Rate analysis is available through the Anomaly Detection module; it needs a trained baseline rather than a single-pass filter.":
    "Анализ частот доступен в модуле обнаружения аномалий: ему нужна обученная базовая модель, а не одноразовый фильтр.",
  "The value does not have a JWT structure.": "Значение не имеет структуры JWT.",
  "The query is too long (limit 1000 characters).": "Запрос слишком длинный (предел 1000 символов).",
  "This paragraph was generated by a language model from the facts above. It is narration, not evidence: verify every statement against the packets, bytes and validation results it refers to.":
    "Этот абзац сгенерирован языковой моделью по приведённым выше фактам. Это формулировка, а не доказательство: проверьте каждое утверждение по пакетам, байтам и результатам проверок, на которые оно ссылается.",
  "Model-generated narration. The counterexamples and validation results above are the evidence; this text only summarises them.":
    "Формулировка, сгенерированная моделью. Доказательствами являются приведённые выше контрпримеры и результаты проверок; этот текст лишь их обобщает.",
  "A counterexample shows where the rule did not hold on this corpus. It does not by itself prove the rule is wrong; a gap in the capture is an equally valid explanation until ruled out.":
    "Контрпример показывает, где правило на этом корпусе не сработало. Сам по себе он не доказывает, что правило неверно: пробел в захвате — столь же допустимое объяснение, пока оно не исключено.",
  "This timeline shows events observed in the capture. It does not prove the internal state of either TCP stack, and packets absent from the capture are simply unknown.":
    "Эта лента показывает события, наблюдавшиеся в захвате. Она не доказывает внутреннее состояние ни одной из стеков TCP, а пакеты, отсутствующие в захвате, просто неизвестны.",
  "These are candidates scored from observed bytes, not conclusions. Apply one and validate it against a corpus before treating it as the protocol's framing.":
    "Это кандидаты, оценённые по наблюдавшимся байтам, а не выводы. Примените один и проверьте его на корпусе, прежде чем считать это фреймингом протокола.",
  "An Isolation Forest needs {required} samples; this corpus has {count}, so the robust profile was used.":
    "Isolation Forest требует {required} примеров, а в этом корпусе их {count}, поэтому использован устойчивый профиль.",
  "scikit-learn is not installed in this deployment, so the robust profile is used.":
    "scikit-learn не установлен в этом развёртывании, поэтому используется устойчивый профиль.",
  "corpus too small": "корпус слишком мал",
  // What the specification format can and cannot express.
  "bit-level fields (use a whole-byte field and mask it manually)":
    "битовые поля (берите поле целым байтом и накладывайте маску вручную)",
  "computed or derived fields (no expression language is evaluated)":
    "вычисляемые и производные поля (язык выражений не вычисляется)",
  "variable-length numeric fields other than through a repeat group":
    "числовые поля переменной длины, кроме как через повторяющуюся группу",
  "checksum verification (no checksum algorithm is assumed or computed)":
    "проверка контрольных сумм (алгоритм не предполагается и не вычисляется)",
  "conditional framing (framing is fixed per specification)":
    "условное кадрирование (кадрирование фиксировано спецификацией)",
  "Specifications are interpreted as data. No code from a specification is ever imported, compiled or executed.":
    "Спецификации интерпретируются как данные. Код из спецификации никогда не импортируется, не компилируется и не выполняется.",
  "A dry run executes nothing, so there is nothing for the model to describe. Untick the dry run for an answer.":
    "Пробный запуск ничего не выполняет, поэтому модели нечего описывать. Снимите галочку пробного запуска, чтобы получить ответ.",
  "{available} of {required} {scope}": "{available} из {required} {scope}",
  "{available} of {required} messages": "{available} из {required} сообщений",
  "{available} of {required} sessions": "{available} из {required} сессий",
  "A baseline learns what this corpus usually looks like, so it needs enough of it to have a 'usually'. This one does not, and a model trained on it would rank noise.":
    "Базовая модель учится тому, как этот корпус обычно выглядит, поэтому его должно хватать, чтобы было «обычно». Здесь не хватает, а модель на таком корпусе ранжировала бы шум.",
  "Messages only exist where a framing rule has been applied. A capture without one contributes none - check the capture's analysis, or derive a rule in the Protocol Bench.":
    "Сообщения существуют только там, где применено правило фрейминга. Захват без правила не даёт ни одного — проверьте анализ захвата или выведите правило в «Верстаке протокола».",
  "Add captures to the corpus: more captures of the same protocol is the direct fix.":
    "Добавьте захваты в корпус: больше захватов того же протокола — прямое решение.",
  "A corpus of at least {required} would train the robust profile, and {count} would train the Isolation Forest instead.":
    "Корпус не меньше {required} сообщений обучит устойчивый профиль, а не меньше {count} — Isolation Forest.",
  "Open the Protocol Bench": "Открыть «Верстак протокола»",
  "Open the captures": "Открыть захваты",
  "Detector": "Детектор",
  "samples": "примеров",
  "Isolation Forest": "Isolation Forest",
  "robust profile": "устойчивый профиль",
  "raw model JSON": "исходный JSON модели",

  "drag to pan · wheel or ± to zoom · reset fits the view · select a node on the canvas or from the centrality list":
    "перетаскивание — панорама · колесо или ± — зум · «сброс» вписывает граф · узел выбирается на холсте или в рейтинге центральности",

  Stream: "Поток",
  "mean {value}": "среднее {value}",
  "message {index}": "сообщение {index}",

  // ------------------------------------------------------------------------
  // TLS decryption: key logs and record opening
  // ------------------------------------------------------------------------
  "TLS key log": "Ключевой журнал TLS",
  "Upload the key log (SSLKEYLOGFILE) of one side of the conversation to decrypt its application records. The file is hashed, stored with owner-only permissions and never returned by the API; nothing here derives keys from observed traffic.":
    "Загрузите ключевой журнал (SSLKEYLOGFILE) одной стороны диалога, чтобы расшифровать её прикладные записи. Файл хэшируется, хранится с правами только для владельца и никогда не возвращается API; здесь не выводится ни одного ключа из наблюдённого трафика.",
  "Upload key log": "Загрузить ключевой журнал",
  "Uploading…": "Загрузка…",
  "No key log uploaded yet.": "Ключевой журнал ещё не загружен.",
  "Decrypt a stream": "Расшифровать поток",
  "Decryption is only possible for the direction the key log belongs to, and only for cipher suites this build implements (TLS 1.2 AES-CBC/GCM, TLS 1.3 AES-GCM and ChaCha20-Poly1305). Everything else is reported as unsupported, never approximated.":
    "Расшифровка возможна только для того направления, которому принадлежит ключевой журнал, и только для наборов шифров, реализованных в этой сборке (TLS 1.2 AES-CBC/GCM, TLS 1.3 AES-GCM и ChaCha20-Poly1305). Всё остальное сообщается как неподдерживаемое и никогда не аппроксимируется.",
  "Select a key log": "Выберите ключевой журнал",
  Decrypt: "Расшифровать",
  "Decrypting…": "Расшифровка…",
  "Select a stream": "Выберите поток",
  "Key log": "Ключевой журнал",
  "No application records were found in this direction.":
    "В этом направлении не найдено прикладных записей.",
  "{bytes} byte(s) decrypted": "расшифровано байт: {bytes}",
  "{status}: {count}": "{status}: {count}",
  "#": "№",
  Record: "Запись",
  Plaintext: "Открытый текст",
  Detail: "Подробность",
  // ------------------------------------------------------------------------
  // Page fragments (see lib/i18n/locales/*)
  // ------------------------------------------------------------------------
  ...RU_PAGES_A,
  ...RU_PAGES_B,
  ...RU_PAGES_C,
};