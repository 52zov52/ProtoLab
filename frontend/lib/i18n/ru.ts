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
  "drag to pan · wheel or ± to zoom · double-click to reset":
    "перетаскивание — сдвиг · колесо или ± — масштаб · двойной щелчок — сброс",
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
  Stream: "Поток",
  "mean {value}": "среднее {value}",
  "message {index}": "сообщение {index}",

  // ------------------------------------------------------------------------
  // Page fragments (see lib/i18n/locales/*)
  // ------------------------------------------------------------------------
  ...RU_PAGES_A,
  ...RU_PAGES_B,
  ...RU_PAGES_C,
};
