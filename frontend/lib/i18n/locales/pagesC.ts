import type { TranslationFragment } from "@/lib/i18n/locales/types";

/**
 * Russian translations for the analysis-and-reporting pages:
 * Anomaly Detection, Investigation Assistant, Reports and Security Center.
 */
export const RU_PAGES_C: TranslationFragment = {
  // ------------------------------------------------------------------------
  // Anomaly Detection
  // ------------------------------------------------------------------------
  "No project selected": "Проект не выбран",
  "Anomaly Detection": "Поиск аномалий",
  "Isolation Forest over a baseline corpus. Scores rank how unusual an entity is relative to that corpus; they are not probabilities and carry no severity.":
    "Изолирующий лес по базовому корпусу. Оценки показывают, насколько необычна сущность относительно этого корпуса; это не вероятности, и они не несут информации о серьёзности.",
  Unavailable: "Недоступно",
  "scikit-learn is not installed": "scikit-learn не установлен",
  "The product is fully usable without this module. Nothing else degrades when anomaly detection is unavailable.":
    "Продукт полностью работоспособен и без этого модуля. Ничто другое не ухудшается, когда поиск аномалий недоступен.",
  "Train a baseline": "Обучение базовой линии",
  "Latest model": "Последняя модель",
  "Model name": "Название модели",
  Scope: "Область",
  messages: "сообщения",
  sessions: "сессии",
  "Training…": "Обучение…",
  "Train baseline": "Обучить базовую линию",
  "Baseline corpus": "Базовый корпус",
  "Baseline model": "Базовая модель",

  // ------------------------------------------------------------------------
  // Investigation Assistant
  // ------------------------------------------------------------------------
  "Investigation Assistant": "Помощник расследования",
  "Your question is compiled into a typed query plan, validated against a field allowlist, and executed through a fixed analytics API. No SQL, shell command or Python is ever generated from text — yours or a model's.":
    "Ваш вопрос компилируется в типизированный план запроса, проверяется по списку разрешённых полей и выполняется через фиксированный аналитический API. Из текста — вашего или модели — никогда не создаётся SQL, команда оболочки или Python.",
  "Ask about the traffic": "Спросите о трафике",
  "Search request": "Поисковый запрос",
  "dry run (show the plan without executing)": "пробный запуск (показать план без выполнения)",
  "allow optional local model narration": "разрешить необязательное описание локальной моделью",
  "Working…": "Выполняется…",
  Run: "Запустить",
  "No result yet": "Результата пока нет",
  "Start with a dry run: you will see exactly how the request was interpreted before anything is executed.":
    "Начните с пробного запуска: вы увидите, как именно был истолкован запрос, прежде чем что-либо выполнится.",
  Corpus: "Корпус",
  "No captures imported; the search will cover the whole index.":
    "Захваты не импортированы; поиск охватит весь индекс.",
  "What this can and cannot do": "Что это умеет и чего не умеет",
  "queryable entities:": "сущности для запросов:",
  "external AI:": "внешний ИИ:",
  "Try one of these": "Попробуйте один из примеров",
  "Find all TCP responses longer than 1000 bytes":
    "Найти все TCP-ответы длиннее 1000 байт",
  "Show messages whose first two bytes match":
    "Показать сообщения, у которых совпадают первые два байта",
  "Find requests answered within 100 milliseconds":
    "Найти запросы, отвеченные в течение 100 миллисекунд",
  "Show streams with holes in the reconstructed bytes":
    "Показать потоки с разрывами в пересобранных байтах",
  "Find POST requests where HTTP content is visible":
    "Найти POST-запросы, в которых видно содержимое HTTP",
  "The assistant refused to guess": "Помощник отказался угадывать",
  "needs clarification": "требует уточнения",
  Result: "Результат",
  executed: "выполнено",
  "planned (dry run)": "запланировано (пробный запуск)",
  "Compiled query plan": "Скомпилированный план запроса",
  "{count} matching {entity}": "{count} совпадений: {entity}",
  records: "записи",
  id: "id",
  stream: "поток",
  direction: "направление",
  range: "диапазон",
  length: "длина",
  entropy: "энтропия",
  "model narration": "описание от модели",
  "Model-generated narration, not evidence.":
    "Текст, сгенерированный моделью, а не доказательство.",

  // ------------------------------------------------------------------------
  // Reports
  // ------------------------------------------------------------------------
  Reports: "Отчёты",
  "Every section is assembled from stored facts and lists the evidence it came from. A report can be produced entirely offline, without any language model.":
    "Каждый раздел собирается из сохранённых фактов и перечисляет доказательства, на которых он основан. Отчёт можно сформировать полностью офлайн, без какой-либо языковой модели.",
  "narrate with local model": "описать локальной моделью",
  "Investigation report": "Отчёт о расследовании",
  "Generating…": "Создание…",
  "Generate report": "Создать отчёт",
  "Server switch is on; the report will still be produced if the model cannot narrate in time.":
    "Серверный переключатель включён; отчёт всё равно будет создан, даже если модель не успеет его описать.",
  "External AI is disabled on this server, so the checkbox has no effect.":
    "Внешний ИИ отключён на этом сервере, поэтому флажок ни на что не влияет.",
  "Generated reports": "Созданные отчёты",
  "No reports yet": "Отчётов пока нет",
  "AI used": "использован ИИ",
  Report: "Отчёт",
  Markdown: "Markdown",
  JSON: "JSON",
  "No report selected": "Отчёт не выбран",
  "Generate a report to see the investigation written out with its evidence.":
    "Создайте отчёт, чтобы увидеть расследование, изложенное вместе с доказательствами.",
  "generator: {generator} · created {created}":
    "генератор: {generator} · создано {created}",
  "a language model contributed to this report":
    "в подготовке этого отчёта участвовала языковая модель",
  "evidence:": "доказательства:",
  "open {label} {id}": "открыть {label} {id}",

  // ------------------------------------------------------------------------
  // Security Center
  // ------------------------------------------------------------------------
  "Security Center": "Центр безопасности",
  "Real local checks with honest verdicts. A check that could not be performed says so; nothing here is a penetration test or a certification.":
    "Реальные локальные проверки с честными вердиктами. Если проверку нельзя было выполнить, это прямо указано; ничто здесь не является тестом на проникновение или сертификацией.",
  "Checking…": "Проверка…",
  "Run configuration check": "Запустить проверку конфигурации",
  "Configuration checks": "Проверки конфигурации",
  "Audit log": "Журнал аудита",
  "No checks available": "Проверки недоступны",
  Runtime: "Среда выполнения",
  mode: "режим",
  bind: "привязка",
  platform: "платформа",
  Checks: "Проверки",
  Integrations: "Интеграции",
  "Documented limits": "Документированные ограничения",
  "Audit chain integrity": "Целостность цепочки аудита",
  "chain verified": "цепочка подтверждена",
  "chain broken": "цепочка нарушена",
  "Security events": "События безопасности",
  Time: "Время",
  Action: "Действие",
  Outcome: "Результат",
  Risk: "Риск",
  Object: "Объект",
  "No audit events": "Событий аудита нет",
};
