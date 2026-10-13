import type { TranslationFragment } from "@/lib/i18n/locales/types";

/**
 * Russian translations for the protocol-research pages:
 * Protocol Workbench, Hypotheses & Rules and Capture Diff.
 */
export const RU_PAGES_B: TranslationFragment = {
  // --------------------------------------------------------------------------
  // Protocol Workbench
  // --------------------------------------------------------------------------
  "No capture selected": "Захват не выбран",
  "The Protocol Workbench compares framed messages from a reconstructed stream. Select an analysed capture and a session, then apply a framing rule to the stream.":
    "Верстак протокола сравнивает размеченные сообщения из пересобранного потока. Выберите проанализированный захват и сессию, затем примените правило кадрирования к потоку.",
  "Go to Captures": "Перейти к захватам",
  "Protocol Workbench": "Верстак протокола",
  "Compare binary messages side by side, read the per-offset statistics and see which field candidates the data actually supports.":
    "Сравнивайте двоичные сообщения рядом, читайте статистику по смещениям и смотрите, каких кандидатов полей данные действительно поддерживают.",
  "one stream per direction": "один поток на направление",
  "Messages (select 2–6 to compare)": "Сообщения (выберите 2–6 для сравнения)",
  clear: "Очистить",
  "No framed messages": "Нет размеченных сообщений",
  "Choose a framing rule on the Stream Explorer first.":
    "Сначала выберите правило кадрирования в Потоках.",
  Range: "Диапазон",
  Len: "Длина",
  Entropy: "Энтропия",
  Unique: "Уникальные",
  State: "Состояние",
  complete: "полное",
  partial: "частичное",
  "Per-offset alignment": "Сопоставление по смещениям",
  "Select at least two messages": "Выберите не менее двух сообщений",
  "Alignment is positional: a byte at offset N in one message is compared with offset N in another. Where a message is shorter, the position is shown as absent, never as zero.":
    "Сопоставление позиционное: байт по смещению N в одном сообщении сравнивается со смещением N в другом. Там, где сообщение короче, позиция показана как отсутствующая, а не как ноль.",
  "No comparison": "Нет сравнения",
  "Field candidates inferred from the bytes": "Кандидаты полей, выведенные из байтов",
  "No candidates": "Нет кандидатов",
  "Insufficient messages or no structure detected yet.":
    "Недостаточно сообщений или структура пока не обнаружена.",
  "supports {supports} · contradicts {contradicts}":
    "подтверждений {supports} · противоречий {contradicts}",
  "These are hypotheses generated from observed bytes. A candidate name is a label, not a claim: nothing here proves what a field":
    "Это гипотезы, выведенные из наблюдаемых байтов. Имя кандидата — это метка, а не утверждение: ничто здесь не доказывает, что поле",
  means: "означает",
  "Column statistics": "Статистика столбцов",
  "No statistics": "Нет статистики",
  "Byte class per offset": "Класс байта по смещению",
  "offset {offset}: {label}": "смещение {offset}: {label}",
  Offset: "Смещение",
  Class: "Класс",
  Present: "Присутствует",
  Absent: "Отсутствует",
  "Change rate": "Частота изменений",
  "Most common": "Самые частые",
  "A position that is absent from some messages is counted as absent. Missing bytes are never filled with zero, and a field that only exists in some messages is reported as such.":
    "Позиция, отсутствующая в части сообщений, считается отсутствующей. Пропущенные байты никогда не заполняются нулём, а поле, существующее лишь в части сообщений, так и указывается.",

  // Column classes (labels and descriptions rendered via column-classes.ts)
  constant: "постоянный",
  counter: "счётчик",
  enum: "перечисление",
  "high entropy": "высокая энтропия",
  variable: "переменный",
  absent: "отсутствует",
  unknown: "неизвестно",
  "The same byte in every message that reaches this offset.":
    "Один и тот же байт в каждом сообщении, доходящем до этого смещения.",
  "Rises across consecutive messages; a counter or running id.":
    "Растёт от сообщения к сообщению; счётчик или возрастающий идентификатор.",
  "A small set of values; a type or status code.":
    "Небольшой набор значений; тип или код состояния.",
  "Near-uniform and always changing: random, compressed, encrypted or a checksum — indistinguishable here.":
    "Почти равномерно и постоянно меняется: случайные данные, сжатие, шифрование или контрольная сумма — здесь неразличимы.",
  "Changes, but no stronger reading is supported.":
    "Меняется, но более сильная интерпретация не подтверждается.",
  "Never present in the corpus.": "Никогда не присутствует в корпусе.",
  "Not classified.": "Не классифицировано.",

  // --------------------------------------------------------------------------
  // Hypotheses & Rules
  // --------------------------------------------------------------------------
  "The specification must be a JSON object.":
    "Спецификация должна быть объектом JSON.",
  "Invalid JSON.": "Некорректный JSON.",
  "Interpretation created.": "Интерпретация создана.",
  "Interpretation updated. Previous validation runs are now marked stale.":
    "Интерпретация обновлена. Предыдущие прогоны проверки теперь помечены как устаревшие.",
  "Select at least one capture to validate against. A rule tested on no data proves nothing.":
    "Выберите хотя бы один захват для проверки. Правило, проверенное на пустых данных, ничего не доказывает.",
  "No project selected": "Проект не выбран",
  "Open a project on the Overview page first.":
    "Сначала откройте проект на странице обзора.",
  "Hypotheses & Rules": "Гипотезы и правила",
  "Write an executable interpretation, run it against a corpus and read the counterexamples. A rule that survives every message in this corpus is":
    "Напишите исполняемую интерпретацию, запустите её на корпусе и прочитайте контрпримеры. Правило, которое выдерживает каждое сообщение в этом корпусе,",
  "supported by observed data": "подтверждается наблюдаемыми данными",
  "— not proven universally.": "— но не доказано универсально.",
  Hypotheses: "Гипотезы",
  new: "Новый",
  "Hypothesis name": "Название гипотезы",
  "No hypotheses yet": "Гипотез пока нет",
  "A hypothesis records what you believe the protocol looks like and why.":
    "Гипотеза фиксирует, как, по вашему мнению, выглядит протокол, и почему.",
  "Status of {name}": "Статус: {name}",
  "Hypothesis updated.": "Гипотеза обновлена.",
  draft: "черновик",
  proposed: "предложена",
  testing: "проверяется",
  supported: "подтверждена",
  contradicted: "опровергнута",
  revised: "пересмотрена",
  rejected: "отклонена",
  Interpretations: "Интерпретации",
  "No rules yet": "Правил пока нет",
  "Write a specification on the right and create it.":
    "Напишите спецификацию справа и создайте её.",
  "Interpretation specification (JSON)": "Спецификация интерпретации (JSON)",
  reset: "сброс",
  create: "Создать",
  save: "Сохранить",
  "Interpretation specification": "Спецификация интерпретации",
  "Valid JSON. The backend validates the schema again on save.":
    "Корректный JSON. Backend повторно проверяет схему при сохранении.",
  "Validate against a corpus": "Проверить на корпусе",
  "Validating…": "Проверка…",
  "Run validation": "Запустить проверку",
  "verdict: {verdict}": "вердикт: {verdict}",
  total: "всего",
  matched: "совпало",
  failed: "не прошло",
  unparsed: "не разобрано",
  "Validation run": "Прогон проверки",
  run: "прогон",
  rule: "правило",
  "rule version": "версия правила",
  checksum: "контрольная сумма",
  status: "статус",
  analyzer: "анализатор",
  "Re-run the validation before citing these results.":
    "Перед ссылкой на эти результаты повторно запустите проверку.",
  Counterexamples: "Контрпримеры",
  "{count} message(s) broke the rule": "{count} сообщени(й) нарушили правило",
  "msg {id}": "сообщ. {id}",
  "offsets {start}…{end}": "смещения {start}…{end}",
  "alternative explanations ({count})": "альтернативные объяснения ({count})",
  "No counterexamples": "Контрпримеров нет",
  "Every message in this corpus satisfied the rule.":
    "Каждое сообщение в этом корпусе удовлетворяет правилу.",
  "Run a validation to see counterexamples":
    "Запустите проверку, чтобы увидеть контрпримеры",
  "What the format can express": "Что может выразить формат",
  "framing:": "кадрирование:",
  "field kinds:": "виды полей:",
  "explicitly unsupported:": "явно не поддерживается:",
  "Corpus (captures to validate against)": "Корпус (захваты для проверки)",
  "Import captures before validating a rule. A rule tested on no data proves nothing.":
    "Импортируйте захваты, прежде чем проверять правило. Правило, проверенное на пустых данных, ничего не доказывает.",
  analysed: "проанализирован",
  "not analysed": "не проанализирован",
  "clear corpus": "Очистить корпус",

  // --------------------------------------------------------------------------
  // Capture Diff
  // --------------------------------------------------------------------------
  "Capture Diff": "Сравнение захватов",
  "Sessions are matched on endpoints, direction, sizes and message-length shape — not on packet numbers, which stop corresponding as soon as behaviour changes.":
    "Сессии сопоставляются по узлам, направлению, размерам и форме длин сообщений — а не по номерам пакетов, которые перестают соответствовать друг другу, как только поведение меняется.",
  "Comparison setup": "Настройка сравнения",
  Baseline: "Базовая линия",
  "Compare with": "Сравнить с",
  Focus: "Фокус",
  "select a capture": "выберите захват",
  all: "всё",
  endpoints: "узлы",
  sessions: "сессии",
  messages: "сообщения",
  bytes: "байт",
  diagnostics: "диагностика",
  ready: "готово",
  "choose two different captures": "выберите два разных захвата",
  "Select a baseline and a comparison capture":
    "Выберите базовый захват и захват для сравнения",
  "The result is a heat map of differences. A difference is not an anomaly: it only means this recording differs from that one.":
    "Результат — тепловая карта различий. Различие — это не аномалия: оно лишь означает, что эта запись отличается от той.",
  "Session heat map": "Тепловая карта сессий",
  similarity: "сходство",
  "Δ shade = magnitude · blue growth · amber shrink · empty = no change":
    "Оттенок Δ = величина · синий — рост · янтарный — спад · пусто — без изменений",
  Status: "Статус",
  Endpoints: "Узлы",
  Similarity: "Сходство",
  "Byte Δ": "Δ байтов",
  "Packet Δ": "Δ пакетов",
  Why: "Причина",
  "Open baseline session": "Открыть базовую сессию",
  "no baseline session": "нет базовой сессии",
  "Open comparison session": "Открыть сессию сравнения",
  "no comparison session": "нет сессии сравнения",
  added: "добавлены",
  removed: "удалены",
  common: "общие",
  none: "нет",
  "Message-level differences": "Различия на уровне сообщений",
  Dir: "Напр.",
  "Base len": "Длина базовой",
  "Compare len": "Длина сравн.",
  "Bytes changed": "Изменено байтов",
};
