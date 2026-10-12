# Примеры (§31 п.9–14)

Эти файлы порождены `scripts/build_examples.py` на реальном наборе
`sample_protocol/` (Термостенд). Их можно открыть в приложении и повторить путь
исследователя целиком.

| Файл | Что это | Как открыть |
| --- | --- | --- |
| `thermostand.mplab` | Портируемый архив проекта | `POST /api/projects/import` (или «Import project» в UI) |
| `thermostand_spec.json` | Принятая спецификация, как её экспортирует приложение (с контрольной суммой) | создать интерпретацию из этого JSON |
| `thermostand_rejected_spec.json` | Правдоподобный, но неверный вариант правила | создать интерпретацию и запустить проверку |
| `thermostand_counterexamples.json` | Контрпримеры, которые неверное правило породило на корпусе | открыть по `run_id` из файла |
| `thermostand_application.json` | Применение принятого правила к записи, которой оно не видело | `POST /api/interpreters/{id}/validate` |
| `thermostand_report.md` | Итоговый отчёт (Markdown) | открыть текстом или через `/api/reports/{id}/markdown` |
| `thermostand_report.json` | Тот же отчёт в JSON | `/api/reports/{id}/json` |

## Что было выведено из байтов

Обрамление предложено приложением, а не задано заранее:

- `length_offset = 2`
- `length_size = 2`
- `endianness = big`
- `includes_header = false`
- `header_size = 8`

Коды операций на проводе:

| Байт 7 | Имя (гипотеза) |
| --- | --- |
| `0x10` | `read_config` |
| `0x20` | `set_config` |
| `0x30` | `read_values` |

Имена соотнесены с `action_journal.csv`: девять запросов сессии `s1` идут как
`read-config`, `set-config`, `read-values`, … а опкоды на проводе повторяют этот
ритм (0x10, 0x20, 0x30). Это **гипотеза**, отмеченная в спецификации как
`semantic_status: hypothesis`.

## Проверка на корпусе

- Неверное правило (`includes_header: true`): вердикт `contradicted`,
  провалов `28`, контрпримеров `28`.
- Исправленное правило: вердикт `consistent_with_corpus`, совпало
  `28`, провалов `0`.
- Применение к новой записи: вердикт `consistent_with_corpus`, совпало
  `16`, провалов `0`.

Контрольная сумма принятой спецификации: `7a47b2acca1f79c8f38a87c04840176b94784ac827fc9e46b5fcce7604c07606`.
Архив `Thermostand-example.mplab`. Отчёт `3302012f762b41f5b7bf4d424e8e5963`.

> «Согласуется с корпусом» — утверждение об этом корпусе, а не доказательство
> универсальной корректности. Так это и записано в отчёте.
