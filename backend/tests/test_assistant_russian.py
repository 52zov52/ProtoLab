"""The assistant must understand the language the analyst writes in.

The audience is Russian-speaking, so an English-only vocabulary meant every
request in their own language came back as "could not be mapped to a supported
query" - a feature that looks broken to exactly the people most likely to use
it. The narration was translated while the *question* was not, which is the
strangest possible combination.

Two real bugs came out of writing these cases, both of which would have been
invisible while only English was tested:

* "не больше 64" contains "больше", so checking the strict pattern first turned
  "no more than" into a strict greater-than.
* "выше 7" was absent while "свыше 7" was present.
"""

from __future__ import annotations

import pytest

from app.reporting.assistant import CompileError, compile_query


def compiled(text: str):
    plan = compile_query(text).plan
    return plan.entity, [(f.field, f.operator, f.value) for f in plan.filters]


# (question, entity, field, operator, value)
RUSSIAN_CASES = [
    ("Найди ответы TCP длиннее 1000 байт", "messages", "payload_length", "greater_than", 1000),
    ("Покажи сообщения с энтропией выше 7", "messages", "entropy", "greater_than", 7),
    ("Найди неполные сообщения короче 100 байт", "messages", "payload_length", "less_than", 100),
    ("Какие пакеты больше 1500 байт", "packets", "payload_length", "greater_than", 1500),
    ("Покажи запросы больше 2 кб", "messages", "payload_length", "greater_than", 2048),
    ("сообщения не больше 64 байт", "messages", "payload_length", "less_or_equal", 64),
    ("сообщения не меньше 64 байт", "messages", "payload_length", "greater_or_equal", 64),
    ("покажи потоки больше 4000 байт", "streams", "stream_length", "greater_than", 4000),
    ("сессии с числом пакетов больше 10", "sessions", "packet_count", "greater_than", 10),
]

ENGLISH_CASES = [
    ("Find TCP responses longer than 1000 bytes", "messages", "payload_length", "greater_than", 1000),
    ("responses no more than 100 bytes", "messages", "payload_length", "less_or_equal", 100),
    ("messages with entropy above 7", "messages", "entropy", "greater_than", 7),
    ("packets shorter than 60", "packets", "payload_length", "less_than", 60),
]


@pytest.mark.parametrize(
    ("question", "entity", "field", "operator", "value"),
    RUSSIAN_CASES + ENGLISH_CASES,
)
def test_a_question_in_either_language_compiles_to_the_same_plan(
    question, entity, field, operator, value
):
    got_entity, filters = compiled(question)
    assert got_entity == entity, question
    assert filters == [(field, operator, value)], question


def test_a_negated_phrase_is_not_read_as_its_own_substring():
    """The ordering bug, stated as the case that caught it."""
    assert compiled("сообщения не больше 64 байт")[1][0][1] == "less_or_equal"
    assert compiled("сообщения не меньше 64 байт")[1][0][1] == "greater_or_equal"
    assert compiled("responses no more than 100 bytes")[1][0][1] == "less_or_equal"
    assert compiled("messages at least 100 bytes")[1][0][1] == "greater_or_equal"


@pytest.mark.parametrize("word", ["выше", "свыше", "больше", "длиннее", "короче", "меньше"])
def test_every_russian_threshold_word_is_recognised(word):
    assert compile_query(f"сообщения {word} 100 байт").plan.filters


@pytest.mark.parametrize("word", ["выше", "свыше", "больше", "длиннее", "короче", "меньше"])
def test_every_russian_threshold_word_matches_its_operator(word):
    """Not just "something was parsed" - the right comparison."""
    expected = (
        "less_than" if word in ("короче", "меньше") else "greater_than"
    )
    assert compile_query(f"сообщения {word} 100 байт").plan.filters[0].operator == expected


@pytest.mark.parametrize(
    ("entity_word", "entity"),
    [
        ("сообщения", "messages"),
        ("запросы", "messages"),
        ("ответы", "messages"),
        ("пакеты", "packets"),
        ("потоки", "streams"),
        ("сессии", "sessions"),
    ],
)
def test_every_russian_entity_word_selects_its_entity(entity_word, entity):
    assert compile_query(f"{entity_word} длиннее 100 байт").plan.entity == entity


@pytest.mark.parametrize(
    ("question", "bytes_expected"),
    [
        ("сообщения больше 2 кб", 2048),
        ("сообщения больше 2 кбайт", 2048),
        ("сообщения больше 2 мб", 2 * 1024 * 1024),
        ("сообщения больше 512 байт", 512),
    ],
)
def test_russian_unit_words_scale_the_same_way_as_english_ones(question, bytes_expected):
    assert compile_query(question).plan.filters[0].value == bytes_expected


def test_the_two_languages_agree_on_the_same_question():
    english = compiled("messages longer than 1000 bytes")
    russian = compiled("сообщения длиннее 1000 байт")
    assert english == russian


def test_a_request_it_still_cannot_map_is_refused_rather_than_guessed():
    """Adding vocabulary must not make the compiler eager."""
    with pytest.raises(Exception) as excinfo:
        compile_query("покажи все сообщения которые мне нравятся")
    assert "supported query" in str(excinfo.value)


# --------------------------------------------------------------------------- #
# Leading-byte comparison, which was broken in both languages
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize(
    ("question", "width"),
    [
        ("show messages whose first two bytes match", 2),
        ("messages where the first 4 bytes are identical", 4),
        ("покажи сообщения, у которых первые два байта совпадают", 2),
        ("сообщения с одинаковыми начальными 4 байтами", 4),
        ("первые 3 байта совпадают", 3),
    ],
)
def test_a_leading_byte_comparison_names_a_field_that_exists(question, width):
    """The bug this pins down.

    The plan used the operator `prefix_equals` as the *field*. The executor
    understood the operator, but the plan validator checks the field against the
    entity's real fields and rejected every such request - in English too, while
    the interface offered it as a worked example. `byte_at` is the field.
    """
    plan = compile_query(question).plan
    (filter_,) = plan.filters
    assert filter_.field == "byte_at"
    assert filter_.operator == "byte_equals_at"
    assert filter_.value == width
    # ...and it survives the same validation every other request goes through.
    from app.reporting.assistant import validate_plan

    assert validate_plan(plan.model_dump()) is not None


@pytest.mark.parametrize(
    "question",
    ["first 12 bytes match", "первые девять байт совпадают", "первые 12 байт совпадают"],
)
def test_a_too_wide_comparison_is_recognised_and_then_refused_with_the_reason(question):
    """Refused with *why*, rather than reported as a question it cannot parse."""
    with pytest.raises(CompileError) as excinfo:
        compile_query(question)
    assert "1 to 8" in str(excinfo.value)