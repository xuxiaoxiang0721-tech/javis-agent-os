"""Opt-in extraction guidance and provenance for personal-memory candidates."""
import copy
from datetime import datetime, timezone
import re

PERSONAL_MEMORY_EXTRACTION_VERSION = "personal-memory-extraction-2-temporal"
PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS = """This is a personal-memory episode, not an encyclopedia.
An explicitly named person, project, organization or specifically identified object can be
identifiable within this episode alone. A person's first name is sufficient when the text
uses it as a person's name; preserve it exactly and never invent a surname or identity.
Preserve identifying qualifiers of named objects and activities. Extract only entities
explicitly present in the source, not generic descriptions of the text or provenance metadata.
Dates, weekdays, quantities and other scalar details belong in supported fact text or
attributes; do not invent entities merely to serve as endpoints for these values.
For each relationship, use two distinct entities actually supported by the source and copy
source_entity_name and target_entity_name exactly from the supplied ENTITIES list.
Retain the full conditions, time details, negation and uncertainty in the fact text.
If no supported pair of entities exists, return no edge for that statement; never invent
an endpoint, relationship, missing value or confirmation to force an extraction.
The episode REFERENCE_TIME is processing metadata, not evidence of when a fact
became true. For this candidate workflow, leave valid_at and invalid_at null when
the source gives no explicit or genuinely source-resolvable validity boundary.
Keep all explicit source dates in fact text. Never add an as-of date to fact text
merely because an episode has a reference timestamp. Do not convert a deadline
into the beginning of an unrelated state. Recurring preferences have unknown
start dates unless the source actually states when the preference began.
"""

# Used only to recognize Graphiti's documented present-tense default, never to
# prove a fact or resolve a date. Any detectable temporal assertion disables the
# narrow normalization below; ambiguous cases retain their raw boundary for Jev.
_TEMPORAL_SIGNAL = re.compile(
    r"(?<!\d)(?:19|20|21)\d{2}(?!\d)|\d{1,2}[:/-]\d{1,2}|"
    r"\b(?:today|tomorrow|yesterday|tonight|now|currently|recently|formerly|previously|"
    r"since|until|before|after|during|ago|began|started|ended|ceased|stopped|"
    r"monday|tuesday|wednesday|thursday|friday|saturday|sunday|january|february|march|"
    r"april|june|july|august|september|october|november|december)\b|"
    r"\b(?:next|last|this)\s+(?:year|month|week|day|quarter)\b|\bas\s+of\b|\bno\s+longer\b|"
    r"今天|明天|昨天|今晚|现在|目前|最近|过去|之前|之后|以前|以后|从前|不再|已经|开始|截至|"
    r"明年|去年|今年|后年|前年|[上下本这]个?[月周]|星期[一二三四五六日天]|周[一二三四五六日天]|"
    r"[零〇一二两三四五六七八九十百千万0-9]+\s*[年月日号天周点时分秒]|"
    r"(?:年|月|日)起", re.I)
_ISO = re.compile(r"(?P<whole>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})(?:\.(?P<fraction>\d{1,9}))?(?P<zone>Z|[+-]\d{2}:\d{2})")


def _instant(value):
    """Exact nanosecond identity; never truncate precision during comparison."""
    if not isinstance(value, str):
        return None
    match = _ISO.fullmatch(value)
    if not match:
        return None
    try:
        stamp = datetime.fromisoformat(match['whole'] + match['zone'].replace('Z', '+00:00')).astimezone(timezone.utc)
    except ValueError:
        return None
    return stamp, (match['fraction'] or '').ljust(9, '0')


def extraction_instructions(temporal_context):
    if temporal_context['source_time'] is None:
        return PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS + (
            "\nThe original message occurrence time is UNKNOWN. REFERENCE_TIME here is only a local "
            "receipt/capture/processing timestamp. Do not resolve today, tomorrow, last week or other "
            "source-relative dates from it. Preserve those words and their uncertainty in the fact text.\n")
    return PERSONAL_MEMORY_EXTRACTION_INSTRUCTIONS + (
        "\nThe source occurrence time is known and may only anchor relative dates actually stated in "
        "the source; its mere availability does not establish a fact validity boundary.\n")


def normalize_candidate_times(facts, text, temporal_context):
    """Separate a documented reference default from a semantic validity claim.

    Preserve the original edge in the caller's graph checkpoint and copy both
    boundaries into an audit field. Only a start exactly equal to the reference,
    with no end and no temporal assertion in source/claim, is known to fit the
    present-tense storage convention. Every other boundary remains unmodified.
    """
    output = []
    reference = _instant(temporal_context['reference_time'])
    for original in facts:
        fact = copy.deepcopy(original)
        boundary = _ISO.fullmatch(fact.get('valid_from') or '') if isinstance(fact.get('valid_from'), str) else None
        default = (reference is not None and _instant(fact.get('valid_from')) == reference
                   and boundary is not None and boundary['zone'] in {'Z', '+00:00'}
                   and fact.get('valid_to') is None
                   and not _TEMPORAL_SIGNAL.search(text) and not _TEMPORAL_SIGNAL.search(fact['value']))
        fact['temporal_provenance'] = {'graphiti_valid_from': fact.get('valid_from'),
            'graphiti_valid_to': fact.get('valid_to'), 'reference_time': temporal_context['reference_time'],
            'reference_basis': temporal_context['reference_basis'],
            'source_time': temporal_context['source_time'],
            'normalization': 'reference_default_to_unknown' if default else 'preserved'}
        if default:
            fact['valid_from'] = None
        output.append(fact)
    return output
