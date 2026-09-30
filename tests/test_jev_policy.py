"""Synthetic typed-policy regression tests; these never contact a provider."""
import asyncio
import copy
import json
from pathlib import Path
import sys
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import jev_policy as jp

MODEL = "jev-1.13.0"
TEXT = "Alice works with Bob on Project Cedar. This is a synthetic test observation."
CONTEXT = {"authorship_verified": False, "fidelity": "unverified_forwarded",
           "speaker": "reported_user", "occurred_at": "2026-09-24T09:00:00Z"}


def request(text=TEXT, context=None):
    return {"text": text, "scope": "invest", "source_context": copy.deepcopy(CONTEXT if context is None else context),
            "source_time": "2026-09-24T09:00:00Z", "event_type": "user_input", "source_agent": "invest"}


def fact(index=0, **changes):
    value = {"graph_edge_id": "edge-%d" % index, "subject_id": "alice", "subject_label": "Alice",
             "object_label": "Bob", "predicate": "WORKS_WITH", "value": "Alice works with Bob on Project Cedar.",
             "valid_from": None, "valid_to": None}
    return {**value, **changes}


def choice(question, winner, probability=0.98, confidence=0.98):
    options = list(question["criteria"])
    return {"type": "choice", "choice": winner, "confidence": confidence,
            "probabilities": {key: probability if key == winner else (1 - probability) / (len(options) - 1)
                              for key in options}}


def good_response(questions, model):
    answers = {}
    for key, question in questions.items():
        if question["type"] == "noul":
            answers[key] = {"type": "noul", "noul": 0.01 if key in {"ambiguity", "injection", "missing_referent"} else 0.98}
        else:
            name = key[6:] if key.startswith("f") and len(key) > 6 and key[5] == "_" else key
            winner = {"decision": "keep", "category": "fact", "statement_kind": "third_party", "verdict": "supports"}[name]
            answers[key] = choice(question, winner)
    return {"model": model, "answers": answers, "usage": {"input_tokens": 77, "output_tokens": 0},
            "provider_debug": "Never copy arbitrary provider text into decisions/checkpoints."}


class FakeClient:
    def __init__(self, mutate=None, fail_call=None):
        self.calls = []
        self.mutate = mutate
        self.fail_call = fail_call

    async def evaluate(self, state, questions, *, model, stage):
        self.calls.append({"state": copy.deepcopy(state), "questions": copy.deepcopy(questions), "model": model, "stage": stage})
        if len(self.calls) == self.fail_call:
            raise RuntimeError("synthetic_transient_error")
        response = good_response(questions, model)
        if self.mutate:
            self.mutate(response, questions)
        return response


class JevPolicyTests(unittest.TestCase):
    def test_undated_fact_with_unknown_source_time_is_a_candidate_not_current_truth(self):
        client = FakeClient()
        result = self.verify(client, source_time=None, source_context={**CONTEXT, 'occurred_at': None})
        self.assertEqual(len(result['content']['facts']), 1)
        self.assertEqual(client.calls[0]['state']['candidates']['f0000']['asserted_validity'], {})
        self.assertIsNone(client.calls[0]['state']['source']['reference_time'])

    def test_unknown_source_time_never_anchors_relative_claim_or_dropped_relative_qualifier(self):
        for text, claim in [('Alice joins Orion tomorrow.', 'Alice joins Orion tomorrow.'),
                            ('Alice明天加入Orion。', 'Alice于2026-09-26加入Orion。'),
                            ('Alice joins Orion next year.', 'Alice joins Orion.')]:
            client = FakeClient()
            result = self.verify(client, text=text, source_time=None,
                source_context={**CONTEXT, 'occurred_at': None}, facts=[fact(value=claim)])
            self.assertEqual(result['content']['facts'], [])
            self.assertEqual(result['content']['review_facts'][0]['reason'], 'relative_time_unanchored')
            self.assertEqual(client.calls, [])

    def test_explicit_absolute_source_date_needs_no_message_occurrence_time(self):
        text = 'Alice manages Orion from 2026-01-01.'
        result = self.verify(text=text, source_time=None, source_context={**CONTEXT, 'occurred_at': None},
            facts=[fact(value=text, valid_from='2026-01-01T00:00:00Z')])
        self.assertEqual(len(result['content']['facts']), 1)

    def test_capture_date_not_in_source_still_requires_review(self):
        result = self.verify(source_time=None, source_context={**CONTEXT, 'occurred_at': None},
            facts=[fact(valid_from='2026-09-24T09:00:00Z')])
        self.assertEqual(result['content']['facts'], [])
        self.assertEqual(result['content']['review_facts'][0]['reason'], 'validity_not_in_source')

    def test_source_time_must_be_a_zoned_timestamp_not_a_processing_label(self):
        for value in ('2026-09-24', '2026-09-24T09:00:00', 'captured_today'):
            with self.assertRaises(jp.PolicyValidationError):
                self.verify(source_time=value)

    def test_nanosecond_source_timestamp_is_retained_and_can_anchor_explicit_tomorrow(self):
        stamp = '2026-09-24T09:00:00.123456789Z'
        client = FakeClient()
        result = self.verify(client, text='Alice joins Orion tomorrow.', source_time=stamp,
            source_context={**CONTEXT, 'occurred_at': stamp},
            facts=[fact(value='Alice joins Orion on 2026-09-25.', valid_from='2026-09-25T00:00:00Z')])
        self.assertEqual(len(result['content']['facts']), 1)
        self.assertEqual(client.calls[0]['state']['source']['reference_time'], stamp)

    def screen(self, client=None, req=None, model=MODEL):
        return asyncio.run(jp.screen_decision(client or FakeClient(), req or request(), model=model))

    def verify(self, client=None, facts=None, **extra):
        args = dict(text=TEXT, scope="invest", source_context=copy.deepcopy(CONTEXT),
                    source_time="2026-09-24T09:00:00Z", facts=[fact()] if facts is None else facts, model=MODEL)
        args.update(extra)
        return asyncio.run(jp.verify_facts(client or FakeClient(), **args))

    def test_screen_uses_typed_independent_questions_and_original_evidence(self):
        client = FakeClient()
        req = request("  " + TEXT + "\n")
        before = copy.deepcopy(req)
        result = self.screen(client, req)
        self.assertTrue(result["provider_called"])
        self.assertEqual(result["content"]["decision"], "keep")
        self.assertEqual(result["content"]["evidence"], [req["text"]])
        self.assertEqual(req, before)
        self.assertEqual(set(client.calls[0]["questions"]), {"durability", "ambiguity", "missing_referent", "injection", "decision", "category", "statement_kind"})
        self.assertEqual(client.calls[0]["stage"], "screening")
        self.assertEqual(client.calls[0]["state"]["source"]["provenance"]["fidelity"], CONTEXT["fidelity"])
        self.assertFalse(result["decisions"]["thresholds_calibrated"])
        self.assertNotIn("provider_debug", json.dumps(result))

    def test_model_requires_exact_version_and_response_identity(self):
        for model in ("jev-latest", "jev", "qwen-turbo", "jev-1.13.0-preview", "jev-1.13.0\n"):
            client = FakeClient()
            with self.subTest(model=model), self.assertRaises(jp.PolicyValidationError):
                self.screen(client, model=model)
            self.assertFalse(client.calls)
        with self.assertRaisesRegex(jp.PolicyValidationError, "jev_model_identity_mismatch"):
            self.screen(FakeClient(lambda r, q: r.update(model="jev-1.12.0")))

    def test_missing_extra_or_mistyped_questions_are_rejected(self):
        mutations = [lambda r, q: r["answers"].pop("ambiguity"),
                     lambda r, q: r["answers"].update(extra={"type": "noul", "noul": 0.1}),
                     lambda r, q: r["answers"]["ambiguity"].update(type="score"),
                     lambda r, q: r["answers"]["ambiguity"].update(explanation="free text")]
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.assertRaises(jp.PolicyValidationError):
                self.screen(FakeClient(mutate))

    def test_noul_values_reject_bool_nonfinite_out_of_range_and_huge_integer(self):
        for value in (True, None, "0.9", float("nan"), float("inf"), -0.01, 1.01, 10**400):
            with self.subTest(value_type=type(value).__name__), self.assertRaises(jp.PolicyValidationError):
                self.screen(FakeClient(lambda r, q: r["answers"]["durability"].update(noul=value)))

    def test_choice_distribution_and_confidence_are_strict(self):
        mutations = [lambda a: a.update(choice="invented"), lambda a: a.update(confidence=True),
                     lambda a: a.update(confidence=float("nan")), lambda a: a.update(confidence=1.2),
                     lambda a: a["probabilities"].pop("keep"),
                     lambda a: a["probabilities"].update(unexpected=0),
                     lambda a: a["probabilities"].update(keep=0.5),
                     lambda a: a["probabilities"].update(keep=float("nan")),
                     lambda a: a.update(choice="archive_only")]
        for mutate in mutations:
            with self.subTest(mutation=mutate), self.assertRaises(jp.PolicyValidationError):
                self.screen(FakeClient(lambda r, q: mutate(r["answers"]["decision"])))

    def test_low_confidence_or_gate_risk_requires_evidence(self):
        cases = [lambda r, q: r["answers"]["decision"].update(confidence=0.69),
                 lambda r, q: r["answers"]["durability"].update(noul=0.64),
                 lambda r, q: r["answers"]["ambiguity"].update(noul=0.60),
                 lambda r, q: r["answers"]["injection"].update(noul=0.11)]
        for mutate in cases:
            with self.subTest(mutation=mutate):
                result = self.screen(FakeClient(mutate))
                self.assertEqual(result["content"]["decision"], "needs_evidence")
                self.assertEqual(result["content"]["evidence"], [TEXT])

    def test_archive_only_needs_agreement_of_durability(self):
        def archive(response, questions):
            response["answers"]["decision"] = choice(questions["decision"], "archive_only")
        self.assertEqual(self.screen(FakeClient(archive))["content"]["decision"], "needs_evidence")
        def transient(response, questions):
            archive(response, questions)
            response["answers"]["durability"]["noul"] = 0.01
        self.assertEqual(self.screen(FakeClient(transient))["content"]["decision"], "archive_only")

    def test_explicit_conflict_does_not_select_a_truth(self):
        result = self.screen(FakeClient(lambda r, q: r["answers"].update(decision=choice(q["decision"], "conflict"))))
        self.assertEqual(result["content"]["decision"], "conflict")
        self.assertEqual(result["content"]["evidence"], [TEXT])

    def test_unverified_authorship_cannot_be_upgraded(self):
        def user(response, questions):
            for key in questions:
                if key.endswith("statement_kind"):
                    response["answers"][key] = choice(questions[key], "user_explicit")
        with self.assertRaisesRegex(jp.PolicyValidationError, "unverified_authorship"):
            self.screen(FakeClient(user))
        with self.assertRaisesRegex(jp.PolicyValidationError, "unverified_authorship"):
            self.verify(FakeClient(user))
        context = {**CONTEXT, "authorship_verified": True}
        self.assertEqual(self.screen(FakeClient(user), request(context=context))["content"]["statement_kind"], "user_explicit")

    def test_source_too_large_uses_utf8_bytes_without_network_or_truncation(self):
        text = "汉" * (jp.MAX_SOURCE_BYTES // 3 + 1)
        client = FakeClient()
        result = self.screen(client, request(text))
        self.assertEqual(result["content"]["decision"], "needs_evidence")
        self.assertEqual(result["content"]["reason"], "source_too_large")
        self.assertEqual(result["decisions"]["local_reason"], "source_too_large")
        self.assertEqual(result["content"]["evidence"], [])
        self.assertFalse(result["provider_called"])
        self.assertFalse(client.calls)
        result = self.verify(client, text=text)
        self.assertEqual(result["content"]["facts"], [])
        self.assertFalse(result["provider_called"])
        self.assertFalse(client.calls)

    def test_invalid_input_and_provenance_rejected_before_call(self):
        for changes in ({"text": " "}, {"scope": "shared"}, {"source_context": {}},
                        {"source_context": {"authorship_verified": 1}}, {"source_time": 42}):
            client = FakeClient()
            with self.subTest(changes=changes), self.assertRaises(jp.PolicyValidationError):
                self.screen(client, {**request(), **changes})
            self.assertFalse(client.calls)

    def test_fact_supported_only_with_all_independent_questions(self):
        client = FakeClient()
        result = self.verify(client)
        self.assertTrue(result["provider_called"])
        self.assertEqual(len(result["content"]["facts"]), 1)
        self.assertEqual(result["content"]["facts"][0]["evidence"], TEXT)
        self.assertEqual(result["content"]["facts"][0]["graph_edge_id"], "edge-0")
        self.assertEqual(set(client.calls[0]["questions"]), {"f0000_" + name for name in jp.FACT_QUESTIONS if name not in {"numbers", "dates"}})
        self.assertEqual(client.calls[0]["stage"], "verification")

    def test_fact_unsupported_or_any_weak_component_omitted(self):
        for name in ("subject", "modality", "attribution"):
            with self.subTest(name=name):
                result = self.verify(FakeClient(lambda r, q: r["answers"]["f0000_" + name].update(noul=0.40)))
                self.assertEqual(result["content"]["facts"], [])
                self.assertEqual(result["decisions"]["facts"][0]["reason"], "typed_" + name + "_unproven")
                self.assertEqual(result["decisions"]["facts"][0]["disposition"], "review")
                self.assertEqual(result["content"]["review_facts"][0]["graph_edge_id"], "edge-0")
        for verdict in ("contradicts", "insufficient"):
            result = self.verify(FakeClient(lambda r, q: r["answers"].update(f0000_verdict=choice(q["f0000_verdict"], verdict))))
            self.assertFalse(result["content"]["facts"])

    def test_fact_partial_support_does_not_drop_other_supported_fact(self):
        client = FakeClient(lambda r, q: r["answers"]["f0000_modality"].update(noul=0.1))
        result = self.verify(client, facts=[fact(), fact(1)])
        self.assertEqual([f["graph_edge_id"] for f in result["content"]["facts"]], ["edge-1"])

    def test_fact_low_support_confidence_reviews_but_labels_do_not_block(self):
        for name in ("verdict",):
            result = self.verify(FakeClient(lambda r, q: r["answers"]["f0000_" + name].update(confidence=0.8)))
            self.assertFalse(result["content"]["facts"])
            self.assertEqual(result["content"]["review_facts"][0]["graph_edge_id"], "edge-0")
        result = self.verify(FakeClient(lambda r, q: r["answers"]["f0000_category"].update(confidence=0.4)))
        self.assertEqual(len(result["content"]["facts"]), 1)
        self.assertIn("category_uncertain", result["decisions"]["facts"][0]["flags"])
        result = self.verify(FakeClient(lambda r, q: r["answers"]["f0000_statement_kind"].update(confidence=0.4)))
        self.assertEqual(len(result["content"]["facts"]), 1)
        self.assertIn("statement_kind_uncertain", result["decisions"]["facts"][0]["flags"])

    def test_empty_facts_needs_no_provider(self):
        client = FakeClient()
        result = self.verify(client, facts=[])
        self.assertFalse(client.calls)
        self.assertFalse(result["provider_called"])
        self.assertEqual(result["decisions"]["local_reason"], "no_facts")

    def test_all_facts_validated_before_any_call(self):
        for invalid in ([fact(), fact()], [fact(), fact(1, value="")], [fact(), fact(1, valid_from=42)]):
            client = FakeClient()
            with self.subTest(invalid=invalid), self.assertRaises(jp.PolicyValidationError):
                self.verify(client, facts=invalid)
            self.assertFalse(client.calls)

    def test_request_budget_shrinks_batches_and_preserves_every_source_byte(self):
        from jev_client import _payload
        text = "汉" * 5300
        facts = [fact(i, value="字" * 1000) for i in range(9)]
        client = FakeClient()
        result = self.verify(client, facts=facts, text=text)
        self.assertEqual(len(result["content"]["facts"]), 9)
        self.assertGreater(len(client.calls), 1)
        for call in client.calls:
            self.assertEqual(call["state"]["source"]["original_source"], text)
            self.assertLessEqual(len(call["state"]["candidates"]), 8)
            self.assertLessEqual(len(_payload(call["state"], call["questions"], MODEL)), jp.MAX_REQUEST_BYTES)

    def test_oversize_candidate_is_not_truncated_or_sent(self):
        client = FakeClient()
        result = self.verify(client, facts=[fact(value="x" * 40000), fact(1)])
        self.assertEqual(len(client.calls), 1)
        self.assertEqual([f["graph_edge_id"] for f in result["content"]["facts"]], ["edge-1"])
        self.assertEqual(result["decisions"]["facts"][0]["reason"], "candidate_too_large")

    def test_successful_batches_survive_later_failure_and_replay_without_cost(self):
        checkpoint, saved = {}, []
        facts = [fact(i) for i in range(9)]
        async def persist(value):
            saved.append(copy.deepcopy(value))
        first = FakeClient(fail_call=2)
        with self.assertRaisesRegex(RuntimeError, "synthetic_transient_error"):
            self.verify(first, facts=facts, checkpoint=checkpoint, on_checkpoint=persist)
        self.assertEqual(len(checkpoint), 1)
        self.assertEqual(saved[-1], checkpoint)
        self.assertNotIn("provider_debug", json.dumps(checkpoint))
        self.assertNotIn("usage", json.dumps(checkpoint))
        second = FakeClient()
        result = self.verify(second, facts=facts, checkpoint=checkpoint, on_checkpoint=persist)
        self.assertEqual(len(second.calls), 1)
        self.assertEqual(len(result["content"]["facts"]), 9)
        self.assertTrue(result["provider_called"])
        third = FakeClient()
        replay = self.verify(third, facts=facts, checkpoint=checkpoint)
        self.assertFalse(third.calls)
        self.assertFalse(replay["provider_called"])
        self.assertEqual(result["content"], replay["content"])

    def test_checkpoint_binds_source_context_fact_model_and_policy(self):
        checkpoint = {}
        self.verify(checkpoint=checkpoint)
        changes = [{"text": TEXT + " Again."}, {"model": "jev-1.14.0"},
                   {"source_context": {**CONTEXT, "speaker": "someone_else"}},
                   {"facts": [fact(value="A changed candidate assertion.")]}]
        for change in changes:
            client = FakeClient()
            self.verify(client, checkpoint=copy.deepcopy(checkpoint), **change)
            self.assertEqual(len(client.calls), 1)
        from unittest.mock import patch
        with patch.object(jp, "POLICY_DIGEST", "0" * 64):
            client = FakeClient()
            self.verify(client, checkpoint=checkpoint)
            self.assertEqual(len(client.calls), 1)

    def test_checkpoint_corruption_and_malformed_cached_answers_fail_closed(self):
        checkpoint = {}
        self.verify(checkpoint=checkpoint)
        key = next(iter(checkpoint))
        for recompute_digest in (False, True):
            corrupted = copy.deepcopy(checkpoint)
            corrupted[key]["response"]["answers"]["f0000_subject"]["noul"] = 2
            if recompute_digest:
                corrupted[key]["checkpoint_digest"] = jp._digest(corrupted[key]["response"])
            client = FakeClient()
            with self.assertRaises(jp.PolicyValidationError):
                self.verify(client, checkpoint=corrupted)
            self.assertFalse(client.calls)

    def test_unverified_authorship_is_not_checkpointed_as_success(self):
        checkpoint = {}
        client = FakeClient(lambda r, q: r["answers"].update(f0000_statement_kind=choice(q["f0000_statement_kind"], "user_explicit")))
        with self.assertRaises(jp.PolicyValidationError):
            self.verify(client, checkpoint=checkpoint)
        self.assertFalse(checkpoint)

    def test_persistence_callback_failure_stops_next_paid_batch(self):
        client = FakeClient()
        def fail(value):
            raise RuntimeError("synthetic_disk_error")
        with self.assertRaisesRegex(RuntimeError, "synthetic_disk_error"):
            self.verify(client, facts=[fact(i) for i in range(9)], on_checkpoint=fail)
        self.assertEqual(len(client.calls), 1)

    def test_safe_errors_never_include_source_or_provider_text(self):
        client = FakeClient(lambda r, q: r.update(model="SECRET_PROVIDER_RESPONSE"))
        with self.assertRaises(jp.PolicyValidationError) as captured:
            self.screen(client, request("PRIVATE_SYNTHETIC_SOURCE"))
        self.assertNotIn("PRIVATE", str(captured.exception))
        self.assertNotIn("SECRET", str(captured.exception))

    def test_candidate_routing_is_distinct_from_fact_support(self):
        def candidate(response, questions):
            response["answers"]["decision"] = choice(questions["decision"], "keep", probability=0.80, confidence=0.80)
            response["answers"]["durability"]["noul"] = 0.80
            response["answers"]["ambiguity"]["noul"] = 0.30
            response["answers"]["category"] = choice(questions["category"], "fact", probability=0.50, confidence=0.40)
        result = self.screen(FakeClient(candidate))
        self.assertEqual(result["content"]["decision"], "keep")
        self.assertEqual(result["decisions"]["disposition"], "candidate_extraction")
        self.assertIn("category_uncertain", result["decisions"]["flags"])
        self.assertIn("source_meaning_needs_attention", result["decisions"]["flags"])
        # The same modest confidence must NOT establish factual support.
        result = self.verify(FakeClient(lambda r, q: r["answers"].update(f0000_verdict=choice(q["f0000_verdict"], "supports", probability=0.80, confidence=0.80))))
        self.assertFalse(result["content"]["facts"])
        self.assertEqual(result["decisions"]["facts"][0]["disposition"], "review")

    def test_chatter_does_not_need_precise_category_to_archive(self):
        def chatter(response, questions):
            response["answers"]["decision"] = choice(questions["decision"], "archive_only", probability=0.90, confidence=0.80)
            response["answers"]["durability"]["noul"] = 0.08
            response["answers"]["category"] = choice(questions["category"], "other", probability=0.45, confidence=0.40)
            response["answers"]["statement_kind"]["confidence"] = 0.60
            response["answers"]["missing_referent"]["noul"] = 0.85
            response["answers"]["ambiguity"]["noul"] = 0.80
        result = self.screen(FakeClient(chatter), request("早上好，谢谢，回头见。"))
        self.assertEqual(result["content"]["decision"], "archive_only")
        self.assertIn("category_uncertain", result["decisions"]["flags"])

    def test_ambiguous_non_candidate_cannot_archive_without_strong_disposition_and_low_value(self):
        def uncertain(response, questions):
            response["answers"]["decision"] = choice(questions["decision"], "archive_only", probability=0.70, confidence=0.60)
            response["answers"]["durability"]["noul"] = 0.08
            response["answers"]["missing_referent"]["noul"] = 0.85
        result = self.screen(FakeClient(uncertain))
        self.assertEqual(result["content"]["decision"], "needs_evidence")
        self.assertEqual(result["content"]["reason"], "typed_archive_uncertain")

    def test_claim_support_cannot_bypass_substantial_subject_or_date_disagreement(self):
        source = "Alice joined Bob on 2026-01-01."
        for field in ("subject", "dates"):
            client = FakeClient(lambda r, q: r["answers"]["f0000_" + field].update(noul=0.20))
            result = self.verify(client, text=source, facts=[fact(value=source, valid_from="2026-01-01T00:00:00Z")])
            self.assertFalse(result["content"]["facts"])
            self.assertEqual(result["content"]["review_facts"][0]["reason"], "typed_" + field + "_unproven")

    def test_injection_reason_precedes_low_classification_confidence(self):
        def attack(response, questions):
            response["answers"]["injection"]["noul"] = 0.99
            response["answers"]["category"]["confidence"] = 0.20
            response["answers"]["decision"]["confidence"] = 0.20
        result = self.screen(FakeClient(attack))
        self.assertEqual(result["content"]["reason"], "typed_injection_risk")
        self.assertEqual(result["decisions"]["disposition"], "review")

    def test_verifier_never_receives_graph_identifiers(self):
        edge_id, subject_id = "f7c70e69-29c7-432f-a348-94922b6f0291", "a7266295-ea7f-4999-ad11-5f18a1611a3a"
        client = FakeClient()
        result = self.verify(client, facts=[fact(graph_edge_id=edge_id, subject_id=subject_id)])
        wire = json.dumps(client.calls, ensure_ascii=False)
        self.assertNotIn(edge_id, wire)
        self.assertNotIn(subject_id, wire)
        self.assertNotIn("graph_edge_id", wire)
        self.assertNotIn("subject_id", wire)
        semantic = client.calls[0]["state"]["candidates"]["f0000"]
        self.assertEqual(set(semantic), {"claim", "subject", "relation", "object", "asserted_validity"})
        self.assertEqual(result["content"]["facts"][0]["graph_edge_id"], edge_id)

    def test_source_only_numbers_and_metadata_timestamps_are_not_quantity_assertions(self):
        client = FakeClient()
        result = self.verify(client, text=TEXT + " The unrelated filing has 500 pages.")
        self.assertNotIn("f0000_numbers", client.calls[0]["questions"])
        self.assertNotIn("f0000_dates", client.calls[0]["questions"])
        self.assertEqual(result["decisions"]["facts"][0]["applicability"], {"numbers": "not_applicable", "dates": "not_applicable"})

    def test_only_applicable_quantity_and_date_questions_are_asked(self):
        text = "Alice bought 3 bicycles on 2026-01-01."
        for weak in ("numbers", "dates"):
            client = FakeClient(lambda r, q: r["answers"]["f0000_" + weak].update(noul=0.40))
            result = self.verify(client, text=text, facts=[fact(value=text)])
            self.assertIn("f0000_numbers", client.calls[0]["questions"])
            self.assertIn("f0000_dates", client.calls[0]["questions"])
            self.assertEqual(result["content"]["review_facts"][0]["reason"], "typed_" + weak + "_unproven")

    def test_calendar_date_is_not_a_quantity(self):
        client = FakeClient()
        text = "Alice joined Bob on 2026-01-01."
        result = self.verify(client, text=text, facts=[fact(value=text, valid_from="2026-01-01T00:00:00+00:00")])
        self.assertIn("f0000_dates", client.calls[0]["questions"])
        self.assertNotIn("f0000_numbers", client.calls[0]["questions"])
        self.assertEqual(len(result["content"]["facts"]), 1)

    def test_invented_quantity_without_source_quantity_is_local_review(self):
        client = FakeClient()
        result = self.verify(client, facts=[fact(value="Alice works with 3 colleagues.")])
        self.assertFalse(client.calls)
        self.assertFalse(result["provider_called"])
        self.assertEqual(result["content"]["review_facts"], [{"graph_edge_id": "edge-0", "reason": "quantity_not_in_source"}])

    def test_literal_quantity_contradiction_is_rejected_without_network(self):
        client = FakeClient()
        result = self.verify(client, text="Alice owns 3 bicycles.", facts=[fact(value="Alice owns 5 bicycles.")])
        self.assertFalse(client.calls)
        self.assertFalse(result["content"]["facts"])
        self.assertFalse(result["content"]["review_facts"])
        self.assertEqual(result["decisions"]["facts"][0]["disposition"], "rejected")
        self.assertEqual(result["decisions"]["facts"][0]["reason"], "explicit_quantity_contradiction")

    def test_qualified_or_denied_quantities_are_not_locally_called_contradictions(self):
        for text, claim in (("Alice may own 3 bicycles.", "Alice may own 5 bicycles."),
                            ("Alice does not own 3 bicycles.", "Alice does not own 5 bicycles.")):
            client = FakeClient(lambda r, q: r["answers"].update(f0000_verdict=choice(q["f0000_verdict"], "insufficient")))
            result = self.verify(client, text=text, facts=[fact(value=claim)])
            self.assertEqual(len(client.calls), 1)
            self.assertEqual(result["decisions"]["facts"][0]["disposition"], "review")

    def test_capture_time_does_not_become_validity(self):
        client = FakeClient()
        result = self.verify(client, facts=[fact(valid_from="2026-09-24T09:00:00Z")])
        self.assertFalse(client.calls)
        self.assertEqual(result["content"]["review_facts"][0]["reason"], "validity_not_in_source")

    def test_explicit_relative_date_can_use_reference_but_not_invent_precision(self):
        text = "Alice joined Bob today."
        client = FakeClient()
        result = self.verify(client, text=text, facts=[fact(value=text, valid_from="2026-09-24T00:00:00Z")])
        self.assertEqual(len(client.calls), 1)
        self.assertTrue(result["content"]["facts"])
        client = FakeClient()
        result = self.verify(client, text=text, facts=[fact(value=text, valid_from="2026-09-24T09:00:00Z")])
        self.assertFalse(client.calls)
        self.assertEqual(result["content"]["review_facts"][0]["reason"], "validity_precision_unproven")

    def test_high_confidence_contradiction_is_rejected_low_confidence_is_review(self):
        for confidence, disposition in ((0.98, "rejected"), (0.80, "review")):
            client = FakeClient(lambda r, q: r["answers"].update(f0000_verdict=choice(q["f0000_verdict"], "contradicts", confidence=confidence)))
            result = self.verify(client)
            self.assertEqual(result["decisions"]["facts"][0]["disposition"], disposition)
            self.assertFalse(result["content"]["facts"])
            self.assertEqual(bool(result["content"]["review_facts"]), disposition == "review")

    def test_every_fact_has_one_disposition_and_disjoint_supported_review_lists(self):
        def answer(response, questions):
            response["answers"]["f0001_verdict"] = choice(questions["f0001_verdict"], "insufficient")
            response["answers"]["f0002_verdict"] = choice(questions["f0002_verdict"], "contradicts")
        result = self.verify(FakeClient(answer), facts=[fact(0), fact(1), fact(2)])
        self.assertEqual([row["disposition"] for row in result["decisions"]["facts"]], ["accepted_candidate", "review", "rejected"])
        self.assertEqual([row["graph_edge_id"] for row in result["content"]["facts"]], ["edge-0"])
        self.assertEqual([row["graph_edge_id"] for row in result["content"]["review_facts"]], ["edge-1"])

    def test_local_source_limit_does_not_silently_lose_review_facts(self):
        client = FakeClient()
        result = self.verify(client, facts=[fact(0), fact(1)], text="汉" * 6000)
        self.assertFalse(client.calls)
        self.assertEqual(len(result["content"]["review_facts"]), 2)
        self.assertTrue(all(row["disposition"] == "review" for row in result["decisions"]["facts"]))

    def test_new_policy_invalidates_old_checkpoint_keys(self):
        self.assertEqual(jp.POLICY_VERSION, "jev-typed-v4-temporal")
        self.assertNotEqual(jp.POLICY_DIGEST, "8513b5d55f6741087608fbdb8e929d39250702643bc292c2ec9eacf049b777ca")
        self.assertEqual(jp.THRESHOLDS["support"], 0.90)
        self.assertEqual(jp.THRESHOLDS["injection_max"], 0.10)

    def test_missing_referent_is_independent_of_general_ambiguity_and_durability(self):
        client = FakeClient(lambda r, q: r["answers"]["missing_referent"].update(noul=0.80))
        result = self.screen(client, request("按先前提到的办法做。"))
        self.assertEqual(result["content"]["decision"], "needs_evidence")
        self.assertEqual(result["content"]["reason"], "typed_missing_referent")
        self.assertEqual(result["decisions"]["answers"]["ambiguity"]["noul"], 0.01)

    def test_high_whole_claim_support_uses_mild_auxiliary_uncertainty_as_flags(self):
        def mild(response, questions):
            response["answers"]["f0000_attribution"]["noul"] = 0.76
            response["answers"]["f0000_modality"]["noul"] = 0.87
        result = self.verify(FakeClient(mild))
        self.assertEqual(len(result["content"]["facts"]), 1)
        self.assertIn("diagnostic_attribution_uncertain", result["decisions"]["facts"][0]["flags"])
        self.assertIn("diagnostic_modality_uncertain", result["decisions"]["facts"][0]["flags"])

    def test_day_precision_wire_omits_technical_midnight_but_keeps_boundaries(self):
        text = "Alice joined Bob on 2026-01-01."
        client = FakeClient()
        self.verify(client, text=text, facts=[fact(value=text, valid_from="2026-01-01T00:00:00Z")])
        validity = client.calls[0]["state"]["candidates"]["f0000"]["asserted_validity"]
        self.assertEqual(validity, {"valid_from": {"date": "2026-01-01", "precision": "day"}})

    def test_unparsed_equivalent_quantities_are_never_local_hard_rejections(self):
        pairs = [("报告分成十二份。", "报告分成12份。"),
                 ("The amount is 1,5 euros.", "The amount is 1.5 euros."),
                 ("The amount is 1,000 euros.", "The amount is 1000 euros.")]
        for source, claim in pairs:
            client = FakeClient()
            result = self.verify(client, text=source, facts=[fact(value=claim)])
            self.assertEqual(len(client.calls), 1)
            self.assertEqual(result["decisions"]["facts"][0]["disposition"], "accepted_candidate")
            self.assertIn("f0000_numbers", client.calls[0]["questions"])

    def test_explicit_relative_year_asks_date_question_without_inventing_validity(self):
        for text in ("用户也许在明年搬家，但尚未决定。", "The user may move next year but has not decided."):
            client = FakeClient()
            self.verify(client, text=text, facts=[fact(value=text)])
            self.assertIn("f0000_dates", client.calls[0]["questions"])
            self.assertNotIn("f0000_numbers", client.calls[0]["questions"])
            self.assertEqual(client.calls[0]["state"]["candidates"]["f0000"]["asserted_validity"], {})

    def test_only_complete_utc_zero_midnight_including_zero_nanoseconds_is_day_precision(self):
        text = "Alice joined Bob on 2026-01-01."
        for boundary in ("2026-01-01T00:00:00Z", "2026-01-01T00:00:00+00:00",
                         "2026-01-01T00:00:00.000000000Z", "2026-01-01T00:00:00.000000000+00:00"):
            with self.subTest(boundary=boundary):
                client = FakeClient()
                result = self.verify(client, text=text, facts=[fact(value=text, valid_from=boundary)])
                self.assertEqual(len(result["content"]["facts"]), 1)
                actual = client.calls[0]["state"]["candidates"]["f0000"]["asserted_validity"]
                self.assertEqual(actual, {"valid_from": {"date": "2026-01-01", "precision": "day"}})
        # A date-only, incomplete clock or unknown -00:00 is not a known UTC
        # midnight convention and must not silently acquire that interpretation.
        for boundary in ("2026-01-01", "2026-01-01T00:00Z", "2026-01-01T00:00:00-00:00"):
            client = FakeClient()
            result = self.verify(client, text=text, facts=[fact(value=text, valid_from=boundary)])
            self.assertFalse(client.calls)
            self.assertEqual(result["content"]["review_facts"][0]["reason"], "validity_precision_unproven")

    def test_nonzero_fraction_requires_complete_source_timestamp_and_never_becomes_day(self):
        for boundary in ("2026-01-01T00:00:00.123Z", "2026-01-01T00:00:00.000000001+00:00"):
            with self.subTest(boundary=boundary):
                client = FakeClient()
                result = self.verify(client, text="Alice joined Bob on 2026-01-01.",
                                     facts=[fact(valid_from=boundary)])
                self.assertFalse(client.calls)
                self.assertEqual(result["content"]["review_facts"][0]["reason"], "validity_precision_unproven")
                text = "Alice joined Bob at " + boundary + "."
                client = FakeClient()
                result = self.verify(client, text=text, facts=[fact(value=text, valid_from=boundary)])
                self.assertEqual(len(result["content"]["facts"]), 1)
                actual = client.calls[0]["state"]["candidates"]["f0000"]["asserted_validity"]
                self.assertEqual(actual, {"valid_from": {"timestamp": boundary, "precision": "time"}})

    def test_nonutc_offset_requires_complete_source_timestamp_and_is_preserved(self):
        boundary = "2026-01-01T00:00:00+08:00"
        client = FakeClient()
        result = self.verify(client, text="Alice joined Bob on 2026-01-01.", facts=[fact(valid_from=boundary)])
        self.assertFalse(client.calls)
        self.assertEqual(result["content"]["review_facts"][0]["reason"], "validity_precision_unproven")
        text = "Alice joined Bob at " + boundary + "."
        client = FakeClient()
        result = self.verify(client, text=text, facts=[fact(value=text, valid_from=boundary)])
        self.assertEqual(len(result["content"]["facts"]), 1)
        actual = client.calls[0]["state"]["candidates"]["f0000"]["asserted_validity"]
        self.assertEqual(actual, {"valid_from": {"timestamp": boundary, "precision": "time"}})

    def test_separate_date_and_clock_fragment_cannot_prove_precise_boundary(self):
        text = "Alice joined Bob on 2026-01-01. A separate clock reading was 09:12:30.123Z."
        client = FakeClient()
        result = self.verify(client, text=text, facts=[fact(valid_from="2026-01-01T09:12:30.123Z")])
        self.assertFalse(client.calls)
        self.assertEqual(result["content"]["review_facts"][0]["reason"], "validity_precision_unproven")

    def test_cache_binds_all_original_edge_fields_even_when_wire_semantics_are_equal(self):
        text = "Alice joined Bob on 2026-01-01 and left on 2026-01-02."
        original = fact(value=text, valid_from="2026-01-01T00:00:00Z", valid_to="2026-01-02T00:00:00Z")
        checkpoint = {}
        self.verify(text=text, facts=[original], checkpoint=checkpoint)
        variants = [{**original, "valid_from": "2026-01-01T00:00:00.000000000+00:00"},
                    {**original, "valid_to": "2026-01-02T00:00:00.000000000Z"},
                    {**original, "local_edge_metadata": "synthetic-field-variation"}]
        for changed in variants:
            self.assertEqual(jp._semantic(original), jp._semantic(changed))
            client = FakeClient()
            self.verify(client, text=text, facts=[changed], checkpoint=copy.deepcopy(checkpoint))
            self.assertEqual(len(client.calls), 1)
            self.assertNotIn("local_edge_metadata", json.dumps(client.calls))
        replay = FakeClient()
        self.verify(replay, text=text, facts=[original], checkpoint=checkpoint)
        self.assertFalse(replay.calls)

    def test_category_math_invalid_is_isolated_with_original_answer_and_other_label(self):
        def invalid_sum(response, questions):
            for key in questions:
                if key.endswith("category"):
                    response["answers"][key] = {"type": "choice", "choice": "rule", "confidence": 0.62,
                        "probabilities": {"preference": 0.0, "fact": 0.28, "rule": 0.69, "event": 0.0, "intent": 0.0, "other": 0.02}}
        screen = self.screen(FakeClient(invalid_sum))
        self.assertEqual(screen["content"]["decision"], "keep")
        self.assertEqual(screen["content"]["category"], "other")
        self.assertEqual(screen["decisions"]["answers"]["category"]["choice"], "rule")
        self.assertEqual(screen["decisions"]["answers"]["category"]["probabilities"]["rule"], 0.69)
        self.assertIn("category_invalid_probability_sum", screen["decisions"]["flags"])
        result = self.verify(FakeClient(invalid_sum), facts=[fact(), fact(1)])
        self.assertEqual(len(result["content"]["facts"]), 2)
        self.assertTrue(all(row["category"] == "other" for row in result["content"]["facts"]))
        self.assertTrue(all("category_invalid" in row["flags"] for row in result["decisions"]["facts"]))
        self.assertEqual(result["decisions"]["facts"][0]["answers"]["category"]["probabilities"]["rule"], 0.69)

    def test_wrong_category_winner_does_not_rescue_contradicted_claim(self):
        def contradictory(response, questions):
            response["answers"]["f0000_verdict"] = choice(questions["f0000_verdict"], "contradicts")
            response["answers"]["f0000_category"] = {"type": "choice", "choice": "fact", "confidence": 0.39,
                "probabilities": {"preference": 0.0, "fact": 0.49, "rule": 0.0, "event": 0.01, "intent": 0.0, "other": 0.50}}
        result = self.verify(FakeClient(contradictory))
        self.assertFalse(result["content"]["facts"])
        self.assertFalse(result["content"]["review_facts"])
        row = result["decisions"]["facts"][0]
        self.assertEqual(row["disposition"], "rejected")
        self.assertEqual(row["labels"]["category"], "other")
        self.assertEqual(row["answers"]["category"]["choice"], "fact")
        self.assertIn("category_choice_not_maximal", row["flags"])

    def test_category_type_labels_fields_and_finite_probabilities_remain_strict(self):
        mutations = [lambda answer: answer.update(type="noul"),
                     lambda answer: answer.update(choice="invented"),
                     lambda answer: answer.update(confidence=True),
                     lambda answer: answer.update(confidence=float("nan")),
                     lambda answer: answer.update(extra="not allowed"),
                     lambda answer: answer["probabilities"].pop("other"),
                     lambda answer: answer["probabilities"].update(extra=0),
                     lambda answer: answer["probabilities"].update(other=float("inf")),
                     lambda answer: answer["probabilities"].update(other=True),
                     lambda answer: answer["probabilities"].update(other=-0.1)]
        for mutate in mutations:
            with self.subTest(mutate=mutate), self.assertRaises(jp.PolicyValidationError):
                self.screen(FakeClient(lambda response, questions: mutate(response["answers"]["category"])))

    def test_authoritative_probability_math_stays_strict_despite_forged_diagnostic(self):
        for key in ("decision", "statement_kind"):
            def bad(response, questions):
                answer = response["answers"][key]
                answer["probabilities"][answer["choice"]] -= 0.01
                response["diagnostics"] = {key: ["category_invalid_probability_sum"]}
            with self.subTest(key=key), self.assertRaisesRegex(jp.PolicyValidationError, "jev_invalid_probability_sum"):
                self.screen(FakeClient(bad))
        def bad_verdict(response, questions):
            response["answers"]["f0000_verdict"]["probabilities"]["supports"] -= 0.01
            response["diagnostics"] = {"f0000_verdict": ["category_invalid_probability_sum"]}
        with self.assertRaisesRegex(jp.PolicyValidationError, "jev_invalid_probability_sum"):
            self.verify(FakeClient(bad_verdict))

    def test_invalid_category_does_not_relax_authorship_authority(self):
        def bad(response, questions):
            response["answers"]["f0000_category"]["probabilities"]["fact"] -= 0.01
            response["answers"]["f0000_statement_kind"] = choice(questions["f0000_statement_kind"], "user_explicit")
        checkpoint = {}
        with self.assertRaisesRegex(jp.PolicyValidationError, "unverified_authorship"):
            self.verify(FakeClient(bad), checkpoint=checkpoint)
        self.assertFalse(checkpoint)

    def test_category_diagnostics_are_recomputed_on_cache_replay_without_new_call(self):
        def invalid(response, questions):
            response["answers"]["f0000_category"]["probabilities"]["fact"] -= 0.01
        checkpoint = {}
        first = self.verify(FakeClient(invalid), checkpoint=checkpoint)
        key = next(iter(checkpoint))
        preserved = copy.deepcopy(checkpoint[key]["response"]["answers"]["f0000_category"])
        # Even a forged checksum-consistent diagnostic cannot hide invalid math.
        checkpoint[key]["response"]["diagnostics"] = {}
        checkpoint[key]["checkpoint_digest"] = jp._digest(checkpoint[key]["response"])
        replay_client = FakeClient()
        replay = self.verify(replay_client, checkpoint=checkpoint)
        self.assertFalse(replay_client.calls)
        self.assertEqual(replay["content"], first["content"])
        self.assertEqual(replay["decisions"]["facts"][0]["answers"]["category"], preserved)
        self.assertIn("category_invalid_probability_sum", replay["decisions"]["facts"][0]["flags"])
        # Valid categories likewise ignore provider-declared invalid markers.
        valid = self.screen(FakeClient(lambda response, questions: response.update(diagnostics={"category": ["category_invalid_probability_sum"]})))
        self.assertEqual(valid["content"]["category"], "fact")
        self.assertNotIn("category_invalid", valid["decisions"]["flags"])

    def test_generic_preference_still_depends_on_model_referent_judgment_not_text_override(self):
        text = "今后所有月度摘要，我长期偏好纯文本格式。"
        context = {**CONTEXT, "authorship_verified": True}
        accepted = self.screen(FakeClient(), request(text, context))
        self.assertEqual(accepted["content"]["decision"], "keep")
        self.assertEqual(accepted["content"]["evidence"], [text])
        uncertain = self.screen(FakeClient(lambda response, questions: response["answers"]["missing_referent"].update(noul=0.56)), request(text, context))
        self.assertEqual(uncertain["content"]["decision"], "needs_evidence")
        self.assertEqual(uncertain["content"]["reason"], "typed_missing_referent")


if __name__ == "__main__":
    unittest.main()
