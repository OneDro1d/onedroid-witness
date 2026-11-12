"""The normalisation rules of the contract (3.3, 3d.1, 3d.3, 3e.3, 3e.4), each as the failure that found it."""
import unittest

from onedroid_witness import normalise

ROW = {"id": "C-1", "kind": "figure", "text": "x", "proofs": [{"url": "https://a", "quote": "q"}, {"url": "https://b", "quote": "r"}], "counter": []}
ROW_AGAINST = {"id": "C-2", "kind": "figure", "text": "x", "proofs": [], "counter": [{"url": "https://c", "quote": "s"}]}


class ChatAnswers(unittest.TestCase):
    def test_plain_json_evidenced(self):
        body, ok = normalise.chat_answer('{"verdict": "EVIDENCED", "on": {"proofs": [1], "counter": []}, "note": "the source says it"}', "stop", ROW)
        self.assertTrue(ok)
        self.assertEqual(body["verdict"], "EVIDENCED")
        self.assertEqual(body["on"], {"proofs": [1], "counter": []})

    def test_code_fence_is_stripped(self):  # 3d.1: Haiku through Bedrock fenced every answer
        text = '```json\n{"verdict": "NO EVIDENCE PUBLISHED", "on": {"proofs": [], "counter": []}, "note": "nothing carries it"}\n```'
        body, ok = normalise.chat_answer(text, "stop", ROW)
        self.assertTrue(ok)
        self.assertEqual(body["verdict"], "NO EVIDENCE PUBLISHED")

    def test_empty_content_names_the_finish_reason(self):  # 3e.2: the budget spent on hidden reasoning
        body, ok = normalise.chat_answer("", "length", ROW)
        self.assertFalse(ok)
        self.assertEqual(body["verdict"], "UNDECIDED")
        self.assertEqual(body["note"], "no content returned (finish: length)")

    def test_not_json_is_not_parseable(self):
        body, ok = normalise.chat_answer("The claim is evidenced by source 1.", "stop", ROW)
        self.assertFalse(ok)
        self.assertEqual(body["note"], normalise.NOT_PARSEABLE)

    def test_truncated_json_is_not_parseable(self):
        body, ok = normalise.chat_answer('{"verdict": "EVIDENCED", "on": {"proofs": [0],', "length", ROW)
        self.assertEqual(body["note"], normalise.NOT_PARSEABLE)

    def test_vocabulary_word_outside_gets_its_own_note(self):  # 3e.3: ministral wrote NO_EVIDENCE_PUBLISHED
        body, ok = normalise.chat_answer('{"verdict": "NO_EVIDENCE_PUBLISHED", "on": {"proofs": [], "counter": []}, "note": "n"}', "stop", ROW)
        self.assertFalse(ok)
        self.assertIn("not in the vocabulary: NO_EVIDENCE_PUBLISHED", body["note"])

    def test_shape_key_outside_gets_its_own_note(self):  # 3e.3: glm wrote "proof"
        body, ok = normalise.chat_answer('{"verdict": "EVIDENCED", "on": {"proof": [0], "counter": []}, "note": "n"}', "stop", ROW)
        self.assertFalse(ok)
        self.assertIn("shape is not the shape: proof", body["note"])

    def test_nonexistent_index_gets_its_own_note(self):  # 3e.3: nova named counter [0] on a row with no AGAINST
        body, ok = normalise.chat_answer('{"verdict": "CONTRADICTED", "on": {"proofs": [], "counter": [0]}, "note": "it contradicts"}', "stop", ROW)
        self.assertFalse(ok)
        self.assertIn("candidate index that does not exist", body["note"])
        self.assertIn("the row has 2 FOR and 0 AGAINST", body["note"])

    def test_evidenced_naming_none_is_undecided_with_the_sentence_kept(self):  # 3d.2
        body, ok = normalise.chat_answer('{"verdict": "EVIDENCED", "on": {"proofs": [], "counter": []}, "note": "the page says so"}', "stop", ROW)
        self.assertFalse(ok)
        self.assertTrue(body["note"].startswith("the model answered EVIDENCED and named no proof: the page says so"))

    def test_contradicted_carries_confidence(self):
        body, ok = normalise.chat_answer('{"verdict": "CONTRADICTED", "on": {"proofs": [], "counter": [0]}, "note": "the source says the opposite"}', "stop", ROW_AGAINST)
        self.assertTrue(ok)
        self.assertEqual(body["confidence"], "high")
        body, _ = normalise.chat_answer('{"verdict": "CONTRADICTED", "on": {"proofs": [], "counter": [0]}, "note": "low confidence: the figures differ slightly"}', "stop", ROW_AGAINST)
        self.assertEqual(body["confidence"], "low")

    def test_no_note_is_refused(self):
        body, ok = normalise.chat_answer('{"verdict": "EVIDENCED", "on": {"proofs": [0], "counter": []}}', "stop", ROW)
        self.assertFalse(ok)
        self.assertEqual(body["note"], "the model gave no note")

    def test_boolean_index_is_not_an_index(self):
        body, ok = normalise.chat_answer('{"verdict": "EVIDENCED", "on": {"proofs": [true], "counter": []}, "note": "n"}', "stop", ROW)
        self.assertFalse(ok)


class DecisionAnswers(unittest.TestCase):
    def test_argmax_names_the_best_candidate(self):  # 3e.4: a threshold cost clef-flash 29 verdicts; Jev C-002 chose EVIDENCED at 0.45/0.33
        answers = {"verdict": {"type": "choice", "choice": "EVIDENCED", "probabilities": {"EVIDENCED": 0.87, "CONTRADICTED": 0, "NO_EVIDENCE_PUBLISHED": 0.06, "UNDECIDED": 0.07}, "confidence": 0.83},
                   "proof_0": {"type": "noul", "noul": 0.45}, "proof_1": {"type": "noul", "noul": 0.33}}
        body, ok = normalise.decision_answer(answers, ROW)
        self.assertTrue(ok)
        self.assertEqual(body["on"], {"proofs": [0], "counter": []})
        self.assertIn("decision model, no text", body["note"])
        self.assertIn("FOR[0] 0.45", body["note"])

    def test_contradicted_confidence_from_choice_confidence(self):
        answers = {"verdict": {"type": "choice", "choice": "CONTRADICTED", "probabilities": {}, "confidence": 0.9}, "counter_0": {"type": "noul", "noul": 0.7}}
        body, ok = normalise.decision_answer(answers, ROW_AGAINST)
        self.assertTrue(ok)
        self.assertEqual(body["confidence"], "high")
        answers["verdict"]["confidence"] = 0.5
        body, _ = normalise.decision_answer(answers, ROW_AGAINST)
        self.assertEqual(body["confidence"], "low")

    def test_evidenced_without_a_for_candidate_is_undecided(self):
        answers = {"verdict": {"type": "choice", "choice": "EVIDENCED", "probabilities": {}, "confidence": 0.9}}
        body, ok = normalise.decision_answer(answers, ROW_AGAINST)
        self.assertFalse(ok)
        self.assertEqual(body["verdict"], "UNDECIDED")

    def test_word_outside_vocabulary(self):
        body, ok = normalise.decision_answer({"verdict": {"type": "choice", "choice": "MAYBE"}}, ROW)
        self.assertFalse(ok)
        self.assertIn("not in the vocabulary: MAYBE", body["note"])

    def test_missing_verdict_question(self):
        body, ok = normalise.decision_answer({"proof_0": {"noul": 0.9}}, ROW)
        self.assertFalse(ok)


class RowRules(unittest.TestCase):
    def test_nep_on_all_copy_none_is_undecided(self):  # 3d.3
        body = {"verdict": "NO EVIDENCE PUBLISHED", "on": {"proofs": [], "counter": []}, "note": "nothing shown"}
        out = normalise.apply_row_rules(body, ROW, True)
        self.assertEqual(out["verdict"], "UNDECIDED")
        self.assertTrue(out["note"].startswith("the candidates were fetched and not saved"))
        self.assertEqual(normalise.apply_row_rules(body, ROW, False), body)

    def test_passthrough(self):  # 3.5
        self.assertEqual(normalise.passthrough({"id": "C-9", "on_request": {"holder": "x"}})["verdict"], "EVIDENCE AVAILABLE ON REQUEST")
        self.assertEqual(normalise.passthrough({"id": "C-9", "withdrawn": True})["verdict"], "WITHDRAWN")
        self.assertEqual(normalise.passthrough({"id": "C-9", "kind": "promise"})["verdict"], "UNDECIDED")
        self.assertIsNone(normalise.passthrough(ROW))


if __name__ == "__main__":
    unittest.main()
