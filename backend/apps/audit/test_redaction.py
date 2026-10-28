import base64
import datetime
import json
import uuid

from django.test import SimpleTestCase

from apps.audit.redaction import MAX_DEPTH, REDACTED, TRUNCATED, redact


def _b64(data: dict) -> str:
    raw = json.dumps(data).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def fake_jwt() -> str:
    """A JWT-shaped string built at runtime, signed with nothing real."""
    return ".".join([_b64({"alg": "none"}), _b64({"sub": "1"}), "c2lnbmF0dXJl"])


def fake_gh_token() -> str:
    return "ghp_" + "Ab1Cd2Ef3G" * 4


def fake_opaque() -> str:
    return "q9Zx" * 12


class RedactKeysTests(SimpleTestCase):
    def test_sensitive_keys_are_redacted_whatever_the_value(self):
        data = {
            "password": "x",
            "Password": "x",
            "new_password": "x",
            "API-Key": "x",
            "apiKey": "x",
            "access_token": "x",
            "client_secret": "x",
            "Authorization": "x",
            "cookie": "x",
            "Set-Cookie": "x",
            "private_key": "x",
            "key": "x",
            "csrfmiddlewaretoken": "x",
        }
        result = redact(data)
        self.assertEqual(set(result), set(data))
        self.assertTrue(all(v == REDACTED for v in result.values()), result)

    def test_sensitive_key_hides_non_string_values_too(self):
        result = redact({"token": {"a": 1}, "secret": [1, 2], "password": 12345})
        self.assertEqual(
            result, {"token": REDACTED, "secret": REDACTED, "password": REDACTED}
        )

    def test_nested_dicts_and_lists(self):
        data = {
            "changes": {
                "status": {"from": "Open", "to": "Closed"},
                "headers": {"Authorization": "x", "Accept": "json"},
            },
            "items": [
                {"name": "a", "password": "x"},
                [{"api_key": "x"}, "plain"],
                ("t", {"token": "x"}),
            ],
        }
        result = redact(data)
        self.assertEqual(result["changes"]["status"], {"from": "Open", "to": "Closed"})
        self.assertEqual(
            result["changes"]["headers"], {"Authorization": REDACTED, "Accept": "json"}
        )
        self.assertEqual(result["items"][0], {"name": "a", "password": REDACTED})
        self.assertEqual(result["items"][1], [{"api_key": REDACTED}, "plain"])
        self.assertEqual(result["items"][2], ["t", {"token": REDACTED}])

    def test_input_is_not_mutated(self):
        data = {"password": "x", "nested": {"token": "y", "ok": "z"}}
        snapshot = json.loads(json.dumps(data))
        redact(data)
        self.assertEqual(data, snapshot)


class RedactValuesTests(SimpleTestCase):
    def test_jwt_under_an_innocent_key(self):
        self.assertEqual(redact({"note": fake_jwt()}), {"note": REDACTED})

    def test_jwt_inside_a_sentence(self):
        text = f"user pasted {fake_jwt()} into the form"
        result = redact(text)
        self.assertNotIn(fake_jwt(), result)
        self.assertTrue(result.startswith("user pasted "))
        self.assertTrue(result.endswith(" into the form"))

    def test_bearer_header_value(self):
        result = redact({"title": "Bearer " + fake_opaque()})
        self.assertEqual(result, {"title": "Bearer " + REDACTED})

    def test_known_token_prefix_in_free_text(self):
        result = redact("my token is " + fake_gh_token() + " please help")
        self.assertNotIn("ghp_", result)
        self.assertIn(REDACTED, result)

    def test_inline_key_value_pairs(self):
        result = redact("login failed, password=hunter2 and api_key: abc123")
        self.assertNotIn("hunter2", result)
        self.assertNotIn("abc123", result)
        self.assertIn("password=" + REDACTED, result)

    def test_long_opaque_string(self):
        self.assertEqual(redact(fake_opaque()), REDACTED)
        self.assertEqual(redact({"title": fake_opaque()}), {"title": REDACTED})

    def test_pem_private_key(self):
        pem = "-----BEGIN PRIVATE KEY-----\nabc\ndef\n-----END PRIVATE KEY-----"
        self.assertEqual(redact("see " + pem + " ok"), "see " + REDACTED + " ok")

    def test_redacted_marker_is_stable(self):
        self.assertEqual(redact(redact({"password": "x"})), {"password": REDACTED})


class RedactFalsePositiveTests(SimpleTestCase):
    def test_ordinary_values_are_untouched(self):
        data = {
            "title": "Lesson page shows a 404 for the second exercise",
            "status": "In Progress",
            "issue_type": "UI",
            "author": "someone",
            "keyboard": "qwerty",
            "monkey": "see",
            "tokenizer": None,
            "count": 3,
            "ratio": 0.5,
            "is_verified": True,
            "url": "https://example.com/lessons/intro-to-git?page=2",
            "slug": "a-very-long-lesson-slug-with-only-words-and-hyphens-in-it",
        }
        result = redact(data)
        # "tokenizer" contains "token", so its value is hidden on purpose.
        expected = dict(data, tokenizer=REDACTED)
        self.assertEqual(result, expected)

    def test_uuid_is_not_treated_as_a_token(self):
        value = str(uuid.uuid4())
        self.assertEqual(redact({"request": value}), {"request": value})

    def test_long_words_without_digits_are_kept(self):
        value = "supercalifragilisticexpialidocious" * 2
        self.assertEqual(redact(value), value)

    def test_short_mixed_strings_are_kept(self):
        self.assertEqual(redact("abc123def456"), "abc123def456")

    def test_words_that_only_mention_token_are_kept(self):
        text = "the token refresh flow is slow"
        self.assertEqual(redact(text), text)


class RedactShapeTests(SimpleTestCase):
    def test_non_json_values_become_strings(self):
        when = datetime.datetime(2026, 1, 2, 3, 4, 5)
        self.assertEqual(redact({"when": when}), {"when": str(when)})
        json.dumps(redact({"when": when, "ids": {1, 2}, 5: "int key"}))

    def test_deep_structures_are_cut_off(self):
        data = leaf = {}
        for _ in range(MAX_DEPTH + 5):
            leaf["next"] = {}
            leaf = leaf["next"]
        text = json.dumps(redact(data))
        self.assertIn(TRUNCATED, text)

    def test_self_referencing_structure_terminates(self):
        data = {"a": 1}
        data["self"] = data
        self.assertIn(TRUNCATED, json.dumps(redact(data)))

    def test_very_long_strings_are_capped(self):
        result = redact("word " * 1000)
        self.assertLess(len(result), 600)
