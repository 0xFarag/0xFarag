import copy
import json
import os
import unittest
from unittest.mock import patch
from authzledger.credentials import CredentialResolver
from authzledger.model import ContractError
from authzledger.engine import run
from test_execution import service, specification


class CredentialTests(unittest.TestCase):
    def test_session_binding_resolves_without_environment_and_preserves_source(self):
        with service() as (target, _):
            source = specification(target)
            before = copy.deepcopy(source)
            resolver = CredentialResolver()
            metadata = resolver.bind_session("EXECUTION_TEST_SECRET", "Bearer ephemeral-session-secret", identity="owner", target_origin=target)
            with patch.dict(os.environ, {}, clear=True):
                result = run(source, credential_resolver=resolver)
            self.assertEqual(result["summary"]["pass"], 1)
            self.assertEqual(source, before)
            self.assertNotIn("ephemeral-session-secret", json.dumps(result) + json.dumps(metadata) + repr(resolver))
            self.assertEqual(metadata["binding"], "declared")
            resolver.clear()
            with patch.dict(os.environ, {}, clear=True), self.assertRaises(ContractError):
                resolver.resolve_contract(source)

    def test_session_scope_rejects_another_identity_or_origin(self):
        resolver = CredentialResolver()
        resolver.bind_session("SESSION_REF", "credential-secret", identity="owner", target_origin="https://example.test")
        for identity, origin in (("peer", "https://example.test"), ("owner", "https://other.test")):
            with self.subTest(identity=identity, origin=origin), self.assertRaises(ContractError):
                resolver.resolve("session://SESSION_REF", identity=identity, target_origin=origin)
        with self.assertRaises(ContractError):
            resolver.bind_session("SESSION_REF", "other-value", identity="peer", target_origin="https://example.test")

    def test_rotation_uses_random_generation_and_old_generation_is_rejected(self):
        resolver = CredentialResolver()
        first = resolver.bind_session("SESSION_REF", "same-secret", identity="owner", target_origin="https://example.test")
        second = resolver.bind_session("SESSION_REF", "same-secret", identity="owner", target_origin="https://example.test")
        self.assertNotEqual(first["generation"], second["generation"])
        with self.assertRaises(ContractError):
            resolver.resolve("session://SESSION_REF", identity="owner", target_origin="https://example.test", generation=first["generation"])
        self.assertNotIn("same-secret", json.dumps(resolver.metadata()))
        self.assertNotIn("sha256", json.dumps(resolver.metadata()))

    def test_env_resolution_and_resolve_many_are_explicit_and_offline(self):
        resolver = CredentialResolver()
        scope = {"identity": "owner", "target_origin": "https://example.test"}
        with patch.dict(os.environ, {"CREDENTIAL_TEST_ENV": "value"}):
            self.assertEqual(resolver.resolve_many(["env://CREDENTIAL_TEST_ENV"], scope), {"env://CREDENTIAL_TEST_ENV": "value"})
        for reference in ("file:///etc/passwd", "session://unknown", "env://INVALID NAME"):
            with self.subTest(reference=reference), self.assertRaises(ContractError):
                resolver.resolve(reference, **scope)

    def test_header_injection_and_secret_errors_are_sanitized(self):
        resolver = CredentialResolver()
        for value in ("Bearer secret\r\nHost: outside", "secret\x00", "", "x" * 16385, "\u2603"):
            with self.subTest(length=len(value)), self.assertRaises(ContractError) as error:
                resolver.bind_session("SESSION_REF", value, identity="owner", target_origin="https://example.test")
            self.assertNotIn("Bearer secret", str(error.exception))


if __name__ == "__main__":
    unittest.main()
