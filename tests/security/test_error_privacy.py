import unittest
from authority_sim.errors import Denied, ReasonCode

class TestErrorPrivacy(unittest.TestCase):
    def test_denied_immutable(self):
        d = Denied(ReasonCode.SCHEMA_INVALID)
        with self.assertRaises((AttributeError, TypeError)):
            d.code = "OTHER"

    def test_denied_slots(self):
        d = Denied(ReasonCode.SCHEMA_INVALID)
        with self.assertRaises((AttributeError, TypeError)):
            d.new_attr = 1

    def test_denied_repr_str_generic(self):
        code = ReasonCode.SCHEMA_INVALID
        d = Denied(code)
        self.assertIn(code.name, str(d))
        self.assertIn(code.name, repr(d))
        # Ensure it doesn't contain extra info (just checking it's generic enough)
        self.assertEqual(str(d), f"Denied(code={code.name})")

    def test_denied_invalid_code(self):
        with self.assertRaises((ValueError, TypeError)):
            Denied("INVALID_CODE_123")

    def test_denied_codes_no_mutable_codes_attr(self):
        # Requirement 16: no mutable class-level CODES set
        self.assertFalse(hasattr(Denied, 'CODES'), "Denied should not have CODES attribute")

    def test_denied_rejects_raw_string(self):
        # Requirement 7: raw string to Denied must reject; only exact ReasonCode enum member accepted
        with self.assertRaises(TypeError):
            Denied("SCHEMA_INVALID")

    def test_denied_accepts_enum(self):
        d = Denied(ReasonCode.SCHEMA_INVALID)
        self.assertEqual(d.code, ReasonCode.SCHEMA_INVALID)

    def test_denied_hidden_mutability(self):
        d = Denied(ReasonCode.SCHEMA_INVALID)
        # Requirement 8: Denied exposes no mutable __dict__, payload, args, cause
        self.assertFalse(hasattr(d, "__dict__"))
        self.assertFalse(hasattr(d, "payload"))
        self.assertFalse(hasattr(d, "args"))
        self.assertFalse(hasattr(d, "__cause__"))

    def test_error_no_echo(self):
        # This is more of a policy check, but we can verify Denied doesn't take extra args
        with self.assertRaises(TypeError):
            Denied(ReasonCode.SCHEMA_INVALID, "secret_payload")

if __name__ == "__main__":
    unittest.main()
