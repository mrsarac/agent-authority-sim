import unittest
import hashlib
import json
from authority_sim.canonical import canonical_bytes, sha256_digest

class TestCanonical(unittest.TestCase):
    def test_reject_floats(self):
        with self.assertRaises(TypeError):
            canonical_bytes(1.0)
        with self.assertRaises(TypeError):
            canonical_bytes(float('nan'))
        with self.assertRaises(TypeError):
            canonical_bytes(float('inf'))

    def test_reject_bytes(self):
        with self.assertRaises(TypeError):
            canonical_bytes(b"data")

    def test_reject_sets(self):
        with self.assertRaises(TypeError):
            canonical_bytes({1, 2, 3})

    def test_reject_non_string_keys(self):
        with self.assertRaises(TypeError):
            canonical_bytes({1: "value"})

    def test_reject_subclasses(self):
        class MyDict(dict): pass
        with self.assertRaises(TypeError):
            canonical_bytes(MyDict(a=1))

        class MyList(list): pass
        with self.assertRaises(TypeError):
            canonical_bytes(MyList([1, 2]))

    def test_key_sorting(self):
        d1 = {"b": 2, "a": 1}
        d2 = {"a": 1, "b": 2}
        # Assert input order differs
        self.assertNotEqual(list(d1.keys()), list(d2.keys()))

        b1 = canonical_bytes(d1)
        b2 = canonical_bytes(d2)
        self.assertEqual(b1, b2)
        self.assertEqual(b1, b'{"a":1,"b":2}')

    def test_unicode_preservation(self):
        # nfc: LATIN SMALL LETTER N WITH TILDE
        nfc = "\u00f1"
        # nfd: LATIN SMALL LETTER N + COMBINING TILDE
        nfd = "n\u0303"

        self.assertNotEqual(nfc, nfd)

        b_nfc = canonical_bytes(nfc)
        b_nfd = canonical_bytes(nfd)

        self.assertNotEqual(b_nfc, b_nfd)
        # Expected UTF-8 bytes
        self.assertEqual(b_nfc, b'"\xc3\xb1"')
        self.assertEqual(b_nfd, b'"n\xcc\x83"')

    def test_whitespace_preservation(self):
        ws = "  line\n  "
        b = canonical_bytes(ws)
        self.assertEqual(b, b'"  line\\n  "')

    def test_caller_mutation_protection(self):
        d = {"a": [1, 2]}
        b1 = canonical_bytes(d)
        d["a"].append(3)
        b2 = canonical_bytes(d)
        self.assertNotEqual(b1, b2)
        self.assertEqual(b1, b'{"a":[1,2]}')

    def test_sha256_digest(self):
        data = b"test"
        expected = "sha256:" + hashlib.sha256(data).hexdigest()
        self.assertEqual(sha256_digest(data), expected)

    def test_sha256_digest_reject_non_bytes(self):
        with self.assertRaises(TypeError):
            sha256_digest("string")

    def test_type_echo_privacy(self):
        # Requirement 9: hostile custom type must not appear in canonical exception
        class HostileType:
            def __repr__(self): return "SECRET_PATH_ECHO"
            def __str__(self): return "SECRET_PATH_ECHO"

        hostile = HostileType()
        with self.assertRaises(TypeError) as cm:
            canonical_bytes(hostile)
        msg = str(cm.exception)
        self.assertNotIn("HostileType", msg)
        self.assertNotIn("SECRET_PATH_ECHO", msg)
        self.assertEqual(msg, "Canonical serialization failed")

    def test_int_subclass_rejection(self):
        class MyInt(int): pass
        with self.assertRaises(TypeError):
            canonical_bytes(MyInt(1))

    def test_bytes_subclass_rejection(self):
        class MyBytes(bytes): pass
        with self.assertRaises(TypeError):
            sha256_digest(MyBytes(b"abc"))

    def test_turkish_and_emoji_utf8(self):
        # Turkish characters and Emoji UTF-8 assertion
        text = "I\u0131\u0130i\u011e\u011f\u015e\u015f\u00c7\u00e7\u00d6\u00f6\u00dc\u00fc \U0001F680"
        # IıİiĞğŞşÇçÖöÜü 🚀
        b = canonical_bytes(text)
        # Verify it's valid UTF-8 and exact
        self.assertEqual(b.decode('utf-8'), f'"{text}"')
        self.assertIn(b'\xc4\xb1', b) # ı
        self.assertIn(b'\xc4\xb0', b) # İ
        self.assertIn(b'\xf0\x9f\x9a\x80', b) # 🚀

if __name__ == "__main__":
    unittest.main()
