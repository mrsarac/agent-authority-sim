import unittest
import os
import json
import hashlib
import shutil
import io
import contextlib
import tempfile
import sys
from scripts.verify_spec_lock import verify_bundle

class FalseyCallable:
    def __init__(self):
        self.count = 0
    def __call__(self, data):
        self.count += 1
    def __bool__(self):
        return False

class TestSpecLock(unittest.TestCase):
    def setUp(self):
        self.sentinel_called_count = 0
        self.real_spec_dir = "spec/v0.1.0"
        self.real_root = "."

        self.tmp_dir_obj = tempfile.TemporaryDirectory()
        self.tmp_root = self.tmp_dir_obj.name

        self.spec_rel_path = "spec/v0.1.0"
        self.temp_spec_dir = os.path.join(self.tmp_root, self.spec_rel_path)
        os.makedirs(self.temp_spec_dir)

        for item in os.listdir(self.real_spec_dir):
            s = os.path.join(self.real_spec_dir, item)
            d = os.path.join(self.temp_spec_dir, item)
            if os.path.isfile(s):
                shutil.copy2(s, d)

        shutil.copy2(os.path.join(self.real_root, "requirements.lock"),
                     os.path.join(self.tmp_root, "requirements.lock"))

        with open(os.path.join(self.real_spec_dir, "spec-lock.json"), "r") as f:
            self.expected_lock_data = json.load(f)

    def tearDown(self):
        self.tmp_dir_obj.cleanup()

    def parser_sentinel(self, data):
        self.sentinel_called_count += 1
        return data

    def test_clean_real_bundle_accepted(self):
        result = verify_bundle(self.temp_spec_dir, self.parser_sentinel)
        self.assertTrue(result)
        self.assertEqual(self.sentinel_called_count, 3)

    def test_altered_requirements_lock_rejected(self):
        req_path = os.path.join(self.tmp_root, "requirements.lock")
        with open(req_path, "ab") as f:
            f.write(b"\n# hostile")

        result = verify_bundle(self.temp_spec_dir, self.parser_sentinel)
        self.assertFalse(result)
        self.assertEqual(self.sentinel_called_count, 0)

    def test_tampered_requirements_lock_sha256_rejected(self):
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = self.expected_lock_data.copy()
        data["requirements_lock_sha256"] = "a" * 64
        with open(lock_path, "w") as f:
            json.dump(data, f)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_wrong_python_version_rejected(self):
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = self.expected_lock_data.copy()
        data["python_version"] = "3.12.0"
        with open(lock_path, "w") as f:
            json.dump(data, f)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_missing_top_level_key_rejected(self):
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = self.expected_lock_data.copy()
        del data["python_version"]
        with open(lock_path, "w") as f:
            json.dump(data, f)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_extra_top_level_key_rejected(self):
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = self.expected_lock_data.copy()
        data["extra_key"] = "bad"
        with open(lock_path, "w") as f:
            json.dump(data, f)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_whitespace_tamper_rejected(self):
        target_file = os.path.join(self.temp_spec_dir, "design.md")
        with open(target_file, "ab") as f:
            f.write(b" ")

        result = verify_bundle(self.temp_spec_dir, self.parser_sentinel)
        self.assertFalse(result)
        self.assertEqual(self.sentinel_called_count, 0)

    def test_hash_tamper_rejected(self):
        target_file = os.path.join(self.temp_spec_dir, "design.md")
        with open(target_file, "r+b") as f:
            f.seek(0)
            original = f.read(1)
            f.seek(0)
            f.write(bytes([original[0] ^ 0xFF]))

        result = verify_bundle(self.temp_spec_dir, self.parser_sentinel)
        self.assertFalse(result)
        self.assertEqual(self.sentinel_called_count, 0)

    def test_missing_file_rejected(self):
        os.remove(os.path.join(self.temp_spec_dir, "design.md"))
        result = verify_bundle(self.temp_spec_dir, self.parser_sentinel)
        self.assertFalse(result)
        self.assertEqual(self.sentinel_called_count, 0)

    def test_extra_file_rejected(self):
        with open(os.path.join(self.temp_spec_dir, "extra.txt"), "w") as f:
            f.write("hostile")
        result = verify_bundle(self.temp_spec_dir, self.parser_sentinel)
        self.assertFalse(result)
        self.assertEqual(self.sentinel_called_count, 0)

    def test_adversarial_duplicate_name(self):
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = json.loads(json.dumps(self.expected_lock_data))
        data["files"].append(data["files"][0])
        with open(lock_path, "w") as f:
            json.dump(data, f)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_adversarial_extra_entry_key(self):
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = json.loads(json.dumps(self.expected_lock_data))
        data["files"][0]["extra"] = "bad"
        with open(lock_path, "w") as f:
            json.dump(data, f)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_adversarial_bool_size(self):
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = json.loads(json.dumps(self.expected_lock_data))
        data["files"][0]["size"] = True
        with open(lock_path, "w") as f:
            json.dump(data, f)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_adversarial_malformed_digest(self):
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = json.loads(json.dumps(self.expected_lock_data))
        data["files"][0]["sha256"] = data["files"][0]["sha256"].upper()
        with open(lock_path, "w") as f:
            json.dump(data, f)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_adversarial_invalid_json_but_correct_hash(self):
        target = "valid-contracts.json"
        path = os.path.join(self.temp_spec_dir, target)
        with open(path, "w") as f:
            f.write("{ invalid json")

        new_content = b"{ invalid json"
        new_size = len(new_content)
        new_hash = hashlib.sha256(new_content).hexdigest()

        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = json.loads(json.dumps(self.expected_lock_data))
        for entry in data["files"]:
            if entry["name"] == target:
                entry["size"] = new_size
                entry["sha256"] = new_hash

        with open(lock_path, "w") as f:
            json.dump(data, f)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_adversarial_symlink_rejection(self):
        target = os.path.join(self.temp_spec_dir, "design.md")
        os.remove(target)
        os.symlink("README.md", target)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_adversarial_requirements_symlink_rejection(self):
        req_path = os.path.join(self.tmp_root, "requirements.lock")
        os.remove(req_path)
        os.symlink("spec/v0.1.0/README.md", req_path)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

    def test_no_hostile_output_leak(self):
        hostile_name = "hostile_<script>alert(1)</script>_path"
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        data = json.loads(json.dumps(self.expected_lock_data))
        data["files"][0]["name"] = hostile_name
        with open(lock_path, "w") as f:
            json.dump(data, f)

        f = io.StringIO()
        with contextlib.redirect_stdout(f):
            result = verify_bundle(self.temp_spec_dir)

        output = f.getvalue()
        self.assertFalse(result)
        if output:
            self.assertIn("SPEC_LOCK_INVALID", output)
            self.assertNotIn(hostile_name, output)

    def test_no_absolute_paths_in_lock(self):
        lock_path = os.path.join(self.real_spec_dir, "spec-lock.json")
        with open(lock_path, "r") as f:
            lock_content = f.read()
        self.assertNotIn("/Users/", lock_content)
        self.assertNotIn("\\", lock_content)

    def test_regression_falsey_callable(self):
        cb = FalseyCallable()
        result = verify_bundle(self.temp_spec_dir, cb)
        self.assertTrue(result)
        self.assertEqual(cb.count, 3)

    def test_regression_spec_lock_symlink_rejection(self):
        lock_path = os.path.join(self.temp_spec_dir, "spec-lock.json")
        backup_path = os.path.join(self.temp_spec_dir, "spec-lock.json.bak")
        os.rename(lock_path, backup_path)
        os.symlink("spec-lock.json.bak", lock_path)

        result = verify_bundle(self.temp_spec_dir)
        self.assertFalse(result)

if __name__ == "__main__":
    unittest.main()
