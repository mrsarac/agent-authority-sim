import os
import json
import hashlib
import re
import sys

def verify_bundle(spec_dir, parser_callback=None):
    """
    Verifies the integrity of the spec bundle against spec-lock.json.
    """
    lock_path = os.path.join(spec_dir, "spec-lock.json")
    expected_names = (
        "authority-state-machine.md",
        "contracts.schema.json",
        "invalid-vectors.json",
        "design.md",
        "property-test-catalog.md",
        "valid-contracts.json"
    )
    json_files = ("contracts.schema.json", "valid-contracts.json", "invalid-vectors.json")

    try:
        if not os.path.isfile(lock_path) or os.path.islink(lock_path):
            raise ValueError()

        with open(lock_path, "rb") as f:
            lock_content = f.read()
            try:
                lock_data = json.loads(lock_content)
            except Exception:
                raise ValueError()

        expected_top_keys = {"schema_version", "python_version", "requirements_lock_sha256", "files"}
        if set(lock_data.keys()) != expected_top_keys:
            raise ValueError()

        if lock_data.get("schema_version") != "0.1.0":
            raise ValueError()

        py_ver = lock_data.get("python_version")
        if not isinstance(py_ver, str) or py_ver != "3.11.14":
            raise ValueError()

        current_py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
        if current_py_ver != "3.11.14":
            raise ValueError()

        req_sha = lock_data.get("requirements_lock_sha256")
        if not isinstance(req_sha, str) or not re.fullmatch(r"[0-9a-f]{64}", req_sha):
            raise ValueError()

        root_dir = os.path.dirname(os.path.dirname(spec_dir))
        req_file_path = os.path.join(root_dir, "requirements.lock")

        if not os.path.isfile(req_file_path) or os.path.islink(req_file_path):
             raise ValueError()

        with open(req_file_path, "rb") as f:
            req_content = f.read()

        actual_req_sha = hashlib.sha256(req_content).hexdigest()
        if actual_req_sha != req_sha:
            raise ValueError()

        locked_files = lock_data.get("files", [])
        if len(locked_files) != 6:
            raise ValueError()

        names_seen = set()
        verification_results = {}

        for entry in locked_files:
            if set(entry.keys()) != {"name", "size", "sha256"}:
                raise ValueError()

            name = entry.get("name")
            size = entry.get("size")
            sha256 = entry.get("sha256")

            if name in names_seen:
                raise ValueError()
            names_seen.add(name)

            if name not in expected_names:
                raise ValueError()

            if type(size) is not int or isinstance(size, bool):
                raise ValueError()
            if size < 0:
                raise ValueError()

            if not isinstance(sha256, str) or not re.fullmatch(r"[0-9a-f]{64}", sha256):
                raise ValueError()

            file_path = os.path.join(spec_dir, name)
            if not os.path.isfile(file_path) or os.path.islink(file_path):
                raise ValueError()

            with open(file_path, "rb") as f:
                content = f.read()

            if len(content) != size:
                raise ValueError()

            if hashlib.sha256(content).hexdigest() != sha256:
                raise ValueError()

            if name in json_files:
                verification_results[name] = content

        if names_seen != set(expected_names):
            raise ValueError()

        allowed_files = set(expected_names) | {"spec-lock.json", "README.md"}
        actual_files = set(os.listdir(spec_dir))
        if actual_files - allowed_files:
            raise ValueError()

        for name in json_files:
            try:
                data = json.loads(verification_results[name])
                if parser_callback is not None:
                    parser_callback(data)
            except Exception:
                raise ValueError()

        return True

    except Exception:
        print("SPEC_LOCK_INVALID")
        return False
