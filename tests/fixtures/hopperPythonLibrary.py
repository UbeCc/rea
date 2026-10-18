#!/usr/bin/env python3
"""Exercise the helper's Hopper PythonFinder preflight with fake interpreters."""
import argparse
import importlib.util
import json
import os
import stat
import sys
import tempfile

helper_path = sys.argv[1]
spec = importlib.util.spec_from_file_location("hopper_demo_x11", helper_path)
if spec is None or spec.loader is None:
    raise SystemExit("unable to load helper")
helper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helper)


def fake_interpreter(directory: str, name: str, soname: str) -> str:
    """Answer Hopper's sysconfig query, then load only an existing library."""
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as script:
        script.write(
            "#!/bin/sh\n"
            'if [ "$1" = "-uc" ]; then\n'
            f'  printf "%s\\n%s\\n" "{directory}" "{soname}"\n'
            "  exit 0\n"
            "fi\n"
            '[ -f "$3" ] || exit 3\n'
        )
    os.chmod(path, stat.S_IRWXU)
    return path


def outcome(candidates: list[str]) -> dict[str, object]:
    args = argparse.Namespace(python_interpreters=candidates)
    try:
        return {"ok": True, "library": helper.check_python_library(args)}
    except helper.AdapterFailure as failure:
        return {
            "ok": False,
            "code": helper.failure_name(failure.code),
            "reason": failure.reason,
            "library": failure.python_library,
        }


with tempfile.TemporaryDirectory() as directory:
    missing = fake_interpreter(directory, "missing", "libpython3.99.so.1.0")
    shared = fake_interpreter(directory, "shared", "libpython3.98.so.1.0")
    static = fake_interpreter(directory, "static", "None")
    open(os.path.join(directory, "libpython3.98.so.1.0"), "wb").close()
    result = {
        "missing": outcome([os.path.join(directory, "absent"), missing, shared]),
        "present": outcome([shared, missing]),
        "static": outcome([static]),
        "no_interpreter": outcome([os.path.join(directory, "absent")]),
    }
    print(json.dumps(result, sort_keys=True).replace(directory, "<dir>"))
