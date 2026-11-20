#!/usr/bin/env python3
"""Small JSON Schema subset, so the gate has no pip dependencies.

Supports only what factory schemas use: type, required, properties,
additionalProperties:false, items, enum, minimum, minLength. An unknown keyword
is an error rather than a silent pass: a validator that skips rules fails open.
"""
import sys

KEYWORDS = {"$schema", "$id", "title", "description", "type", "required", "properties",
            "additionalProperties", "items", "enum", "minimum", "minLength"}
TYPES = {"object": dict, "array": list, "string": str, "boolean": bool,
         "integer": int, "number": (int, float)}


def validate(value, schema, where="$"):
    """Return a list of errors; an empty list means valid."""
    unknown = set(schema) - KEYWORDS
    if unknown:
        return [f"{where}: unsupported schema keyword {sorted(unknown)}"]
    expected = schema.get("type")
    if expected:
        ok = isinstance(value, TYPES[expected])
        # bool is a subclass of int in Python; "1" and true must never pass as each other.
        if expected in ("integer", "number") and isinstance(value, bool):
            ok = False
        if not ok:
            return [f"{where}: expected {expected}"]
    errors = []
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{where}: not in enum")
    if "minimum" in schema and value < schema["minimum"]:
        errors.append(f"{where}: below minimum")
    if "minLength" in schema and len(value) < schema["minLength"]:
        errors.append(f"{where}: too short")
    if isinstance(value, dict):
        for key in schema.get("required", []):
            if key not in value:
                errors.append(f"{where}: missing {key}")
        props = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            for key in value:
                if key not in props:
                    errors.append(f"{where}: unexpected key")
        for key, sub in props.items():
            if key in value:
                errors += validate(value[key], sub, f"{where}.{key}")
    if isinstance(value, list) and "items" in schema:
        for i, item in enumerate(value):
            errors += validate(item, schema["items"], f"{where}[{i}]")
    return errors


def selftest():
    schema = {"type": "object", "required": ["a"], "additionalProperties": False,
              "properties": {"a": {"type": "boolean"},
                             "b": {"type": "array", "items": {"type": "integer", "minimum": 1}},
                             "c": {"type": "string", "enum": ["x"], "minLength": 1}}}
    cases = [
        ({"a": True, "b": [1], "c": "x"}, True, "valid object"),
        ({"a": "true"}, False, "string is not boolean"),
        ({"a": 1}, False, "int is not boolean"),
        ({"b": [1]}, False, "missing required"),
        ({"a": True, "z": 1}, False, "extra key refused"),
        ({"a": True, "b": [True]}, False, "bool is not integer"),
        ({"a": True, "b": [0]}, False, "below minimum"),
        ({"a": True, "c": "y"}, False, "enum enforced"),
        ([], False, "wrong root type"),
    ]
    failed = 0
    for value, want, name in cases:
        got = not validate(value, schema)
        failed += got != want
        print(("ok  " if got == want else "FAIL"), name)
    bad = validate({}, {"type": "object", "pattern": "x"})
    failed += not bad
    print("ok  " if bad else "FAIL", "unknown keyword fails closed")
    print(f"minischema selftest: {'FAILED' if failed else 'passed'} ({len(cases) + 1} cases)")
    return 1 if failed else 0


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        sys.exit(selftest())
    sys.exit("minischema.py is a library; only --selftest is runnable")
