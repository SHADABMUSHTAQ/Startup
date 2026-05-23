"""Compile-check every Python file in the codebase."""
import ast, os, sys

dirs_to_check = ["app", "workers", "tests"]
total = 0
passed = 0
failed = []

for d in dirs_to_check:
    if not os.path.isdir(d):
        continue
    for root, _, files in os.walk(d):
        for f in files:
            if not f.endswith(".py"):
                continue
            path = os.path.join(root, f)
            total += 1
            try:
                with open(path, "r", encoding="utf-8-sig") as fh:
                    source = fh.read()
                ast.parse(source)
                passed += 1
            except SyntaxError as e:
                failed.append((path, str(e)))
            except Exception as e:
                failed.append((path, str(e)))

print(f"[COMPILATION AUDIT] Total: {total} | Passed: {passed} | Failed: {len(failed)}")
if failed:
    for path, err in failed:
        print(f"  FAIL: {path} -> {err}")
    sys.exit(1)
else:
    print("[PASS] All Python files compile cleanly.")
