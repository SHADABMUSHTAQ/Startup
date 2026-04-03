import ast
import os
import sys

def verify_syntax(directory):
    errors = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            if file.endswith(".py"):
                path = os.path.join(root, file)
                try:
                    with open(path, "r", encoding="utf-8") as f:
                        source = f.read()
                    ast.parse(source)
                except SyntaxError as e:
                    errors.append(f"SYNTAX ERROR in {path}: {e}")
                except Exception as e:
                    errors.append(f"READ ERROR in {path}: {e}")
    return errors

if __name__ == "__main__":
    target_dir = sys.argv[1] if len(sys.argv) > 1 else "app"
    syntax_errors = verify_syntax(target_dir)
    if syntax_errors:
        for err in syntax_errors:
            print(err)
        sys.exit(1)
    else:
        print("✅ AST Parsing: 100% Syntax Correct.")
        sys.exit(0)
