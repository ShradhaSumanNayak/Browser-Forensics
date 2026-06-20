import os
import sys
import ast

EXCLUDE_DIRS = {".venv", "venv", "build", "dist", "__pycache__", ".git"}

def should_skip(path):
    parts = set(path.split(os.sep))
    return bool(parts & EXCLUDE_DIRS)

def find_py_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        # modify dirnames in-place to skip excludes
        dirnames[:] = [d for d in dirnames if d not in EXCLUDE_DIRS]
        for f in filenames:
            if f.endswith('.py'):
                yield os.path.join(dirpath, f)

def check_file(path):
    try:
        with open(path, 'r', encoding='utf-8') as fh:
            src = fh.read()
        ast.parse(src, filename=path)
        return None
    except Exception as e:
        return str(e)

def main():
    root = os.getcwd()
    errors = []
    for p in find_py_files(root):
        if should_skip(p):
            continue
        err = check_file(p)
        if err:
            errors.append((p, err))

    if errors:
        print(f"Syntax check found {len(errors)} file(s) with errors:\n")
        for path, msg in errors:
            print(f"--- {path} ---")
            print(msg)
            print()
        sys.exit(1)
    else:
        print("Syntax check: no syntax errors found in Python files.")
        sys.exit(0)

if __name__ == '__main__':
    main()
