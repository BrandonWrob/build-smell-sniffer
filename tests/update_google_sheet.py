import time
import sys
import os
import tempfile
from pathlib import Path

import gspread
from gspread.exceptions import APIError

from secure_linter import lint_pom, lint_gradle, lint_make, lint_cmake, check_if_cmake
from secure_linter.makefile_analyzer import looks_like_makefile

def retry(fn, retries=5, delay=1, backoff=2):
    last_exc = None
    for attempt in range(1, retries + 1):
        try:
            return fn()
        except APIError as e:
            code = getattr(e.response, "status_code", None)
            if code == 503 and attempt < retries:
                wait = delay * (backoff ** (attempt - 1))
                print(f"⚠️  API 503; retrying in {wait}s (#{attempt}/{retries})")
                time.sleep(wait)
                continue
            raise
    raise last_exc


def run_linter(fp: str):

    name = Path(fp).name
    low = name.lower()

    if low.endswith(".xml"):
        return lint_pom(fp)

    if low.endswith(".gradle") or low.endswith(".gradle.kts"):
        return lint_gradle(fp)

    if "cmakelists.txt" in low or check_if_cmake(fp):
        return lint_cmake(fp)

    if (
        low == "makefile"
        or low.endswith(".mk")
        or "makefile" in low
        or looks_like_makefile(fp)
    ):
        return lint_make(fp)

    raise ValueError(f"Unsupported build system for {name!r}")


def main():
    SPREADSHEET_ID = "{GOOGLE_SHEET_ID}"
    base = Path(__file__).resolve().parents[1]
    creds = base / "{SERVICE_ACCOUNT_JSON}"
    tests_dir = base / "test_build_scripts"

    # sanity
    if not creds.exists():
        print(f"❌ Missing service account JSON: {creds}", file=sys.stderr)
        sys.exit(1)
    if not tests_dir.is_dir():
        print(f"❌ test_build_scripts not found at {tests_dir}", file=sys.stderr)
        sys.exit(1)

    gc = gspread.service_account(filename=str(creds))
    sheet = retry(lambda: gc.open_by_key(SPREADSHEET_ID)).sheet1

    retry(lambda: sheet.clear())
    retry(lambda: sheet.append_row(
        ["Script Name", "Results"],
        value_input_option="USER_ENTERED"
    ))

    for path in sorted(tests_dir.iterdir()):
        if not path.is_file():
            continue

        print(f"🔨 Linting {path.name}…")

        # make a temp copy *with the same suffix* so our dispatcher sees the right extension
        full_suffix = "".join(path.suffixes)   # e.g. ".gradle.kts", or ".xml", or ".txt", or ""
        tmp = tempfile.NamedTemporaryFile(delete=False, suffix=full_suffix)
        tmp.write(path.read_bytes())
        tmp.flush()
        tmp.close()
        temp_fp = tmp.name

        try:
            issues = run_linter(temp_fp)
            lines = [itm["issue"] for itm in issues]
        except ValueError as ve:
            print(f"↪️  Skipping {path.name}: {ve}")
            continue
        except Exception as e:
            lines = [f"Error running linter: {e}"]
        finally:
            # make sure the temp file is gone
            try:
                os.remove(temp_fp)
            except OSError:
                pass

        if not lines:
            lines = ["No issues found"]

        # upload, one issue per line in the cell
        retry(lambda: sheet.append_row(
            [path.name, "\n".join(lines)],
            value_input_option="USER_ENTERED"
        ))
        print(f"✅ Uploaded {path.name}")

    print("🎉 All done – your sheet now has all scripts!")


if __name__ == "__main__":
    main()
