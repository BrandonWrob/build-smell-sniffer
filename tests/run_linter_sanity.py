import os
import csv
import tempfile

from secure_linter import lint_file_to_record


BASE = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                    os.pardir,
                                    "Linters sanity check"))

BUILD_DIRS = {
    "Maven": "maven",
    "Gradle": "gradle",
    "Make": "make",
    "Cmake": "cmake",
}


def main():
    csv_path = "linter_results.csv"
    with open(csv_path, "w", newline="", encoding="utf-8") as csvf:
        writer = csv.DictWriter(csvf, fieldnames=[
            "build_system", "filename", "smells", "status"
        ])
        writer.writeheader()

        for human, bs in BUILD_DIRS.items():
            folder = os.path.join(BASE, human)
            if not os.path.isdir(folder):
                print(f"⚠️  Skipping missing folder {folder!r}")
                continue

            print(f"\n=== {human} ===")
            for fname in sorted(os.listdir(folder)):
                path = os.path.join(folder, fname)
                if not os.path.isfile(path):
                    continue

                with open(path, "rb") as src:
                    data = src.read()
                tmp = tempfile.NamedTemporaryFile(delete=False)
                tmp.write(data)
                tmp.flush()
                tmp.close()

                try:
                    rec = lint_file_to_record(tmp.name, explicit_build_system=bs)
                    smells = rec.get("smells", [])
                    out = ",".join(smells) if smells else "(no smells)"
                    status = "OK"
                    print(f"{fname}: {out}")
                except Exception as e:
                    out = ""
                    status = f"ERROR: {e}"
                    print(f"{fname}: ERROR ({e})")
                finally:
                    try:
                        os.remove(tmp.name)
                    except OSError:
                        pass

                writer.writerow({
                    "build_system": human,
                    "filename":     fname,
                    "smells":       out,
                    "status":       status,
                })

    print(f"\n✅  Wrote all results to {csv_path!r}")


if __name__ == "__main__":
    main()
