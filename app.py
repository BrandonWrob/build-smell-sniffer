from flask import Flask, request, render_template
from secure_linter import lint_pom, lint_gradle, lint_make, lint_cmake, check_if_cmake
import tempfile
import os

from secure_linter.makefile_analyzer import looks_like_makefile

app = Flask(__name__)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/lint', methods=['POST'])
def lint():
    if 'pom_file' not in request.files:
        return 'No file part', 400

    upload = request.files['pom_file']
    filename = upload.filename.lower()
    tmp = tempfile.NamedTemporaryFile(delete=False)
    file_path = tmp.name
    upload.save(file_path)
    tmp.close()

    try:
        if filename.endswith('.xml') or 'pom.xml' in filename:
            issues = lint_pom(file_path)

        elif filename.endswith('.gradle') or filename.endswith('.gradle.kts'):
            issues = lint_gradle(file_path)

        elif 'cmakelists.txt' in filename or check_if_cmake(file_path):
            issues = lint_cmake(file_path)

        elif (
            filename == 'makefile'
            or filename.endswith('.mk')
            or 'makefile' in filename
            or looks_like_makefile(file_path)
        ):
            issues = lint_make(file_path)

        else:
            issues = [{"issue": "Unsupported file type!", "severity": "High"}]

    finally:
        try:
            os.remove(file_path)
        except OSError:
            pass

    return render_template('results.html', issues=issues)

if __name__ == '__main__':
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=True)