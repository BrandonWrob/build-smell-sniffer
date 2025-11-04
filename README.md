# Secure Linter ("Sniffer")

**Sniffer** is a lightweight, Flask-powered static analysis tool designed to detect build-script “code smells”, recurring patterns that may hinder maintainability, security, or reproducibility.
It currently supports CMake, Gradle, GNU Make, and Maven, enabling cross-build-system analysis within a unified framework.
Sniffer helps developers and researchers identify anti-patterns early in the CI/CD pipeline, facilitating cleaner, more reliable build configurations.
You can run Sniffer locally or integrate it into automated workflows for large-scale analysis.

---

## Table of Contents

1. [Features](#features)  
2. [Getting Started](#getting-started)  
   - [Prerequisites](#prerequisites)  
   - [Clone & Install](#clone--install)  
3. [Usage](#usage)  
   - [Web UI](#webui)  
   - [Command Line](#commandline)  
   - [Python API](#python-api)  
4. [Docker](#docker)  
   - [Build & Run](#build-and-run)  
   - [Publish Image](#publish-image)  
5. [Project Layout](#project-layout)  
6. [Adding New Checks](#adding-new-checks)  

---

## Features

- 🔍 **Multi-Build-System Support**  
  - **CMake** (`.cmake`, `CMakeLists.txt`)  
  - **Gradle** (`.gradle`, `.gradle.kts`)  
  - **GNU Make** (`Makefile`, `.mk`)  
  - **Maven** (`pom.xml`)  
- 🛠 **Pluggable Rules**  
  Drop new security checks in `secure_linter/*_security_checks.py` and they’re auto-discovered.  
- 🌐 **Web Interface**  
  Upload a script, click **Lint**, see issues color-coded by severity.  
- ⚙️ **CLI & API**  
  Integrate into CI/CD pipelines or call via Python.

---

## Getting Started

### Prerequisites

- Python **3.11**–**3.13**  
- [Poetry](https://python-poetry.org/) (for local install)  
- (Optional) Docker & Docker Engine

### Clone & Install

```bash
# Clone the repo
git clone https://github.com/Mahzabin-Tamanna/Build-SmellSniffer.git
cd Build-SmellSniffer/secure-linter

# Install dependencies
poetry install

# Start the Flask app
poetry run python app.py
```
## Usage
### WebUI
1. Open your browser to `http://localhost:5000/`.
2. Upload or paste your build script.
3. Click **Lint** and review the report.
### Command Line
```
# Lint a file and print JSON
poetry run python - <<EOF
from secure_linter import lint_file_to_record
print(lint_file_to_record("path/to/Makefile"))
EOF
```
### Python API
```
from secure_linter import lint_file_to_record

result = lint_file_to_record("CMakeLists.txt")
print(result["build_system"], result["smells"])
```
### Docker
#### Build and Run
```
# Build image
docker build -t secure-linter:latest .

# Run container
docker run --rm -p 5000:5000 secure-linter:latest
```
#### Publish Image
```
# Tag
docker tag secure-linter:latest buildsmellsniffer/secure-linter:0.1.0

# Push (anonymous per conference policy)
docker push buildsmellsniffer/secure-linter:0.1.0
```
#### Image URL: https://hub.docker.com/repository/docker/buildsmellsniffer/secure-linter

## Project Layout
secure-linter/  
├── app.py # Flask application entrypoint  
├── Dockerfile # Docker configuration for building the image  
├── pyproject.toml # Poetry project metadata and dependencies  
├── poetry.lock # Locked dependency versions  
├── requirements.txt # Exported dependencies for non-Poetry installs  
├── secure_linter/ # Linter source code  
│ ├── \_\_init\_\_.py  
│ ├── cmake_parser.py  
│ ├── cmake_security_checks.py  
│ ├── gradle_parser.py  
│ ├── gradle_security_checks.py  
│ ├── makefile_analyzer.py  
│ ├── makefile_security_checks.py  
│ ├── maven_parser.py  
│ └── maven_security_checks.py  
├── templates/ # HTML templates for Flask views  
│ ├── index.html  
│ └── results.html  
└── tests/ # Scripts for various linter evaluation modes  
├── run_linter_sanity.py  
├── run_linter_empricalanalysis.py  
├── run_linter_userstudy.py  
└── update_google_sheet.py

## Adding new checks
1.  Create or modify a file in `secure_linter/` named `<build>_security_checks.py`.
    
2.  Define functions named `check_<something>(data) -> List[Dict[str,str]]`.
    
3.  Each return dict must include keys:
    
    -   `issue` (string)
        
    -   `severity` (`High`/`Medium`/`Low`)
        
4.  On next run, your checks are auto-loaded.

