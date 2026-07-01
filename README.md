# Perscrutator

![Python](https://img.shields.io/badge/python-3.x-blue)
![Security](https://img.shields.io/badge/security-research-red)

Perscrutator is a modular web security scanner written in Python.

It is designed to discover web application attack surfaces, analyze inputs, and run security checks through dynamically loaded scanner modules.

The project uses an addon-based architecture, allowing new scanners to be added without modifying the core engine.

---

## ⚠️ Disclaimer

Perscrutator is intended for **authorized security testing, education, and research purposes only**.

Do **not** use this tool against websites, applications, servers, or networks that you do not own or do not have explicit permission to test.

Unauthorized security testing may be illegal.

The user is solely responsible for ensuring they have proper authorization before running this software. The author assumes no responsibility for misuse or damage caused by this tool.

Recommended testing environments:

- Your own applications
- Local development environments
- Capture The Flag (CTF) challenges
- Intentionally vulnerable applications

---

# Features

## Core Engine

- Modular scanner addon system
- Automatic scanner loading
- Target parsing
- Endpoint discovery
- Parameter extraction
- Form analysis
- JSON reporting

## SSRF Scanner

Current SSRF capabilities:

- URL parameter detection
- Form field analysis
- JSON parameter testing
- Header injection testing
- Out-of-band callback detection
- Custom payload engine
- Evidence generation

Example detection:

```
POSSIBLE SSRF VULNERABILITY FOUND!

Field   : url
Payload : https://callback.example/cb/token

Trigger : Confirmed OOB callback
Severity: High
```

---

# Installation

Clone the repository:

```bash
git clone https://github.com/YOUR_USERNAME/perscrutator.git

cd perscrutator
```

Install dependencies:

```bash
pip install -r requirements.txt
```

---

# Usage

Run:

```bash
python main.py
```

Provide a target when prompted:

```
Target:
https://example.com
```

Perscrutator will:

1. Parse the target
2. Discover inputs
3. Load enabled scanners
4. Run vulnerability checks
5. Generate results

---

# Project Structure

```
perscrutator/
│
├── main.py                 # Main scanner engine
├── parser.py               # Target parser
├── requirements.txt
│
├── scanners/
│   ├── ssrf.py             # SSRF scanner module
│   └── ...
│
├── lib/
│   └── ssrf_prober.py      # SSRF probing engine
│
├── examples/
│   └── vulnerable_apps/
│
└── README.md
```

---

# Adding New Scanners

Perscrutator uses an addon system.

A scanner should:

1. Be placed inside:

```
scanners/
```

2. Match the filename:

```
example.py
```

3. Expose a function:

```python
def example(asset):
    return result
```

The loader automatically imports scanners based on their filename.

---

# Configuration

Environment variables can be used to configure scanners.

Example:

```bash
export SSRF_PROBE_ALL_FIELDS=1
```

Enable debug output:

```bash
export SSRF_DEBUG=1
```

---

# Testing

For safe testing, use intentionally vulnerable applications:

- OWASP WebGoat
- OWASP Juice Shop
- DVWA
- PortSwigger Web Security Academy labs
- Your own vulnerable applications

---

# Roadmap

Planned features:

- [ ] SQL injection scanner
- [ ] Cross-site scripting scanner
- [ ] Better JavaScript endpoint discovery
- [ ] Authentication/session support
- [ ] Proxy support
- [ ] Improved reporting
- [ ] More vulnerability modules

---

# Contributing

Contributions are welcome.

Before submitting changes:

1. Test your changes locally
2. Follow the existing code style
3. Do not include secrets or private targets
4. Add documentation where needed

---

# License

Choose a license before publishing.

Recommended:

- MIT License for open-source projects
- GPL if you want derivative projects to remain open-source

---

# Author

Created by:

YOUR_NAME
