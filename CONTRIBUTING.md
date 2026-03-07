# Contributing to Unified Phishing Detector

Thank you for considering contributing! Here's everything you need to know.

## How to Contribute

### Reporting Bugs
Open an issue with:
- A clear title describing the bug
- Steps to reproduce it
- Expected vs. actual output
- Your Python version and OS

### Suggesting Features
Open an issue tagged `enhancement`. Check the [improvement roadmap](phishing_detector_improvements.docx) first — your idea may already be planned.

### Submitting Code

1. Fork the repo and create a branch:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. Follow the **module return format** — every module must return:
   ```python
   {
       "module": "Module Name",   # string — appears in report header
       "score": 0,                # int/float 0–100
       "flags": [                 # list of (message, ANSI_COLOR) tuples
           ("Flag description", RED),
       ],
       "info": {}                 # dict of key facts shown in report
   }
   ```

3. Add your module to the `modules` list inside `scan()` and to `MODULE_WEIGHTS`.

4. Test your module in both full and fast scan modes.

5. Update `README.md` module table if adding a new module.

6. Submit a Pull Request with a clear description of what your module detects and why.

## Code Style
- Follow existing code style (PEP 8 where practical)
- Keep module functions independent — no side effects on shared state
- Handle all exceptions within the module — never let one module crash the full scan
- Use the existing `ensure_pkg()` helper for optional dependencies
