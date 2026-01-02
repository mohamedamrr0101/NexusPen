# Contributing to NexusPen

First off, thank you for considering contributing to NexusPen! 🎉

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [How Can I Contribute?](#how-can-i-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Coding Guidelines](#coding-guidelines)
- [Submitting Changes](#submitting-changes)
- [Reporting Bugs](#reporting-bugs)
- [Feature Requests](#feature-requests)

---

## Code of Conduct

### Our Pledge

We are committed to providing a welcoming and inclusive environment. All contributors are expected to:

- Be respectful and considerate
- Accept constructive criticism gracefully
- Focus on what is best for the community
- Show empathy towards other community members

### Responsible Disclosure

⚠️ **IMPORTANT**: NexusPen is a security tool. Any vulnerabilities discovered using this tool should be:
- Reported responsibly to the affected parties
- Never used for malicious purposes
- Only tested on systems you have explicit authorization to test

---

## How Can I Contribute?

### 1. Report Bugs
Found a bug? Please open an issue with:
- A clear description of the problem
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version, etc.)

### 2. Suggest Features
Have an idea? We'd love to hear it:
- Open an issue with the "enhancement" label
- Describe the feature and its use case
- Explain how it fits into the project

### 3. Submit Code
Ready to code? Great!
- Fork the repository
- Create a feature branch
- Write your code
- Submit a pull request

### 4. Improve Documentation
Documentation is crucial:
- Fix typos or unclear explanations
- Add examples and tutorials
- Translate documentation

### 5. Add New Modules
Want to add a new security module?
- Follow the existing module structure
- Include comprehensive docstrings
- Add unit tests

---

## Development Setup

### Prerequisites

```bash
# Python 3.9+
python --version

# Git
git --version
```

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/nexuspen.git
cd nexuspen

# Create virtual environment
python -m venv venv

# Activate virtual environment
# Windows
venv\Scripts\activate
# Linux/Mac
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Install development dependencies
pip install -r requirements-dev.txt

# Install in development mode
pip install -e .
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=modules --cov-report=html

# Run specific test file
pytest tests/test_web.py

# Run specific test
pytest tests/test_web.py::test_sqli_scanner
```

---

## Project Structure

```
NexusPen/
├── nexuspen.py           # Main entry point
├── core/                 # Core framework
│   ├── engine.py         # Scanning engine
│   ├── database.py       # Database management
│   ├── detector.py       # Technology detection
│   ├── logger.py         # Logging utilities
│   └── utils.py          # Helper functions
├── modules/              # Security modules
│   ├── web/              # Web vulnerabilities
│   ├── windows/          # Windows attacks
│   ├── linux/            # Linux attacks
│   ├── ad/               # Active Directory
│   ├── network/          # Network attacks
│   ├── password/         # Password attacks
│   ├── wireless/         # Wireless attacks
│   ├── exploit/          # Exploitation
│   ├── common/           # Shared utilities
│   └── report/           # Report generation
├── tests/                # Unit tests
├── config/               # Configuration files
└── docs/                 # Documentation
```

---

## Coding Guidelines

### Python Style

We follow [PEP 8](https://pep8.org/) with these additions:

```python
# Good: Clear, descriptive names
def scan_sql_injection(url: str, params: dict) -> List[Vulnerability]:
    """
    Scan URL for SQL injection vulnerabilities.
    
    Args:
        url: Target URL to scan
        params: Query parameters to test
        
    Returns:
        List of discovered vulnerabilities
    """
    pass

# Good: Type hints
def process_target(target: str, options: Optional[dict] = None) -> bool:
    pass

# Good: Dataclasses for structured data
@dataclass
class Vulnerability:
    name: str
    severity: str
    description: str
    remediation: str
```

### Module Structure

Each module should follow this pattern:

```python
#!/usr/bin/env python3
"""
NexusPen - Module Name
=======================
Brief description of the module.
"""

import subprocess
from typing import Dict, List, Optional
from dataclasses import dataclass

from rich.console import Console

console = Console()


@dataclass
class Finding:
    """Data class for findings."""
    name: str
    severity: str
    details: str


class ModuleScanner:
    """
    Main scanner class.
    
    Attributes:
        target: Target to scan
    """
    
    def __init__(self, target: str):
        self.target = target
        self.findings: List[Finding] = []
    
    def scan(self) -> List[Finding]:
        """Run the scan and return findings."""
        console.print(f"[cyan]Scanning {self.target}...[/cyan]")
        # Implementation
        return self.findings
```

### Commit Messages

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat: add SQL injection time-based detection
fix: resolve false positive in XSS scanner
docs: update README with installation guide
test: add unit tests for SSRF module
refactor: simplify credential management
```

---

## Submitting Changes

### Pull Request Process

1. **Fork & Clone**
   ```bash
   git clone https://github.com/yourusername/nexuspen.git
   ```

2. **Create Branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make Changes**
   - Write code
   - Add tests
   - Update documentation

4. **Test**
   ```bash
   pytest
   ```

5. **Commit**
   ```bash
   git add .
   git commit -m "feat: add your feature"
   ```

6. **Push**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create Pull Request**
   - Go to GitHub
   - Click "New Pull Request"
   - Fill in the template

### PR Requirements

- [ ] Code follows the style guidelines
- [ ] Tests pass locally
- [ ] New code has tests
- [ ] Documentation is updated
- [ ] Commit messages follow convention

---

## Reporting Bugs

### Bug Report Template

```markdown
**Describe the bug**
A clear description of the bug.

**To Reproduce**
1. Go to '...'
2. Run command '...'
3. See error

**Expected behavior**
What you expected to happen.

**Screenshots**
If applicable, add screenshots.

**Environment:**
- OS: [e.g., Windows 11, Kali Linux]
- Python: [e.g., 3.11.0]
- NexusPen: [e.g., 1.0.0]

**Additional context**
Any other context about the problem.
```

---

## Feature Requests

### Feature Request Template

```markdown
**Is your feature request related to a problem?**
A clear description of the problem.

**Describe the solution you'd like**
What you want to happen.

**Describe alternatives you've considered**
Alternative solutions or features.

**Additional context**
Any other context or screenshots.
```

---

## Recognition

Contributors will be recognized in:
- CHANGELOG.md
- README.md contributors section
- Release notes

---

## Questions?

Feel free to:
- Open an issue with the "question" label
- Reach out to maintainers

Thank you for contributing! 🙏
