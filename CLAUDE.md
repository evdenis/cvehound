# CLAUDE.md - AI Assistant Guide for CVEhound

This document provides comprehensive guidance for AI assistants working with the CVEhound codebase. It covers project structure, development workflows, coding conventions, and key architectural decisions.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Repository Structure](#repository-structure)
3. [Key Technologies](#key-technologies)
4. [Development Workflow](#development-workflow)
5. [Writing CVE Detection Rules](#writing-cve-detection-rules)
6. [Codebase Architecture](#codebase-architecture)
7. [Testing Strategy](#testing-strategy)
8. [Common Tasks](#common-tasks)
9. [Coding Conventions](#coding-conventions)
10. [Troubleshooting](#troubleshooting)

---

## Project Overview

**CVEhound** is a tool for checking Linux kernel sources for known CVEs (Common Vulnerabilities and Exposures). It uses Coccinelle semantic patches and grep patterns to detect vulnerable code patterns or missing security fixes.

### Purpose
- Detect unfixed CVEs in Linux kernel source trees (especially vendor kernels without git history)
- Check if security fixes have been backported
- Identify vulnerable code patterns across kernel versions

### Key Statistics
- **Language**: Python 3 (>=3.9)
- **Version**: 1.2.1 (from `cvehound/__init__.py`)
- **CVE Rules**: 525+ detection rules in `cvehound/cve/`
- **License**: Python code (GPLv3), CVE rules (GPLv2)
- **Main Dependencies**: Coccinelle (>=1.0.7), sympy, lxml

### Primary Use Cases
1. **Vendor Kernel Auditing**: Check kernel sources released as archives without git history
2. **Security Research**: Identify missing CVE fixes in custom kernel builds
3. **Compliance**: Verify security patch status for specific CVE lists

---

## Repository Structure

```
cvehound/
├── cvehound/               # Main Python package
│   ├── __init__.py        # CVEhound class, core detection logic
│   ├── __main__.py        # CLI entry point, argument parsing
│   ├── config.py          # Kernel config file parser
│   ├── cwe.py             # CWE (Common Weakness Enumeration) handling
│   ├── exception.py       # Custom exceptions
│   ├── kbuild.py          # Kbuild/Makefile parser for config mapping
│   ├── util.py            # Utility functions (version detection, rule parsing)
│   ├── cve/               # CVE detection rules (525+ .cocci files)
│   │   ├── CVE-*.cocci    # Coccinelle semantic patches
│   │   ├── CVE-*.grep     # Grep-based detection patterns
│   │   └── disputed/      # Disputed CVE rules
│   ├── data/              # Static data files (CWE mappings, metadata)
│   ├── kbuildparse/       # Kbuild parsing utilities
│   └── scripts/           # Maintenance scripts
│       ├── update_rules.py      # Update CVE rules from GitHub
│       └── update_metadata.py   # Update CVE metadata
├── tests/                 # Test suite
│   ├── conftest.py        # Pytest configuration
│   ├── test_00_metadata.py      # Metadata validation tests
│   ├── test_01_on_branch.py     # Branch-specific tests
│   ├── test_02_on_init.py       # Initialization tests
│   ├── test_03_on_fix.py        # Fix commit tests
│   ├── test_04_on_fixes.py      # Fixes commit tests
│   ├── test_05_between_fixes_fix.py  # Range tests
│   └── test_06_on_branch_all_files.py
├── docs/                  # Comprehensive documentation
│   ├── WRITING_RULES.md         # Complete guide for writing CVE rules
│   ├── AI_AGENT_GUIDE.md        # Systematic guide for AI agents
│   ├── COCCINELLE_CHEATSHEET.md # Quick reference for Coccinelle
│   ├── LSS2021_CVEhound_en.pdf  # Conference presentation
│   └── ZN2021_CVEhound_ru.pdf   # Conference presentation (Russian)
├── contrib/               # Templates and examples
│   ├── template.cocci     # Enhanced template with examples
│   └── blank.cocci        # Minimal template
├── .github/
│   └── workflows/
│       ├── test.yml       # CI/CD pipeline
│       └── publish.yml    # PyPI publishing
├── setup.py               # Package configuration
├── README.md              # User-facing documentation
├── pytest.ini             # Pytest configuration
└── tox.ini                # Tox configuration
```

---

## Key Technologies

### 1. Coccinelle
- **What**: Program matching and transformation tool for C code
- **Why**: Provides semantic pattern matching (understands C syntax, not just text)
- **Usage**: Primary method for detecting vulnerable code patterns
- **Version**: Requires >= 1.0.7, tested with 1.0.8, 1.0.9, 1.1.0, 1.2
- **Language**: Semantic Patch Language (.cocci files)

### 2. Python 3
- **Versions**: 3.9, 3.10, 3.11 (as of setup.py)
- **Key Libraries**:
  - `sympy`: Symbolic logic solver for config expressions
  - `lxml`: XML parsing for Kbuild files
  - `pytest`: Testing framework
  - `gitpython`: Git repository interaction (tests)

### 3. Grep with PCRE
- **Why**: Faster than Coccinelle for simple pattern matching
- **Usage**: Some CVE rules use grep patterns (.grep files)
- **Requirement**: grep with -P flag (Perl-compatible regex)

---

## Development Workflow

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/evdenis/cvehound.git
cd cvehound

# Install in editable mode with test dependencies
pip install -e '.[tests]'

# Verify installation
cvehound --version
cvehound --help

# Install Coccinelle (Ubuntu)
sudo add-apt-repository ppa:npalix/coccinelle
sudo apt install coccinelle libpython2.7

# Install Coccinelle (Fedora)
sudo dnf install coccinelle

# Install Coccinelle (macOS)
brew install coccinelle
```

### Branch Strategy

- **main/master**: Stable releases
- Development branches should follow the pattern: `claude/claude-md-*-<session-id>`
- Always develop on feature branches, never directly on main

### Commit Guidelines

1. **Clear, descriptive commit messages**
   ```
   docs: Update README with links to new documentation
   contrib: Add enhanced template with examples and guidance
   feat: Add support for CWE filtering
   fix: Correct metadata parsing for CVE-2020-12345
   test: Add test cases for CVE-2020-12912
   ```

2. **Commit message prefixes**:
   - `feat:` - New features
   - `fix:` - Bug fixes
   - `docs:` - Documentation changes
   - `test:` - Test additions/changes
   - `refactor:` - Code refactoring
   - `contrib:` - Contribution templates/guides
   - `rules:` - CVE rule additions/updates

3. **Small, focused commits**: Each commit should represent one logical change

### Pull Request Process

1. Create a feature branch
2. Make changes and commit
3. Run tests locally: `pytest`
4. Push to remote
5. Create pull request with clear description
6. Reference related issues or CVEs

---

## Writing CVE Detection Rules

This is the most common contribution task. CVEhound has 525+ CVE detection rules.

### Quick Start for Writing Rules

1. **Read the comprehensive guides first**:
   - `docs/WRITING_RULES.md` - Complete guide with examples
   - `docs/AI_AGENT_GUIDE.md` - Systematic approach for AI agents
   - `docs/COCCINELLE_CHEATSHEET.md` - Quick reference

2. **Use the templates**:
   - `contrib/template.cocci` - Enhanced template with examples
   - `contrib/blank.cocci` - Minimal template

3. **Study existing rules**: Look at similar CVEs in `cvehound/cve/`

### Rule File Structure

Every CVE rule follows this structure:

```cocci
/// Files: <affected_file_paths>
/// Fix: <git_commit_hash_that_fixed_the_vulnerability>
/// Fixes: <commit_that_introduced_bug> OR Detect-To: <last_vulnerable_commit>
/// Version: <min_coccinelle_version> (optional)

virtual detect

@err@
position p;
@@

<pattern_to_match>

@script:python depends on detect@
p << err.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

### Two Detection Strategies

1. **Unfixed Code Detection**: Match vulnerable code pattern directly
   - Use when: Fix changes a value, removes code, or has distinctive vulnerable pattern
   - Example: `return 0444;` → `return 0400;` (CVE-2020-12912)

2. **Missing Fix Detection**: Check for absence of a security fix
   - Use when: Fix adds new validation, initialization, or checks
   - Example: Missing `memset(&var, 0, sizeof(var));` (CVE-2020-12352)

### Rule Naming Convention

- **Format**: `CVE-YYYY-NNNNN.cocci` or `CVE-YYYY-NNNNN.grep`
- **Location**: `cvehound/cve/` (or `cvehound/cve/disputed/` for disputed CVEs)
- **Case**: Uppercase CVE, exact format
- **Extension**: `.cocci` for Coccinelle, `.grep` for grep patterns

### Testing Your Rule

```bash
# Test with spatch directly on vulnerable code
spatch --no-includes --include-headers -D detect \
    --cocci-file CVE-YYYY-NNNNN.cocci \
    /path/to/vulnerable/file.c

# Test with CVEhound
cvehound --kernel /path/to/kernel --cve CVE-YYYY-NNNNN

# Run full test suite
pytest

# Run tests for specific CVE
pytest --cve=CVE-YYYY-NNNNN

# Run slow tests (against real kernel trees)
pytest --runslow
```

### Rule Quality Checklist

- [ ] File naming: `CVE-YYYY-NNNNN.cocci`
- [ ] Metadata complete (Files, Fix, Fixes/Detect-To)
- [ ] Position variable declared and used
- [ ] Detects vulnerability in unfixed code
- [ ] Does NOT detect in fixed code
- [ ] No false positives on unrelated code
- [ ] Tested with both spatch and cvehound
- [ ] Follows patterns from similar CVEs

---

## Codebase Architecture

### Core Classes and Modules

#### 1. `CVEhound` Class (`cvehound/__init__.py`)

Main class that orchestrates CVE detection.

**Key Methods**:
- `__init__(kernel, metadata, config, check_strict, arch)` - Initialize with kernel path and options
- `check_cve(cve)` - Check kernel for a specific CVE
- `check_kernel(cves)` - Check kernel for multiple CVEs
- `get_report()` - Generate JSON report of findings

**Important Attributes**:
- `kernel` - Absolute path to kernel sources
- `metadata` - CVE metadata from linuxkernelcves.com
- `config_map` - Mapping of files to kernel config options
- `cve_all_rules` - All available CVE rules
- `cve_assigned_rules` - Non-disputed CVE rules
- `cve_disputed_rules` - Disputed CVE rules

#### 2. CLI Entry Point (`cvehound/__main__.py`)

Handles command-line interface and argument parsing.

**Key Functions**:
- `main(args)` - Main entry point
- Parses arguments from command line and config files
- Supports config files: `/etc/cvehound.ini`, `~/.config/cvehound.ini`

**Important Arguments**:
- `--kernel DIR` - Linux kernel sources directory
- `--cve CVE [CVE ...]` - List of CVE identifiers (or groups: all, assigned, disputed)
- `--kernel-config [FILE]` - Check kernel .config file
- `--report [FILE]` - Generate JSON report
- `--files PATH [PATH ...]` - Limit check to specific files
- `--cwe ID [ID ...]` - Filter by CWE IDs
- `--exploit` - Only check exploitable CVEs

#### 3. Config Parser (`cvehound/config.py`)

Parses kernel `.config` files.

**Key Class**: `Config`
- Parses CONFIG_* options from kernel .config
- Handles tristate values (y, m, n)

#### 4. Kbuild Parser (`cvehound/kbuild.py`, `cvehound/kbuildparse/`)

Parses Kbuild and Makefile to map source files to kernel config options.

**Purpose**: Determine which CONFIG_* options are needed to compile each source file

**Key Components**:
- `KbuildParser` - Main parser class
- Handles conditional compilation (obj-$(CONFIG_FOO))
- Uses sympy for complex boolean logic

#### 5. Utility Functions (`cvehound/util.py`)

Helper functions for version detection, rule parsing, etc.

**Key Functions**:
- `get_spatch_version()` - Get Coccinelle version
- `get_rule_cves()` - List all CVE rules
- `get_cves_metadata(path)` - Load CVE metadata
- `parse_coccinelle_output(output)` - Parse spatch output

#### 6. CWE Handler (`cvehound/cwe.py`)

Maps CVEs to CWE (Common Weakness Enumeration) categories.

**Class**: `CWE`
- Loads CWE definitions
- Filters CVEs by CWE ID

### Data Flow

```
User Input (CLI/Config)
    ↓
__main__.main()
    ↓
CVEhound.__init__()
    ├→ Load CVE rules from cvehound/cve/
    ├→ Load metadata from data/kernel_cves.json.gz
    ├→ Parse Kbuild files (if --kernel-config)
    └→ Setup Coccinelle include paths
    ↓
CVEhound.check_kernel(cves)
    ↓
For each CVE:
    ├→ CVEhound.check_cve(cve)
    │   ├→ Read rule file (cvehound/cve/CVE-*.cocci)
    │   ├→ Get affected files from rule metadata
    │   ├→ Run spatch on each affected file
    │   └→ Parse output for matches
    └→ If match found:
        ├→ Print CVE details
        └→ Add to report
    ↓
CVEhound.get_report()
    ↓
Output (stdout + optional JSON report)
```

### Execution Model

CVEhound executes Coccinelle rules using subprocess:

```python
subprocess.run([
    'spatch',
    '--no-includes',        # Don't process #include
    '--include-headers',    # But do process headers
    '-D', 'detect',         # Enable detect virtual mode
    '--no-show-diff',       # No diffs
    '--very-quiet',         # Minimal output
    '--cocci-file', rule_file,
    '-I', include_path,     # Kernel includes
    target_file
], capture_output=True)
```

---

## Testing Strategy

### Test Suite Organization

1. **`test_00_metadata.py`**: Validates CVE metadata and rule format
2. **`test_01_on_branch.py`**: Tests CVE detection on specific branches
3. **`test_02_on_init.py`**: Tests initialization and setup
4. **`test_03_on_fix.py`**: Verifies CVE NOT detected on fix commits
5. **`test_04_on_fixes.py`**: Tests CVE detected before fixes commit
6. **`test_05_between_fixes_fix.py`**: Tests detection in commit range
7. **`test_06_on_branch_all_files.py`**: Tests with --all-files option

### Running Tests

```bash
# Run all tests (fast tests only)
pytest

# Run all tests including slow tests (requires kernel sources)
pytest --runslow

# Run specific test file
pytest tests/test_00_metadata.py

# Run tests for specific CVE
pytest --cve=CVE-2020-12912

# Run with verbose output
pytest -v

# Run with debug output
pytest -vv
```

### Test Requirements

- **Fast tests**: No external dependencies, metadata validation
- **Slow tests** (--runslow): Require Linux kernel git repository
  - Cloned to `tests/linux/`
  - Tests check CVE detection on actual kernel code
  - CI caches kernel bundle for faster runs

### CI/CD Pipeline

GitHub Actions workflow (`.github/workflows/test.yml`):

1. **Install Job**: Tests installation on multiple OS/Python versions
   - Ubuntu 22.04 + Python 3.9
   - Ubuntu latest + Python 3.11
   - macOS latest + Python 3.10

2. **Build Job**: Full test suite
   - Tests multiple Coccinelle versions (1.0.8, 1.0.9, 1.1.0, 1.2, system)
   - Downloads Linux kernel bundle
   - Runs pytest with kernel sources
   - Caches kernel bundle monthly

3. **Triggers**:
   - Push to `cvehound/**` or `tests/**`
   - Pull requests
   - Weekly schedule (Monday midnight)
   - Manual dispatch

### Adding Tests for New CVE Rules

When adding a new CVE rule, add test case to `tests/test_03_on_fix.py`:

```python
@pytest.mark.parametrize("cve,kernel,commit", [
    # ... existing tests ...
    ("CVE-2020-12345", "torvalds", "abc123def456"),  # Your new test
])
def test_cve_on_fix(cve, kernel, commit):
    """Test that CVE is NOT detected on fixed commit"""
    pass
```

---

## Common Tasks

### Task 1: Adding a New CVE Rule

1. **Research the CVE**:
   ```bash
   # Find the fix commit
   git log --all --grep="CVE-2020-12345"

   # View the diff
   git show <commit_hash>
   ```

2. **Choose detection strategy**:
   - Unfixed code: Match the vulnerable pattern
   - Missing fix: Check for absence of fix

3. **Create the rule**:
   ```bash
   # Copy template
   cp contrib/blank.cocci cvehound/cve/CVE-2020-12345.cocci

   # Edit the rule (see WRITING_RULES.md for guidance)
   ```

4. **Test the rule**:
   ```bash
   # Test on vulnerable code
   git checkout <commit_before_fix>
   cvehound --kernel /path/to/kernel --cve CVE-2020-12345

   # Test on fixed code (should not detect)
   git checkout <fix_commit>
   cvehound --kernel /path/to/kernel --cve CVE-2020-12345
   ```

5. **Add test case**: Edit `tests/test_03_on_fix.py`

6. **Commit and push**:
   ```bash
   git add cvehound/cve/CVE-2020-12345.cocci tests/test_03_on_fix.py
   git commit -m "rules: Add detection rule for CVE-2020-12345"
   git push
   ```

### Task 2: Updating CVE Metadata

```bash
# Update metadata from linuxkernelcves.com
cvehound_update_metadata

# This updates cvehound/data/kernel_cves.json.gz
```

### Task 3: Updating CVE Rules from GitHub

```bash
# Pull latest rules from repository
cvehound_update_rules

# This updates rules in ~/.local/share/cvehound/cve/
# or /usr/share/cvehound/cve/ (system-wide)
```

### Task 4: Running CVEhound on a Kernel

```bash
# Basic check (all assigned CVEs)
cvehound --kernel ~/linux-5.10

# Check specific CVEs
cvehound --kernel ~/linux-5.10 --cve CVE-2020-12912 CVE-2020-27194

# Check with kernel config
cvehound --kernel ~/linux-5.10 --kernel-config

# Generate JSON report
cvehound --kernel ~/linux-5.10 --report results.json

# Filter by CWE
cvehound --kernel ~/linux-5.10 --cwe 119 787

# Check only specific files
cvehound --kernel ~/linux-5.10 --files drivers/net/

# Check only exploitable CVEs
cvehound --kernel ~/linux-5.10 --exploit

# Exclude specific CVEs
cvehound --kernel ~/linux-5.10 --exclude CVE-2020-12345 CVE-2020-67890
```

### Task 5: Debugging a Rule

```bash
# Run spatch directly with debug output
spatch --debug file.c --sp-file CVE-2020-12345.cocci

# Parse cocci file for syntax errors
spatch --parse-cocci CVE-2020-12345.cocci

# Run with verbose output
cvehound --kernel ~/linux-5.10 --cve CVE-2020-12345 -vv

# Test on specific file
spatch --no-includes --include-headers -D detect \
    --cocci-file cvehound/cve/CVE-2020-12345.cocci \
    /path/to/affected/file.c
```

### Task 6: Contributing Documentation

1. **For rule writing guides**: Edit `docs/WRITING_RULES.md`
2. **For quick reference**: Edit `docs/COCCINELLE_CHEATSHEET.md`
3. **For AI guidance**: Edit `docs/AI_AGENT_GUIDE.md`
4. **For templates**: Edit `contrib/template.cocci`
5. **For general documentation**: Edit `README.md`

---

## Coding Conventions

### Python Code Style

1. **PEP 8 Compliance**: Follow PEP 8 style guide
2. **Indentation**: 4 spaces (no tabs)
3. **Line Length**: ~80-100 characters (flexible)
4. **Naming**:
   - `snake_case` for functions and variables
   - `PascalCase` for classes
   - `UPPER_CASE` for constants

### Docstrings

Use docstrings for public classes and functions:

```python
def check_cve(self, cve):
    """Check kernel for a specific CVE.

    Args:
        cve: CVE identifier (e.g., 'CVE-2020-12345')

    Returns:
        True if CVE is found, False otherwise
    """
    pass
```

### Error Handling

- Use custom exceptions from `cvehound.exception`
- Handle subprocess errors gracefully
- Provide meaningful error messages

### Logging

Use Python's logging module:

```python
import logging

logging.warning('Found: CVE-2020-12345')
logging.info('MSG: Buffer overflow vulnerability')
logging.debug('Running spatch on file.c')
```

### File Paths

- Always use `os.path.join()` for path construction
- Use `os.path.abspath()` for absolute paths
- Handle both POSIX and Windows paths (where applicable)

### Coccinelle Rule Style

1. **Metadata order**: Files, Fix, Fixes/Detect-To, Version
2. **Always include**: `virtual detect`
3. **Position markers**: Always use `position p;` and `@p`
4. **Rule naming**: Descriptive names like `@err@`, `@missing_check@`
5. **Comments**: Explain complex patterns
6. **Indentation**: Match surrounding C code style (typically 4 spaces or tabs)

---

## Troubleshooting

### Common Issues and Solutions

#### Issue 1: Coccinelle Version Too Old

**Symptom**: Warning about spatch version

**Solution**:
```bash
# Ubuntu
sudo add-apt-repository ppa:npalix/coccinelle
sudo apt install --upgrade coccinelle

# Fedora
sudo dnf upgrade coccinelle

# macOS
brew upgrade coccinelle

# Or install via opam
opam install coccinelle.1.2
```

#### Issue 2: Rule Not Detecting Vulnerability

**Causes**:
- Pattern too specific
- Missing `exists` constraint
- Incorrect position marker
- Code formatting differences

**Debug Steps**:
```bash
# 1. Verify rule syntax
spatch --parse-cocci CVE-YYYY-NNNNN.cocci

# 2. Test on known vulnerable file
spatch -D detect --cocci-file CVE-YYYY-NNNNN.cocci vulnerable_file.c

# 3. Add debug output to rule (optional * markers)
# 4. Simplify pattern incrementally
# 5. Check if file exists and is correct version
```

#### Issue 3: False Positives

**Causes**:
- Pattern too generic
- Missing context
- Incorrect `when` constraints

**Solutions**:
- Add function name context
- Use `when !=` to exclude non-vulnerable cases
- Add rule dependencies
- Study the fix commit more carefully

#### Issue 4: Tests Failing

**Common causes**:
- Kernel sources not available (`tests/linux/`)
- Wrong git commit checked out
- Coccinelle version incompatibility
- Rule syntax error

**Solutions**:
```bash
# Download kernel sources for tests
git clone --depth 1 https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git tests/linux

# Run specific test
pytest tests/test_03_on_fix.py::test_cve_on_fix -v

# Skip slow tests
pytest -m "not slow"
```

#### Issue 5: Kbuild Parsing Errors

**Symptom**: Config mapping fails or incorrect

**Causes**:
- Unusual Kbuild syntax
- Complex conditional logic
- Missing Makefile

**Debug**:
```bash
# Test kbuild parser directly
python -c "from cvehound.kbuild import KbuildParser; parser = KbuildParser(...)"
```

#### Issue 6: Metadata Issues

**Symptom**: Missing CVE information in output

**Solution**:
```bash
# Update metadata
cvehound_update_metadata

# Or specify custom metadata location
cvehound --kernel ~/linux --metadata /path/to/kernel_cves.json.gz
```

### Getting Help

1. **Documentation**:
   - `docs/WRITING_RULES.md` - Comprehensive rule writing guide
   - `docs/AI_AGENT_GUIDE.md` - Systematic approach for AI agents
   - `docs/COCCINELLE_CHEATSHEET.md` - Quick reference

2. **Coccinelle Resources**:
   - [Coccinelle Documentation](https://coccinelle.gitlabpages.inria.fr/website/docs/)
   - [Coccinelle Mailing List](mailto:cocci@inria.fr)

3. **CVEhound Resources**:
   - [GitHub Issues](https://github.com/evdenis/cvehound/issues)
   - [Existing Rules](cvehound/cve/) - Study similar CVEs
   - [Test Suite](tests/) - Working examples

4. **CVE Information**:
   - [Linux Kernel CVEs](https://www.linuxkernelcves.com/)
   - [Linux Kernel Git](https://git.kernel.org/)
   - [CVE Database](https://cve.mitre.org/)

---

## Key Architectural Decisions

### Why Coccinelle?

- **Semantic matching**: Understands C syntax, not just text patterns
- **Robust**: Handles different code styles and formatting
- **Proven**: Used by Linux kernel developers
- **Flexible**: Can match complex patterns with constraints

### Why Grep for Some Rules?

- **Performance**: Much faster than Coccinelle for simple patterns
- **Simplicity**: Some patterns are simple string matches
- **Complementary**: Use grep for speed, Coccinelle for accuracy

### Why Kbuild Parsing?

- **Config awareness**: Determine if vulnerable code is actually compiled
- **Reduce false positives**: Don't report CVEs in disabled code
- **Vendor kernels**: Many vendors customize kernel config

### Why Python 3.9+?

- **Type hints**: Better code quality and IDE support
- **Modern features**: Dict merge operator, walrus operator
- **Performance**: Improved over earlier versions
- **Long-term support**: Python 3.9+ has good LTS coverage

### Why JSON for Reports?

- **Machine-readable**: Easy to parse and process
- **Standard format**: Well-supported across tools
- **Extensible**: Can add fields without breaking compatibility

---

## Performance Considerations

### Optimization Tips

1. **Use `--files` to limit scope**: Only check relevant files
   ```bash
   cvehound --kernel ~/linux --files drivers/net/
   ```

2. **Use `--cve` to check specific CVEs**: Don't check all 525+ rules
   ```bash
   cvehound --kernel ~/linux --cve CVE-2020-12912 CVE-2020-27194
   ```

3. **Enable parallel execution**: CVEhound uses concurrent.futures internally

4. **Cache kernel bundle**: CI caches kernel for faster tests

5. **Use grep rules when possible**: Faster than Coccinelle

### Scalability

- **Large kernels**: Tested on full Linux kernel sources (50k+ files)
- **Multiple CVEs**: Can check 525+ CVEs in reasonable time
- **Memory usage**: Coccinelle can be memory-intensive for complex patterns
- **CPU usage**: Parallelized to use multiple cores

---

## Security Considerations

### CVE Rule Accuracy

- **False negatives**: Worse than false positives (missing real vulnerabilities)
- **False positives**: Should be minimized but acceptable with context
- **Testing**: Every rule should be tested on vulnerable and fixed code

### Metadata Trust

- **Source**: Metadata from linuxkernelcves.com (community-maintained)
- **Updates**: Should be updated regularly with `cvehound_update_metadata`
- **Validation**: Test suite validates metadata format

### Kernel Config Trust

- **User-provided**: Kernel .config is provided by user
- **Parsing**: Config parser handles malformed input gracefully
- **Validation**: Kbuild parser validates syntax

---

## Future Enhancements

### Potential Improvements

1. **Better performance**: Optimize Coccinelle rule execution
2. **More CVE rules**: Continuous addition of new CVEs
3. **Better reporting**: Enhanced JSON report format
4. **Web interface**: Browser-based CVE checking
5. **CI integration**: GitHub Actions for kernel repos
6. **SARIF support**: Standard format for security tools

### Contributing Ideas

- Add CVE rules for recent vulnerabilities
- Improve documentation with more examples
- Add support for other architectures (ARM, RISC-V)
- Enhance Kbuild parser for edge cases
- Add more CWE mappings

---

## Glossary

- **CVE**: Common Vulnerabilities and Exposures
- **CWE**: Common Weakness Enumeration
- **Coccinelle**: Program matching and transformation tool
- **Spatch**: Coccinelle's semantic patch command
- **Kbuild**: Linux kernel build system
- **FSTEC BDU**: Russian security database (exploit information)
- **CVSS**: Common Vulnerability Scoring System
- **Semantic patch**: Pattern that understands code semantics, not just syntax

---

## Quick Reference

### Essential Commands

```bash
# Check kernel for all CVEs
cvehound --kernel /path/to/kernel

# Check specific CVEs
cvehound --kernel /path/to/kernel --cve CVE-2020-12912

# Generate report
cvehound --kernel /path/to/kernel --report output.json

# Check with kernel config
cvehound --kernel /path/to/kernel --kernel-config

# List all known CVEs
cvehound --list

# Test a single rule
spatch -D detect --cocci-file cvehound/cve/CVE-2020-12912.cocci file.c

# Run tests
pytest
pytest --runslow  # Include slow tests

# Update rules
cvehound_update_rules

# Update metadata
cvehound_update_metadata
```

### Important Files

- `cvehound/__init__.py` - Main CVEhound class
- `cvehound/__main__.py` - CLI entry point
- `cvehound/cve/CVE-*.cocci` - CVE detection rules
- `docs/WRITING_RULES.md` - Rule writing guide
- `tests/test_03_on_fix.py` - Fix commit tests

### Key Patterns

```python
# Initialize CVEhound
from cvehound import CVEhound
ch = CVEhound(kernel='/path/to/kernel')

# Check for CVEs
results = ch.check_kernel(['CVE-2020-12912'])

# Get report
report = ch.get_report()
```

---

## Document Maintenance

- **Last Updated**: 2024-11
- **CVEhound Version**: 1.2.1
- **Maintainer**: CVEhound Contributors
- **Review Cycle**: Update when major changes occur

This document should be updated when:
- New major features are added
- Architecture changes significantly
- New documentation is created
- Testing strategy evolves
- Significant patterns emerge from contributions

---

**End of CLAUDE.md**
