# AI Agent Guide: Writing Coccinelle CVE Detection Rules

This guide is specifically designed for AI agents to systematically create accurate CVE detection rules for the CVEhound project. Follow this structured approach for consistent, high-quality results.

## Mission

Create a Coccinelle semantic patch (.cocci file) that detects a specific Linux kernel CVE by matching vulnerable code patterns or identifying missing security fixes.

## Prerequisites Checklist

Before writing a rule, gather this information:

- [ ] CVE ID (format: CVE-YYYY-NNNNN)
- [ ] Fix commit hash from Linux kernel git repository
- [ ] Commit that introduced the bug (optional but helpful)
- [ ] Complete diff of the vulnerable commit (`git show <hash>`)
- [ ] Affected file paths (relative to kernel root)
- [ ] Understanding of what makes the code vulnerable

## Decision Tree: Detection Strategy

```
START: Analyze the fix commit diff
│
├─ Does the fix ADD new code?
│  │
│  ├─ YES → Use "Missing Fix Detection"
│  │        Pattern: Check for ABSENCE of the new code
│  │        Example: Missing validation check, missing initialization
│  │
│  └─ NO → Continue to next question
│
├─ Does the fix CHANGE a value (constant, flag, permission)?
│  │
│  ├─ YES → Use "Unfixed Code Detection"
│  │        Pattern: Match the OLD (vulnerable) value
│  │        Example: return 0444 → return 0400
│  │
│  └─ NO → Continue to next question
│
├─ Does the fix REMOVE code?
│  │
│  ├─ YES → Use "Unfixed Code Detection"
│  │        Pattern: Detect presence of removed code
│  │        Example: Removed vulnerable driver
│  │
│  └─ NO → Continue to next question
│
└─ Does the fix REFACTOR or CHANGE logic?
   │
   └─ YES → Use "Unfixed Code Detection" or "Hybrid Approach"
            Pattern: Match distinctive vulnerable pattern
            May require multiple rules with dependencies
```

## Standard Rule Template

Every rule MUST follow this structure:

```cocci
/// Files: <space-separated list of affected files>
/// Fix: <40-char git commit hash>
/// Fixes: <commit-hash> OR Detect-To: <commit-hash>

virtual detect

@err@
position p;
@@

<pattern>

@script:python depends on detect@
p << err.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

## Required Metadata Fields

The header must be the first contiguous block of `///` lines; parsing stops at the first
line that isn't one. Repeated fields overwrite, so keep one line per field.

### Files:
```cocci
/// Files: net/bluetooth/a2mp.c net/bluetooth/mgmt.c
```
- Relative paths from kernel root, space-separated, all on one line
- Nothing validates them: if none of the paths exist, `check_cve` silently scans the
  whole kernel tree instead of erroring, so a typo shows up only as a very slow run

### Fix: (required in practice)
```cocci
/// Fix: bcf85fcedfdd17911982a3e3564fcfec7b01eebd
```
- Full commit hash of the fix
- `test_03_on_fix` checks it out (rule must not fire) and its parent (rule must fire);
  omitting it crashes that test rather than skipping it

### Fixes: or Detect-To: (one required in practice)
```cocci
/// Fixes: da4458bda237aa0cb1688f6c359477f203788f6a
/// Detect-To: 8abee9566b7e8eecf566c4daf6be062a27369890
```
- Both assign the **same** field — use exactly one
- Fixes: the commit that introduced the bug, when known
- Detect-To: the earliest commit the rule must fire at, when the introducing commit isn't
  marked or can only be guessed
- May also be the tag `v2.6.12-rc2`, meaning "present since the start of git history"
- Drives `test_04_on_fixes` and `test_05_between_fixes_fix`

## Pattern Construction Rules

### Rule 1: Always Use Position Markers
```cocci
@err@
position p;        // REQUIRED: Declare position variable
@@

* vulnerable_code@p(...);  // REQUIRED: Mark with @p
```

### Rule 2: Mark Vulnerable Lines with `*`
```cocci
* return 0444;@p         // Context marker: the line to report
```
`*` is the context marker, not a wildcard (`...` is). It is not cosmetic: it switches the
whole patch into match mode, which flips the default quantification of un-annotated `...`
from `forall` to `exists`, so adding or removing it can change what matches. It also
cannot be combined with `-`/`+`. 508 of 526 rules use it.

### Rule 3: Use Appropriate Metavariables
```cocci
identifier func;     // For function/variable names (unknown)
symbol kfree;        // Match this exact name literally, not as a metavariable
expression E;        // For any expression
statement S;         // For any statement
type T;              // For any type
position p;          // For location tracking (required)
```

### Rule 4: Context Scoping
Always provide enough context to avoid false positives:

```cocci
// BAD: Too generic
@err@
position p;
@@

* return -1;@p

// GOOD: Specific context
@err@
position p;
@@

vulnerable_function(...)
{
    ...
*   return -1;@p
}
```

### Rule 5: Use Ellipsis Correctly
```cocci
func(...)              // Match any function arguments
{
    ...                // Match 0 or more statements
    code();
    ...                // More statements
}
```

### Rule 6: Apply Constraints with `when`
```cocci
@err@
identifier var;
position p;
@@

func(...)
{
    struct foo var;
    ... when != memset(&var, 0, sizeof(var));    // Must NOT have init
        when != var = ...;                        // Must NOT be assigned
*   use_var(&var)@p;
}
```

## Common Vulnerability Pattern Templates

Use the catalog in
[COCCINELLE_CHEATSHEET.md](COCCINELLE_CHEATSHEET.md#common-vulnerability-patterns).
Pick the entry matching what the fix did (per the decision tree above), then open the
real rules it cites in `cvehound/cve/` and follow those rather than the sketch.

## Systematic Development Process

### Step 1: Analyze the Vulnerable Commit
```bash
# Get the diff showing the vulnerability fix
git show <fix_commit_hash>

# Understand what changed
# - Lines with - are old (vulnerable) code
# - Lines with + are new (fixed) code
```

### Step 2: Identify Key Pattern
Extract the minimal distinguishing pattern:

**Example Analysis**:
```c
// From git diff
-    return 0444;
+    return 0400;
```

**Key Pattern**: `return 0444;` in specific function

### Step 3: Write Initial Rule
Start with the basic template and fill in:

```cocci
/// Files: drivers/hwmon/amd_energy.c
/// Fix: 60268b0e8258fdea9a3c9f4b51e161c123571db3

virtual detect

@err@
position p;
@@

amd_energy_is_visible(...)
{
*   return 0444;@p
}

@script:python depends on detect@
p << err.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-2020-12912')
```

### Step 4: Validate the Rule
```bash
# Test on vulnerable version (should detect)
git checkout <commit_before_fix>
spatch --no-includes --include-headers -D detect \
    --cocci-file CVE-YYYY-NNNNN.cocci \
    <affected_file>

# Test on fixed version (should NOT detect)
git checkout <fix_commit>
spatch --no-includes --include-headers -D detect \
    --cocci-file CVE-YYYY-NNNNN.cocci \
    <affected_file>
```

### Step 5: Refine for Accuracy
If false positives occur:
- Add more context (function name, surrounding code)
- Add `when` constraints
- Use rule dependencies

If false negatives occur:
- Simplify pattern
- Use `exists` constraint
- Add alternative patterns with `\(alt1\|alt2\)`

## Advanced Pattern Techniques

### Technique 1: Function Alternatives
When the same bug exists in multiple related functions:

```cocci
@err@
position p;
@@

\(function1\|function2\|function3\)(...)
{
*   vulnerable_pattern@p;
}
```

### Technique 2: Rule Dependencies
When detection requires multiple conditions:

```cocci
@prerequisite@
@@

feature_function(...)
{
    ...
}

@err depends on prerequisite@
position p;
@@

* vulnerable_code@p(...);
```

### Technique 3: Multiple Detection Points
When vulnerability appears in multiple locations:

```cocci
@err@
position p;
@@

(
* vulnerable_call1@p(...);
|
* vulnerable_call2@p(...);
|
* vulnerable_call3@p(...);
)

@script:python depends on detect@
p << err.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

### Technique 4: Repetitive Patterns
When the same pattern repeats across functions (see CVE-2020-12352):

```cocci
@err_func1 exists@
identifier req;
position p;
@@

func1(...)
{
    ...
    struct type req;
    ... when != memset(&req, 0, sizeof(req));
*   send(..., &req)@p;
    ...
}

@err_func2 exists@
identifier rsp;
position p;
@@

func2(...)
{
    ...
    struct type rsp;
    ... when != memset(&rsp, 0, sizeof(rsp));
*   send(..., &rsp)@p;
    ...
}

// Repeat for each affected function

@script:python depends on detect@
p << err_func1.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')

@script:python depends on detect@
p << err_func2.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

## Testing Protocol

### Test 1: Positive Detection
```bash
# Rule MUST detect on vulnerable code
cd /path/to/kernel
git checkout <commit_before_fix>
spatch --no-includes --include-headers -D detect \
    --very-quiet --cocci-file CVE-YYYY-NNNNN.cocci \
    <affected_file>

# Expected: Should print "ERROR: CVE-YYYY-NNNNN"
```

### Test 2: Negative Detection (Fixed Code)
```bash
# Rule MUST NOT detect on fixed code
git checkout <fix_commit>
spatch --no-includes --include-headers -D detect \
    --very-quiet --cocci-file CVE-YYYY-NNNNN.cocci \
    <affected_file>

# Expected: No output
```

### Test 3: False Positive Check
```bash
# Test on unrelated kernel files
spatch --no-includes --include-headers -D detect \
    --cocci-file CVE-YYYY-NNNNN.cocci \
    <unrelated_file>

# Expected: No output
```

### Test 4: CVEhound Integration
```bash
cvehound --kernel /path/to/kernel --cve CVE-YYYY-NNNNN

# Expected: Should find CVE on vulnerable versions only
```

## Error Prevention Checklist

Before finalizing, verify:

- [ ] File naming: `CVE-YYYY-NNNNN.cocci` (exact format)
- [ ] All metadata fields present (Files, Fix)
- [ ] Position variable declared: `position p;`
- [ ] Vulnerable lines marked with `*` and `@p`
- [ ] Python script references correct position: `p << err.p;`
- [ ] CVE ID correct in error message
- [ ] Rule tested on vulnerable code (detects)
- [ ] Rule tested on fixed code (does not detect)
- [ ] No syntax errors: `spatch --parse-cocci CVE-YYYY-NNNNN.cocci`
- [ ] Proper context to avoid false positives
- [ ] Follows patterns from similar CVEs in repository

## Common Mistakes to Avoid

### Mistake 1: Missing Position Marker
```cocci
// WRONG
@err@
@@

vulnerable_code();

// CORRECT
@err@
position p;
@@

vulnerable_code@p();
```
Note: The asterisk (*) is optional for detection.

### Mistake 2: Too Generic Pattern
```cocci
// WRONG: Will match everywhere
@err@
position p;
@@

* return -1;@p

// CORRECT: Specific function context
@err@
position p;
@@

specific_function(...)
{
    ...
*   return -1;@p
}
```

### Mistake 3: Wrong Position Syntax
```cocci
// WRONG: Multiple positions on same line
* vulnerable_code@p1()@p2;

// CORRECT: One position per statement
* vulnerable_code@p();
```

### Mistake 4: Incorrect Python Script
```cocci
// WRONG: Wrong variable name
@script:python depends on detect@
p << wrong_rule.p;
@@

// CORRECT: Must match rule name
@err@
position p;
@@

* code@p;

@script:python depends on detect@
p << err.p;    // Matches @err@ rule name
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

### Mistake 5: Forgetting `virtual detect`
```cocci
// WRONG: Missing virtual declaration
/// Files: foo.c
/// Fix: abc123

@err@

// CORRECT: Always include
/// Files: foo.c
/// Fix: abc123

virtual detect

@err@
```

## File Naming Convention

**Format**: `CVE-YYYY-NNNNN.cocci`

- YYYY: 4-digit year
- NNNNN: 4-7 digit CVE number
- Extension: Always `.cocci`
- No prefixes or suffixes

**Examples**:
- `CVE-2020-12912.cocci` ✓
- `CVE-2016-5195.cocci` ✓
- `cve-2020-12912.cocci` ✗ (wrong case)
- `CVE-2020-12912.patch` ✗ (wrong extension)
- `rule_CVE-2020-12912.cocci` ✗ (has prefix)

## Repository Integration

### File Placement
```
cvehound/cve/CVE-YYYY-NNNNN.cocci
```

### For Disputed CVEs
```
cvehound/cve/disputed/CVE-YYYY-NNNNN.cocci
```

### Testing Integration
No test edits are needed. Rules are auto-discovered by `get_rule_cves()` and every test
is auto-parametrized over them by `pytest_generate_tests` in `tests/conftest.py`, so
dropping in the `.cocci` file is the whole change. The tests read your `Fix:` and
`Fixes:`/`Detect-To:` headers directly, which is why those hashes must be correct.

If a CVE legitimately fails a test — e.g. the fix was never backported to a stable
branch — register it as data rather than editing a test:

- `missing_backports` in `tests/conftest.py`: `(cve, branch)` pairs.
- `ownfixes` in `tests/test_00_metadata.py`: `(cve, reason)` pairs, for a wrong upstream
  `Fixes:` tag.

## Execution Model

For `.cocci` rules, CVEhound builds this command (`cvehound/__init__.py`):

```bash
spatch \
    --no-includes \             # do not resolve #include directives at all
    --include-headers \         # process .h files as inputs in their own right
    -D detect \                 # enable the "detect" virtual mode
    --chunksize 1 -j 1 \        # one job here; CVEhound parallelizes across CVEs
    --no-show-diff --very-quiet \
    --cocci-file <rule> \
    [--python <sys.executable>] \   # only when spatch > 1.0.4
    -I <kernel>/arch/<arch>/include ... -I <kernel>/include/uapi ... \
    --include <kernel>/include/linux/kconfig.h \
    <every path from the rule's Files: header>
```

`.grep` rules take a different path entirely: `grep -rPzle <pattern> <files>`.

Output goes to stdout as `file:line:col-col: ERROR: CVE-…` and is parsed by CVEhound.
Note the two-level parallelism: `spatch` is pinned to `-j 1` and `__main__.py` fans out
across CVEs with a `ProcessPoolExecutor`, so don't add another layer.

## Learning from Examples

When creating a new rule, find similar CVEs:

### Find Similar Vulnerability Types
```bash
cd cvehound/cve
grep -l "memset" *.cocci          # Initialization bugs
grep -l "copy_to_user" *.cocci    # Information leaks
grep -l "when != if" *.cocci      # Missing checks
grep -l "return 0" *.cocci        # Return value bugs
```

### Study Complex Rules
```bash
# Large comprehensive rules
wc -l *.cocci | sort -n | tail -5

# Rules with dependencies
grep -l "depends on" *.cocci

# Rules with alternatives
grep -l "\\\\(" *.cocci
```

## Decision Matrix: Choosing Metavariables

| Need to Match | Use This | Example |
|---------------|----------|---------|
| Unknown function name | `identifier func` | `identifier func;` |
| Specific function | `symbol func_name` | `symbol kfree;` |
| Any expression | `expression E` | `expression E;` |
| Any statement | `statement S` | `statement S;` |
| Any type | `type T` | `type T;` |
| Location for reporting | `position p` | `position p;` |
| Specific constant | literal | `0444`, `-EINVAL` |
| Any integer | `constant C` | `constant C;` |

## Pattern Complexity Guidelines

### Simple Pattern (Preferred)
- Single rule
- Direct pattern matching
- Minimal context
- Fast execution

```cocci
@err@
position p;
@@

function(...)
{
*   return 0444;@p
}
```

### Medium Pattern
- 2-3 rules with simple dependencies
- Some constraints
- Moderate context

```cocci
@has_feature@
@@

init_function(...)

@err depends on has_feature@
position p;
@@

* usage@p(...);
```

### Complex Pattern (Use When Necessary)
- Multiple rules with dependencies
- Complex constraints
- Alternative patterns
- Multiple detection points

Only use complex patterns when:
- The vulnerability requires checking multiple conditions
- Simple patterns produce too many false positives
- The CVE affects many similar functions (like CVE-2020-12352)

## Output Format

`coccilib.report.print_report` emits `file:line:col-col: message`, so a hit looks like:

```
net/nfc/rawsock.c:123:4-13: ERROR: CVE-YYYY-NNNNN
```

The `coccilib.report.print_report()` function handles this automatically.

## Version Compatibility

CVEhound supports Coccinelle >= 1.0.7. If your rule requires newer features:

```cocci
/// Files: foo.c
/// Fix: abc123
/// Version: 1.0.8

virtual detect
...
```

## Summary: Quick Start Workflow

1. **Gather info**: CVE ID, fix commit hash, affected files
2. **Analyze diff**: `git show <fix_commit>`
3. **Choose strategy**: Missing fix vs unfixed code detection
4. **Pick template**: Use appropriate vulnerability pattern template
5. **Write rule**: Fill in template with specific patterns
6. **Test positive**: Verify detection on vulnerable code
7. **Test negative**: Verify no detection on fixed code
8. **Refine**: Adjust for false positives/negatives
9. **Document**: Ensure all metadata is complete
10. **Integrate**: Place in `cvehound/cve/` directory

## Resources

- Human-oriented guide: `docs/WRITING_RULES.md`
- Quick reference: `docs/COCCINELLE_CHEATSHEET.md`
- Enhanced template: `contrib/template.cocci`
- Minimal template: `contrib/blank.cocci`
- Example rules: `cvehound/cve/*.cocci`
- Coccinelle docs: https://coccinelle.gitlabpages.inria.fr/website/docs/

---

**Agent Optimization Note**: This guide is designed for systematic execution. Follow the decision trees and templates exactly for consistent results. When in doubt, study similar CVEs in the repository and replicate their approach.
