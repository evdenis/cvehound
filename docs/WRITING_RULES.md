# Writing Coccinelle Detection Rules for CVE Patterns

This is the complete guide to writing CVEhound detection rules, for humans and coding
agents alike. It covers how to go from a kernel fix commit to a working `.cocci` rule.

Two companion documents:

- [COCCINELLE_CHEATSHEET.md](COCCINELLE_CHEATSHEET.md) — the syntax reference and the
  catalog of vulnerability patterns. This guide assumes it; read it first.
- `AGENTS.md` in the repository root — the repository's own conventions (tests, style,
  architecture).

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Rule Structure and Metadata](#rule-structure-and-metadata)
4. [Coccinelle Basics](#coccinelle-basics)
5. [Choosing a Detection Strategy](#choosing-a-detection-strategy)
6. [Pattern Construction Rules](#pattern-construction-rules)
7. [Pattern Matching Techniques](#pattern-matching-techniques)
8. [Common Vulnerability Patterns](#common-vulnerability-patterns)
9. [Step-by-Step Guide](#step-by-step-guide)
10. [Best Practices](#best-practices)
11. [Common Mistakes to Avoid](#common-mistakes-to-avoid)
12. [Testing Your Rules](#testing-your-rules)
13. [Advanced Techniques](#advanced-techniques)
14. [Execution Model](#execution-model)
15. [Learning from Existing Rules](#learning-from-existing-rules)
16. [Examples Walkthrough](#examples-walkthrough)
17. [Troubleshooting](#troubleshooting)
18. [Additional Resources](#additional-resources)
19. [Contributing](#contributing)
20. [License](#license)

## Overview

CVEhound uses [Coccinelle](https://coccinelle.gitlabpages.inria.fr/website/), a program
matching and transformation tool, to detect vulnerable code patterns in Linux kernel
sources. Each CVE is represented by a `.cocci` file that describes the vulnerable code
pattern or the absence of a fix.

### Two Detection Approaches

CVEhound rules can detect vulnerabilities using two complementary approaches:

1. **Unfixed Code Detection**: Match the vulnerable code pattern directly
   - Example: Detecting insecure permission values, uninitialized variables
   - Use when the vulnerable code has a distinctive pattern

2. **Missing Fix Detection**: Check for the absence of a security fix
   - Example: Detecting missing validation checks or initialization
   - Use when the fix adds new code that wasn't present before

[Choosing a Detection Strategy](#choosing-a-detection-strategy) turns this into a
decision you can make mechanically from the fix diff.

## Prerequisites

Before writing CVE detection rules, you should:

- Understand basic C programming (kernel-level C knowledge is helpful)
- Be familiar with Linux kernel source code structure
- Have Coccinelle installed (version >= 1.0.7)

Gather this information before you write a line of the rule:

- [ ] CVE ID (format: `CVE-YYYY-NNNNN`)
- [ ] Fix commit hash from the Linux kernel git repository
- [ ] The commit that introduced the bug, if it is known
- [ ] The complete diff of the fix (`git show <hash>`)
- [ ] Affected file paths, relative to the kernel root
- [ ] An understanding of what actually makes the code vulnerable

### Recommended Reading

- [Coccinelle Tutorial](https://coccinelle.gitlabpages.inria.fr/website/docs/index.html)
- [Linux Kernel Coding Style](https://www.kernel.org/doc/html/latest/process/coding-style.html)
- The CVE's fix commit from the Linux kernel git repository

## Rule Structure and Metadata

Every Coccinelle rule file in CVEhound follows a consistent structure:

```cocci
/// Files: <affected_files>
/// Fix: <fix_commit_hash>
/// Fixes: <commit_hash> OR Detect-To: <commit_hash>
/// Version: <minimum_spatch_version> (optional)

virtual detect

@<rule_name>@
<metavariable declarations>
position p;
@@

<code pattern to match>

@script:python depends on detect@
p << <rule_name>.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

### Metadata Fields Explained

The header must be the **first contiguous block of `///` lines** in the file — the parser
stops at the first line that doesn't start with `///`. Each field is assigned by simple
overwrite, so a repeated field keeps only the last occurrence; put all paths on one
`Files:` line rather than on several.

These headers are test inputs, not commentary. The whole slow test suite is generated
from them, so a wrong hash is a failing test.

#### `Files:` (should always be set)
Kernel source paths affected by this CVE, space-separated, relative to the kernel root.

```cocci
/// Files: net/bluetooth/a2mp.c net/bluetooth/mgmt.c
```

Nothing enforces this field, which makes a typo dangerous rather than loud: if none of
the listed paths exist, `check_cve` silently skips the rule unless the caller explicitly
requests `all_files=True`. A typo can therefore cause a false negative.

#### `Fix:` (required in practice)
The mainline commit that fixed the vulnerability.

```cocci
/// Fix: 26896f01467a28651f7a536143fe5ac8449d4041
```

`test_03_on_fix` checks out this commit (the rule must **not** fire) and its parent (the
rule **must** fire). Omit it and the test crashes rather than skipping. All rules set it.

#### `Fixes:` or `Detect-To:` (one of them required in practice)
Both populate the same field — use exactly one:

- **`Fixes:`** — the commit that introduced the bug, when it's known.
- **`Detect-To:`** — the earliest commit at which the rule must fire, when the introducing
  commit isn't explicitly marked or can only be guessed.

```cocci
/// Fixes: da4458bda237aa0cb1688f6c359477f203788f6a
/// Detect-To: 8abee9566b7e8eecf566c4daf6be062a27369890
```

`test_04_on_fixes` asserts the rule fires at this commit and not at its parent, and
`test_05_between_fixes_fix` checks every commit in `Fixes..Fix~`. The value may also be
the tag `v2.6.12-rc2`, which is special-cased to mean "present since the start of git
history" (around fifty rules use it).

#### `Version:` (optional)
Minimum spatch version, used when the rule needs newer syntax. The value is parsed by
stripping the dots (`1.0.8` → `108`), so the line must contain the bare version and
nothing else — trailing prose makes rule parsing raise `ValueError`. Below this version
`check_cve` raises `UnsupportedVersion` and the tests skip.

```cocci
/// Version: 1.0.8
```

### Virtual Mode Declaration

```cocci
virtual detect
```

This line declares a virtual mode that CVEhound uses to activate detection patterns.
Always include this line after the metadata. Every report script is written as
`depends on detect`, so a rule without this declaration parses but never reports.

## Coccinelle Basics

The syntax reference — metavariable types, ellipsis, the `*` context marker,
alternatives and disjunction, `when` constraints, rule dependencies and `exists` — lives
in [COCCINELLE_CHEATSHEET.md](COCCINELLE_CHEATSHEET.md). Read it first; this guide
assumes it.

The rest of this document covers what the cheatsheet deliberately leaves out: how to go
from a fix commit to a working rule, and worked examples from real CVEs.

## Choosing a Detection Strategy

Read the fix diff and answer these questions in order. The first "yes" decides the
approach.

```
START: Analyze the fix commit diff
│
├─ Does the fix ADD new code?
│  │
│  ├─ YES → Missing Fix Detection
│  │        Pattern: check for the ABSENCE of the new code
│  │        Example: missing validation check, missing initialization
│  │
│  └─ NO → next question
│
├─ Does the fix CHANGE a value (constant, flag, permission)?
│  │
│  ├─ YES → Unfixed Code Detection
│  │        Pattern: match the OLD (vulnerable) value
│  │        Example: return 0444 → return 0400
│  │
│  └─ NO → next question
│
├─ Does the fix REMOVE code?
│  │
│  ├─ YES → Unfixed Code Detection
│  │        Pattern: detect the presence of the removed code
│  │        Example: a whole vulnerable driver deleted
│  │
│  └─ NO → next question
│
└─ Does the fix REFACTOR or change logic?
   │
   └─ YES → Unfixed Code Detection, or a hybrid
            Pattern: match the distinctive vulnerable shape
            May require multiple rules with dependencies
```

Missing Fix Detection is the trickier of the two: "the check isn't there" is expressed
with `when !=` inside an ellipsis, and it fires on any code that never had the bug in the
first place unless you anchor it to the enclosing function. See
[Example 3](#example-3-missing-initialization---cve-2020-12352).

## Pattern Construction Rules

### Rule 1: Always declare and bind a position

```cocci
@err@
position p;        // REQUIRED: declare the position variable
@@

* vulnerable_code@p(...);  // REQUIRED: bind it with @p
```

Without a bound position there is nothing for the Python script rule to report.

### Rule 2: Mark vulnerable lines with `*`

```cocci
* return 0444;@p         // context marker: the line to report
```

`*` is the context marker, not a wildcard (`...` is). It is not cosmetic: it switches the
whole patch into match mode, which flips the default quantification of un-annotated `...`
from `forall` to `exists`, so adding or removing it can change what matches. It also
cannot be combined with `-`/`+`. Nearly every rule in the repository uses it.

### Rule 3: Use appropriate metavariables

```cocci
identifier func;     // For function/variable names (unknown)
symbol kfree;        // Match this exact name literally, not as a metavariable
expression E;        // For any expression
statement S;         // For any statement
type T;              // For any type
position p;          // For location tracking (required)
```

Full selection table:

| Need to match | Use | Example |
|---------------|-----|---------|
| Unknown function or variable name | `identifier` | `identifier func;` |
| A specific name, matched literally | `symbol` | `symbol kfree;` |
| Any expression | `expression` | `expression E;` |
| Any statement | `statement` | `statement S;` |
| Any type | `type` | `type T;` |
| Location for reporting | `position` | `position p;` |
| A specific constant | write it literally | `0444`, `-EINVAL` |
| Any constant | `constant` | `constant C;` |

`symbol` is the one people miss: it declares a name to be matched literally rather than
bound as a metavariable, which matters when the name you want to match could otherwise be
read as a fresh identifier (`symbol current;`). Around fifty rules use it.

### Rule 4: Scope the pattern with context

Always provide enough context to avoid false positives:

```cocci
// BAD: too generic, matches across the whole tree
@err@
position p;
@@

* return -1;@p

// GOOD: anchored in the function that has the bug
@err@
position p;
@@

vulnerable_function(...)
{
    ...
*   return -1;@p
}
```

### Rule 5: Use ellipsis correctly

```cocci
func(...)              // Match any function arguments
{
    ...                // Match 0 or more statements
    code();
    ...                // More statements
}
```

### Rule 6: Apply constraints with `when`

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

### Pattern complexity: prefer the simplest thing that works

**Simple — one rule, direct match, minimal context.** This is the target. It is fast and
it is what most rules in `cvehound/cve/` look like:

```cocci
@err@
position p;
@@

function(...)
{
*   return 0444;@p
}
```

**Medium — two or three rules with a dependency**, for "the fix introduced X, so only
look for the bug where X exists":

```cocci
@has_feature@
@@

init_function(...)

@err depends on has_feature@
position p;
@@

* usage@p(...);
```

**Complex — many rules, alternatives, several detection points.** Only reach for this
when the vulnerability genuinely requires checking multiple conditions, when simpler
patterns produce too many false positives, or when the CVE affects many similar functions
(as in CVE-2020-12352).

## Pattern Matching Techniques

### Matching Function Calls

```cocci
// Match any call to a specific function
@rule@
@@

target_function(...);

// Match with specific arguments
@rule@
expression E;
@@

target_function(E, NULL);

// Match function definition
@rule@
identifier func;
@@

int func(int param1, char *param2)
{
    ...
}
```

### Matching Struct Members

```cocci
// Match struct field access
@rule@
identifier s;
@@

s->field = 0;

// Match struct initialization
@rule@
@@

struct my_struct s = {
    .field1 = value1,
    .field2 = value2,
};
```

### Matching Conditionals

```cocci
// Match specific condition
@rule@
expression E;
@@

if (E < 0)
    return E;

// Match any conditional
@rule@
statement S;
@@

if (...)
    S
```

### Matching Return Statements

```cocci
// Match specific return value
@rule@
position p;
@@

* return -EINVAL;@p

// Match return with expression
@rule@
expression E;
@@

return E;
```

### Alternative Patterns

Use `\( ... \| ... \)` for alternatives — most often when the same bug lives in several
related functions:

```cocci
// Match any of these function calls
@rule@
@@

\(function1\|function2\|function3\)(...);

// The same bug across renamed variants of one function
@err@
position p;
@@

\(follow_page_pte\|follow_page_mask\|follow_page\)(...)
{
*   vulnerable_pattern@p;
}
```

This is how a single rule keeps working across kernel versions that renamed the function.

### Disjunction

Use `( ... | ... )` within pattern context:

```cocci
@rule@
expression E;
@@

(
* E = unsafe_function1(...);
|
* E = unsafe_function2(...);
)
```

## Common Vulnerability Patterns

The pattern catalog lives in
[COCCINELLE_CHEATSHEET.md](COCCINELLE_CHEATSHEET.md#common-vulnerability-patterns) —
uninitialized variable, missing NULL/bounds check, use-after-free, information leak,
incorrect permission, missing lock, integer overflow. Each entry there names real rules
in `cvehound/cve/` to read alongside it.

Pick the entry matching what the fix did (per
[Choosing a Detection Strategy](#choosing-a-detection-strategy)), then open the real
rules it cites and follow those rather than the sketch.

## Step-by-Step Guide

### Step 1: Understand the CVE

1. Read the CVE description
2. Find the fix commit in the kernel git repository
3. Use `git show <commit_hash>` to see the changes — lines with `-` are the vulnerable
   code, lines with `+` are the fix
4. Identify what makes the code vulnerable

```bash
git show bcf85fcedfdd17911982a3e3564fcfec7b01eebd
```

### Step 2: Choose Detection Strategy

Walk the decision tree in
[Choosing a Detection Strategy](#choosing-a-detection-strategy).

### Step 3: Identify the Code Pattern

Extract the minimal distinguishing pattern. For example, if the fix changed:

```c
// BEFORE (vulnerable):
return 0444;

// AFTER (fixed):
return 0400;
```

The vulnerable pattern is `return 0444;` — but only inside the function the fix touched.

### Step 4: Create the Rule File

Create a file named `CVE-YYYY-NNNNN.cocci` in the `cvehound/cve/` directory, starting
from `contrib/blank.cocci` or the template:

```cocci
/// Files: path/to/affected/file.c
/// Fix: <commit_hash>
/// Fixes: <introduced_commit_hash>

virtual detect

@err@
position p;
@@

<pattern goes here>

@script:python depends on detect@
p << err.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

### Step 5: Write the Pattern

Using the example from Step 3:

```cocci
@err@
position p;
@@

some_visibility_func(...)
{
*   return 0444;@p
}
```

Key points:
- Declare `position p;` and bind it with `@p`
- Mark the line to report with `*`
- Anchor the pattern in the enclosing function

### Step 6: Add Context (if needed)

If the pattern is too generic, add more context:

```cocci
@err@
identifier driver, attr;
position p;
@@

driver_sysfs_ops(...)
{
    ...
    if (attr->mode)
*       return 0444;@p
    ...
}
```

### Step 7: Test the Rule

Check it parses, then run it against the vulnerable and the fixed tree — see
[Testing Your Rules](#testing-your-rules) for the full protocol.

### Step 8: Refine the Pattern

If you get false positives:
- Add more context (function name, surrounding code)
- Use `when !=` constraints
- Add dependencies on other rules

If you miss the vulnerability:
- Simplify the pattern
- Use the `exists` constraint
- Consider alternatives `\( ... \| ... \)`

### Step 9: Document and Submit

1. Ensure metadata is complete and accurate
2. Add comments explaining complex patterns
3. Run `uv run pytest --runslow --cve=CVE-YYYY-NNNNN`
4. Submit a pull request referencing the CVE and the fix commit

## Best Practices

Two rules matter more than any checklist here:

1. **Anchor the pattern in a named function.** A bare `return -1;` or `kfree(x);` with no
   enclosing context is the most common source of false positives. Nearly every real rule
   in `cvehound/cve/` names the function it matches.
2. **Read three similar rules before writing yours.** They are the ground truth for house
   style, and they encode workarounds this prose cannot:
   `grep -l copy_to_user cvehound/cve/*.cocci`.

For the mechanical checks (does it parse, does it fire at `Fix~`, is it silent at `Fix`),
don't rely on judgement — run the suite, see [Testing Your Rules](#testing-your-rules).

When a rule is a judgement call, prefer a false positive: a missed CVE is worse than a
noisy one.

## Common Mistakes to Avoid

### Mistake 1: No position to report

```cocci
// WRONG: nothing for the script rule to bind
@err@
@@

vulnerable_code();

// CORRECT
@err@
position p;
@@

* vulnerable_code@p();
```

### Mistake 2: Pattern too generic

```cocci
// WRONG: will match across the whole tree
@err@
position p;
@@

* return -1;@p

// CORRECT: specific function context
@err@
position p;
@@

specific_function(...)
{
    ...
*   return -1;@p
}
```

### Mistake 3: Wrong position syntax

```cocci
// WRONG: two positions bound on one expression
* vulnerable_code@p1()@p2;

// CORRECT: one position per statement
* vulnerable_code@p();
```

### Mistake 4: Script rule references the wrong rule name

```cocci
@err@
position p;
@@

* code@p;

@script:python depends on detect@
p << err.p;    // must match the @err@ rule name, not something else
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

### Mistake 5: Forgetting `virtual detect`

```cocci
// WRONG: rule parses, matches, and silently reports nothing,
// because every script rule is "depends on detect"
/// Files: foo.c
/// Fix: abc123

@err@

// CORRECT
/// Files: foo.c
/// Fix: abc123

virtual detect

@err@
```

### Mistake 6: One script rule bound to several rules

A script rule fires only if **all** the rules it binds matched. Binding two independent
detection sites to one script rule turns an OR into an AND:

```cocci
// WRONG if err_a and err_b are independent sites:
@script:python depends on detect@
p << err_a.p;
q << err_b.p;
@@

// CORRECT: one script rule per independent site
@script:python depends on detect@
p << err_a.p;
@@
coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')

@script:python depends on detect@
p << err_b.p;
@@
coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

### Mistake 7: A typo in `Files:`

If none of the paths exist in the tree, `check_cve` skips the rule instead of erroring
unless the caller explicitly requests `all_files=True`. This can hide a vulnerable kernel,
so verify each path exists at the `Fix` commit.

## Testing Your Rules

### Manual Testing with Spatch

```bash
# Check the rule parses before anything else
spatch --parse-cocci CVE-2020-12345.cocci

# Run it. -D detect is required: every report script is "depends on detect",
# so without it the rule matches but prints nothing.
spatch --no-includes --include-headers -D detect \
    --very-quiet --no-show-diff \
    --cocci-file CVE-2020-12345.cocci \
    file.c
```

A hit is reported as `file:line:col-col: ERROR: CVE-YYYY-NNNNN`, for example:

```
net/nfc/rawsock.c:123:4-13: ERROR: CVE-2020-12345
```

The three checks that matter, run against a kernel checkout:

```bash
# 1. MUST detect on the vulnerable tree
git checkout <fix_commit>~
spatch ... --cocci-file CVE-YYYY-NNNNN.cocci <affected_file>   # expect a hit

# 2. MUST NOT detect on the fixed tree
git checkout <fix_commit>
spatch ... --cocci-file CVE-YYYY-NNNNN.cocci <affected_file>   # expect silence

# 3. MUST NOT fire on unrelated code
spatch ... --cocci-file CVE-YYYY-NNNNN.cocci <unrelated_file>  # expect silence
```

### Testing with CVEhound

```bash
# Test single CVE
cvehound --kernel /path/to/kernel --cve CVE-2020-12345

# Test with config checking
cvehound --kernel /path/to/kernel --kernel-config --cve CVE-2020-12345

# Generate detailed report
cvehound --kernel /path/to/kernel --cve CVE-2020-12345 --report report.json
```

### Using CVEhound Test Suite

You don't add test cases. `tests/conftest.py` discovers every rule in `cvehound/cve/`
and parametrizes the whole suite over them, so a new `.cocci` file is picked up
automatically:

```shell
uv run pytest --runslow --cve=CVE-2020-12345
```

The tests are driven by your metadata headers — `test_03_on_fix` checks out `Fix:` (must
not detect) and `Fix~` (must detect), `test_04_on_fixes` does the same around
`Fixes:`/`Detect-To:`, and `test_05_between_fixes_fix` checks every commit in between.
An incorrect hash shows up as a test failure.

If a CVE legitimately fails — e.g. the fix was never backported to some stable branch —
add it to the `missing_backports` list in `tests/conftest.py` (or `ownfixes` in
`tests/test_00_metadata.py` if the upstream `Fixes:` tag is wrong) instead of editing a
test function.

### Validation Checklist

Before submitting:

- [ ] File named `CVE-YYYY-NNNNN.cocci` exactly — uppercase `CVE`, no prefix or suffix
- [ ] Placed in `cvehound/cve/` (or `cvehound/cve/disputed/` for disputed CVEs)
- [ ] `virtual detect` present
- [ ] `Files:`, `Fix:`, and one of `Fixes:`/`Detect-To:` present and correct
- [ ] Every path in `Files:` exists in the tree at the `Fix` commit
- [ ] `position p;` declared and bound with `@p`
- [ ] Each script rule binds exactly the rules that should report together
- [ ] CVE ID in the report message matches the filename
- [ ] Parses: `spatch --parse-cocci CVE-YYYY-NNNNN.cocci`
- [ ] Detects at `Fix~`, silent at `Fix`
- [ ] No false positives on unrelated code
- [ ] `uv run pytest --runslow --cve=CVE-YYYY-NNNNN` passes

## Advanced Techniques

### Multiple Rule Dependencies

Create complex detection logic with rule chains:

```cocci
// Check if feature exists
@has_feature@
@@

feature_init(...)
{
    ...
}

// Check if feature is used unsafely
@uses_feature depends on has_feature@
position p;
@@

* feature_unsafe_call@p(...);

// Only report if both conditions are met
@err depends on has_feature && uses_feature@
position p;
@@

* another_vulnerable_pattern@p();
```

**Example**: CVE-2016-5195 (Dirty COW) — checks for function existence before detecting
the vulnerability.

### Matching Macros

Coccinelle expands macros, but you can match macro usage:

```cocci
@err@
position p;
@@

// Match macro call
* UNSAFE_MACRO@p(...);

// Or match the expanded form
* expanded_function@p(...);
```

### Capturing Multiple Positions

When a CVE has several vulnerable sites, the house style is one rule per site — each with
its own `position p;` — and a separate script rule per site:

```cocci
@err_a exists@
position p;
@@

* vulnerable_call1@p(...);

@err_b exists@
position p;
@@

* vulnerable_call2@p(...);

@script:python depends on detect@
p << err_a.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')

@script:python depends on detect@
p << err_b.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

A script rule fires only if **all** its bound rules matched, so binding independent sites
to one script rule silently turns an OR into an AND. See
`cvehound/cve/CVE-2016-5195.cocci` (two independent sites, two script rules) and
`cvehound/cve/CVE-2021-3347.cocci` (three rules deliberately bound at once). Declaring
`position p1, p2;` inside a single rule is not the idiom used here.

This is also the shape to use when the same bug repeats across many functions — one
`@err_funcN exists@` rule per function, each with its own script rule. `CVE-2020-12352`
does this ten times.

### Complex Python Scripts

Use Python for advanced logic:

```cocci
@err@
identifier func;
position p;
@@

* func@p(...)
{
    ...
}

@script:python depends on detect@
func << err.func;
p << err.p;
@@

# Custom validation logic
if func.startswith("unsafe_") and not func.endswith("_safe"):
    coccilib.report.print_report(p[0], f'ERROR: CVE-YYYY-NNNNN in {func}')
```

### Matching Type Definitions

Detect vulnerable type declarations:

```cocci
@err@
identifier T;
position p;
@@

* struct T@p {
    unsigned int field;  // Should be unsigned long
    ...
};
```

## Execution Model

For `.cocci` rules, CVEhound builds this command (`cvehound/__init__.py`):

```bash
spatch \
    --no-includes \             # do not resolve #include directives at all
    --include-headers \         # process .h files as inputs in their own right
    -D detect \                 # enable the "detect" virtual mode
    --chunksize 1 -j 1 \        # one job here; CVEhound parallelizes across CVEs
    --no-show-diff --very-quiet \
    -I <kernel>/arch/<arch>/include ... -I <kernel>/include/uapi ... \
    --include <kernel>/include/linux/kconfig.h \
    --python <sys.executable> \
    --cocci-file <rule> \
    <every path from the rule's Files: header>
```

`.grep` rules take a different path entirely: `grep -rPzle <pattern> <files>`.

Output goes to stdout as `file:line:col-col: ERROR: CVE-…` and is parsed by CVEhound.
Note the two-level parallelism: `spatch` is pinned to `-j 1` and `__main__.py` fans out
across CVEs with a `ProcessPoolExecutor`, so don't add another layer.

Because `--no-includes` is in effect, your rule never sees the contents of headers it
`#include`s. Match what is written in the `.c` file, not what a macro expands to after
preprocessing.

## Learning from Existing Rules

The 500+ rules in `cvehound/cve/` are the real specification. Find ones like yours:

```bash
cd cvehound/cve

# By vulnerability type
grep -l "memset" *.cocci          # initialization bugs
grep -l "copy_to_user" *.cocci    # information leaks
grep -l "when != if" *.cocci      # missing checks

# By technique
grep -lP 'depends on (?!detect)' *.cocci   # real inter-rule dependencies
grep -l '\\(' *.cocci                      # function alternatives
grep -lw 'exists' *.cocci                  # the exists constraint

# The most involved rules, worth reading once
wc -l *.cocci | sort -n | tail -5
```

Note the `-P 'depends on (?!detect)'`: a plain `grep -l "depends on"` matches every rule
in the directory, because each one ends with `@script:python depends on detect@`.

## Examples Walkthrough

### Example 1: Simple Pattern - CVE-2015-4004

**Vulnerability**: Driver with unfixed initialization function

**Fix Commit**: Removed vulnerable driver entirely

**Strategy**: Detect presence of the removed driver initialization function

```cocci
/// Files: drivers/staging/ozwpan/ozmain.c
/// Fix: a73e99cb67e7438e5ab0c524ae63a8a27616c839
/// Detect-To: 62450bca861f206b09b44492b829b419222c4968

virtual detect

@err exists@
position p;
@@

* ozwpan_init@p(...)
{
    ...
}

@script:python depends on detect@
p << err.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-2015-4004')
```

**Explanation**:
- Matches the entire `ozwpan_init` function
- Uses `exists` to relax matching constraints
- If this function exists, the vulnerable driver is present
- Simple and effective for removed/deprecated code

### Example 2: Value-Based Detection - CVE-2020-12912

**Vulnerability**: Incorrect file permission in sysfs attribute

**Fix**: Changed `return 0444;` to `return 0400;`

**Strategy**: Detect the specific insecure return value

```cocci
/// Files: drivers/hwmon/amd_energy.c
/// Fix: 60268b0e8258fdea9a3c9f4b51e161c123571db3
/// Detect-To: 8abee9566b7e8eecf566c4daf6be062a27369890

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

coccilib.report.print_report(p[0], "ERROR: CVE-2020-12912")
```

**Explanation**:
- Matches specific function `amd_energy_is_visible`
- Looks for exact vulnerable value `0444` (read for all)
- Fixed version returns `0400` (read for owner only)
- Context (function name) prevents false positives

### Example 3: Missing Initialization - CVE-2020-12352

**Vulnerability**: Uninitialized struct sent to Bluetooth device

**Fix**: Added `memset(&req, 0, sizeof(req));` before sending

**Strategy**: Detect struct usage without initialization

```cocci
/// Files: net/bluetooth/a2mp.c
/// Fix: eddb7732119d53400f48a02536a84c509692faa8

virtual detect

@err_a2mp_discover_rsp exists@
identifier req;
position p;
@@

a2mp_discover_rsp(...)
{
    ...
    struct a2mp_info_req req;
    ... when != memset(&req, 0, sizeof(req));
*   a2mp_send(..., A2MP_GETINFO_REQ, ..., sizeof(req), &req)@p;
    ...
}

@script:python depends on detect@
p << err_a2mp_discover_rsp.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-2020-12352')
```

**Explanation**:
- Declares `identifier req` to match the variable name
- `when != memset(...)` ensures the struct is NOT initialized
- Detects when uninitialized struct is passed to `a2mp_send`
- This is the canonical Missing Fix Detection shape
- The real rule repeats this block ten times, once per affected function

### Example 4: Complex Dependencies - CVE-2016-5195 (Dirty COW)

**Vulnerability**: Copy-on-write race condition

**Fix**: Multiple changes across memory management

**Strategy**: Check for new function and missing fixes

```cocci
/// Files: mm/gup.c mm/memory.c mm/madvise.c
/// Fix: 19be0eaffa3ac7d8eb6784ad9bdbc7d67ed8e619

virtual detect

// Check if fixed function exists
@madvise exists@
@@

madvise_need_mmap_write(...)
{
    ...
}

// If fixed function exists, check for unfixed pattern 1
@err_follow_page_pte depends on madvise exists@
identifier flags;
position p;
statement S;
@@

\(follow_page_pte\|follow_page_mask\|follow_page\)(..., unsigned int flags, ...)
{
    ...
*   if ((flags & FOLL_WRITE) &&@p !pte_write(...)) S
    ...
}

// Check for unfixed pattern 2
@err_faultin_page depends on madvise exists@
identifier ret, vma, flags;
position p;
@@

\(faultin_page\|__get_user_pages\|get_user_pages\)(...)
{
    ...
    if ((ret & VM_FAULT_WRITE) && !(vma->vm_flags & VM_WRITE))
*       *flags &=@p ~FOLL_WRITE;
    ...
}

@script:python depends on detect@
p << err_follow_page_pte.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-2016-5195')

@script:python depends on detect@
p << err_faultin_page.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-2016-5195')
```

**Explanation**:
- First rule checks if fix introduced `madvise_need_mmap_write`
- Only checks for unfixed patterns if this function exists
- Uses function alternatives with `\(func1\|func2\|func3\)`
- Detects two different unfixed code patterns
- Two separate script rules, so either site reports independently

### Example 5: ASLR Weakness - CVE-2015-1593

**Vulnerability**: Weak stack randomization

**Fix**: Removed function that reduced randomization entropy

**Strategy**: Detect presence of weak randomization function

```cocci
/// Files: arch/x86/mm/mmap.c fs/binfmt_elf.c
/// Fix: 4e7c22d447bb6d7e37bfe39ff658486ae78e8d77

virtual detect

@err_stack_maxrandom_size exists@
position p;
@@

* unsigned int stack_maxrandom_size@p(void)
{
    ...
}

@err_randomize_stack_top exists@
identifier random_variable;
position p;
@@

*   unsigned int random_variable = 0;
    ...
(
*   random_variable =@p get_random_int() % ...;
|
*   random_variable =@p get_random_int() & ...;
)

@script:python depends on detect@
p << err_stack_maxrandom_size.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-2015-1593')

@script:python depends on detect@
p << err_randomize_stack_top.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-2015-1593')
```

**Explanation**:
- Detects the vulnerable `stack_maxrandom_size` function
- Also detects weak randomization pattern in `randomize_stack_top`
- Uses disjunction `( ... | ... )` for alternative operations (% or &)
- Both patterns indicate the vulnerable code is present

## Troubleshooting

### Problem: Pattern doesn't match

**Solutions**:
- Add `exists` constraint to relax matching: `@rule exists@`
- Simplify pattern - remove unnecessary details
- Check for whitespace/formatting differences
- Test with `--debug` flag: `spatch --debug file.c`
- Use `...` to skip over irrelevant code

### Problem: Rule parses and matches but prints nothing

**Solutions**:
- Add `virtual detect` — without it every `depends on detect` script rule is inert
- Pass `-D detect` on the spatch command line
- Check the script rule binds the rule name that actually matched
- Check you are not binding several independent rules to one script rule (that ANDs them)

### Problem: Too many false positives

**Solutions**:
- Add more context (function name, surrounding code)
- Use `when !=` constraints
- Make the pattern more specific
- Add dependencies on other rules
- Check if fix actually addresses your pattern

### Problem: Coccinelle crashes or hangs

**Solutions**:
- Reduce scope with file-specific matching
- Avoid deeply nested `...` patterns
- Split complex rules into smaller ones
- Check for infinite loops in Python scripts
- Increase timeout or memory limits

### Problem: Position not reported correctly

**Solutions**:
- Ensure `position p;` is declared
- Mark correct line with `@p`
- Use `p[0]` in Python script
- Check that position is passed correctly: `p << rule.p;`

### Problem: Rule works in one kernel version but not another

**Solutions**:
- Check if affected code exists in that version
- Account for backported changes
- Use alternative patterns with `\( ... \| ... \)` for renamed functions
- Consider using version-specific metadata

### Problem: Macro expansion issues

**Solutions**:
- Match both macro and expanded forms
- Remember CVEhound runs with `--no-includes`, so headers are not resolved
- Use `--macro-file` option with spatch when testing manually
- Test with actual kernel build system

### Getting Help

1. **Coccinelle Documentation**: https://coccinelle.gitlabpages.inria.fr/website/docs/
2. **Coccinelle Mailing List**: cocci@inria.fr
3. **CVEhound Issues**: https://github.com/evdenis/cvehound/issues
4. **Existing Rules**: Study similar CVE rules in `cvehound/cve/`
5. **Test Suite**: See `tests/` for working examples

## Additional Resources

### Coccinelle Documentation
- [Coccinelle Tutorial](https://coccinelle.gitlabpages.inria.fr/website/docs/main_grammar.html)
- [Semantic Patch Language Reference](https://coccinelle.gitlabpages.inria.fr/website/docs/main_grammar.html)
- [Coccinelle Examples](https://github.com/coccinelle/coccinelle/tree/master/demos)

### Linux Kernel Resources
- [kernel.org vulns.git](https://git.kernel.org/pub/scm/linux/security/vulns.git/)
- [CIP kernel-sec](https://gitlab.com/cip-project/cip-kernel/cip-kernel-sec)
- [Kernel Git Repository](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git)
- [LWN Kernel Coverage](https://lwn.net/Kernel/)

### CVEhound Resources
- [CVEhound Repository](https://github.com/evdenis/cvehound)
- [Existing Rules](../cvehound/cve/)
- [Rule Template](../contrib/template.cocci)
- [Blank Template](../contrib/blank.cocci)

## Contributing

When contributing new CVE detection rules:

1. Follow the naming convention: `CVE-YYYY-NNNNN.cocci` — uppercase `CVE`, four-digit
   year, no prefix or suffix. `cve-2020-12912.cocci`, `CVE-2020-12912.patch`, and
   `rule_CVE-2020-12912.cocci` are all wrong.
2. Place the file in `cvehound/cve/` (or `cvehound/cve/disputed/` for disputed CVEs —
   note those are skipped by the default `--cve assigned`)
3. Include complete metadata (`Files:`, `Fix:`, and one of `Fixes:`/`Detect-To:`)
4. Run `uv run pytest --runslow --cve=CVE-YYYY-NNNNN` — the suite picks the rule up
   automatically; don't add test functions
5. Submit a pull request with a clear description
6. Reference CVE sources and fix commits

## License

All CVE detection rules in CVEhound are licensed under GPLv2, following the Linux kernel license.
