# Writing Coccinelle Detection Rules for CVE Patterns

This guide provides comprehensive documentation on how to write Coccinelle detection rules for CVE patterns in CVEhound. Whether you're contributing a new CVE detection rule or understanding existing ones, this document will help you master the process.

## Table of Contents

1. [Overview](#overview)
2. [Prerequisites](#prerequisites)
3. [Rule Structure and Metadata](#rule-structure-and-metadata)
4. [Coccinelle Basics](#coccinelle-basics)
5. [Pattern Matching Techniques](#pattern-matching-techniques)
6. [Common Vulnerability Patterns](#common-vulnerability-patterns)
7. [Step-by-Step Guide](#step-by-step-guide)
8. [Best Practices](#best-practices)
9. [Testing Your Rules](#testing-your-rules)
10. [Advanced Techniques](#advanced-techniques)
11. [Examples Walkthrough](#examples-walkthrough)
12. [Troubleshooting](#troubleshooting)
13. [Additional Resources](#additional-resources)
14. [Contributing](#contributing)
15. [License](#license)

## Overview

CVEhound uses [Coccinelle](https://coccinelle.gitlabpages.inria.fr/website/), a powerful program matching and transformation tool, to detect vulnerable code patterns in Linux kernel sources. Each CVE is represented by a `.cocci` file that describes the vulnerable code pattern or the absence of a fix.

### Two Detection Approaches

CVEhound rules can detect vulnerabilities using two complementary approaches:

1. **Unfixed Code Detection**: Match the vulnerable code pattern directly
   - Example: Detecting insecure permission values, uninitialized variables
   - Use when the vulnerable code has a distinctive pattern

2. **Missing Fix Detection**: Check for the absence of a security fix
   - Example: Detecting missing validation checks or initialization
   - Use when the fix adds new code that wasn't present before

## Prerequisites

Before writing CVE detection rules, you should:

- Understand basic C programming (kernel-level C knowledge is helpful)
- Familiarity with Linux kernel source code structure
- Basic understanding of the CVE you're writing a rule for
- Read the CVE fix commit and understand what changed
- Have Coccinelle installed (version >= 1.0.7)

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
the listed paths exist, `check_cve` silently falls back to scanning the **entire** kernel
tree, so you get a very slow run and possible false positives instead of an error.

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
history" (47 rules use it).

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

This line declares a virtual mode that CVEhound uses to activate detection patterns. Always include this line after the metadata.

## Coccinelle Basics

The syntax reference — metavariable types, ellipsis, the `*` context marker,
alternatives and disjunction, `when` constraints, rule dependencies and `exists` — lives
in [COCCINELLE_CHEATSHEET.md](COCCINELLE_CHEATSHEET.md). Read it first; this guide
assumes it.

The rest of this document covers what the cheatsheet deliberately leaves out: how to go
from a fix commit to a working rule, and worked examples from real CVEs.

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

Use `\( ... \| ... \)` for alternatives:

```cocci
// Match any of these function calls
@rule@
@@

\(function1\|function2\|function3\)(...);

// Match different operations
@rule@
expression E1, E2;
@@

(
E1 = E2 % 0x1000;
|
E1 = E2 & 0xFFF;
)
```

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

Which pattern you reach for follows from what the fix commit did — see
[Two Detection Approaches](#two-detection-approaches) above and the decision tree in
[AI_AGENT_GUIDE.md](AI_AGENT_GUIDE.md#decision-tree-detection-strategy).

## Step-by-Step Guide

### Step 1: Understand the CVE

1. Read the CVE description
2. Find the fix commit in the kernel git repository
3. Use `git show <commit_hash>` to see the changes
4. Identify what makes the code vulnerable

Example:
```bash
git show bcf85fcedfdd17911982a3e3564fcfec7b01eebd
```

### Step 2: Choose Detection Strategy

Ask yourself:

- **Does the vulnerable code have a unique pattern?** → Use unfixed code detection
- **Does the fix add new code?** → Use missing fix detection
- **Is the change a simple value modification?** → Use unfixed code detection
- **Is the change complex with multiple locations?** → May need multiple rules

### Step 3: Identify the Code Pattern

Extract the key pattern from the CVE. For example, if the fix changed:

```c
// BEFORE (vulnerable):
return 0444;

// AFTER (fixed):
return 0400;
```

The vulnerable pattern is: `return 0444;`

### Step 4: Create the Rule File

Create a file named `CVE-YYYY-NNNNN.cocci` in the `cvehound/cve/` directory.

Start with the template:

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
- Use `position p;` to capture the location
- Optionally mark lines with `*` for debugging
- Add `@p` to associate the position with that location

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

Test on the vulnerable code:

```bash
spatch --no-includes --include-headers -D detect \
    --cocci-file CVE-YYYY-NNNNN.cocci \
    /path/to/kernel/source/file.c
```

Test on the fixed code (should produce no output):

```bash
# Checkout the fixed version
git checkout <fix_commit>
spatch --no-includes --include-headers -D detect \
    --cocci-file CVE-YYYY-NNNNN.cocci \
    /path/to/kernel/source/file.c
```

### Step 8: Refine the Pattern

If you get false positives:
- Add more context
- Use `when` constraints
- Add dependencies on other rules

If you miss the vulnerability:
- Simplify the pattern
- Use `exists` constraint
- Consider using alternatives `\( ... \| ... \)`

### Step 9: Document and Submit

1. Ensure metadata is complete and accurate
2. Add comments explaining complex patterns
3. Test with CVEhound:
   ```bash
   cvehound --kernel /path/to/kernel --cve CVE-YYYY-NNNNN
   ```
4. Submit your contribution

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

`symbol` is worth knowing: it declares a name to be matched literally rather than as a
metavariable (49 rules use it, e.g. `symbol current;`).

## Testing Your Rules

### Manual Testing with Spatch

Test directly with Coccinelle:

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

A hit is reported as `file:line:col-col: ERROR: CVE-YYYY-NNNNN`.

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

- [ ] Rule detects vulnerability in unfixed code
- [ ] Rule does NOT trigger on fixed code
- [ ] Metadata is complete and accurate
- [ ] File paths are correct
- [ ] No false positives on unrelated code
- [ ] Works with different kernel versions
- [ ] Follows naming convention (CVE-YYYY-NNNNN.cocci)
- [ ] Tested with spatch and cvehound
- [ ] Documentation is clear

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

**Example**: CVE-2016-5195 (Dirty COW) - checks for function existence before detecting vulnerability

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
its own `position p;` — and a single script rule that binds them all:

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
q << err_b.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
coccilib.report.print_report(q[0], 'ERROR: CVE-YYYY-NNNNN')
```

Note each script rule fires only if **all** its bound rules matched. To report sites
independently, give each its own script rule — see `cvehound/cve/CVE-2016-5195.cocci`
(two independent sites) and `cvehound/cve/CVE-2021-3347.cocci` (three rules bound at
once). Declaring `position p1, p2;` inside a single rule is not the idiom used here.

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
- This pattern repeats 10 times for different functions in actual rule

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
- Complex CVE requires checking multiple conditions

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
- Use alternative patterns with `\( ... \| ... \)`
- Consider using version-specific metadata

### Problem: Macro expansion issues

**Solutions**:
- Match both macro and expanded forms
- Use `--macro-file` option with spatch
- Include kernel headers properly
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
- [Linux Kernel CVEs](https://www.linuxkernelcves.com/)
- [Kernel Git Repository](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git)
- [LWN Kernel Coverage](https://lwn.net/Kernel/)

### CVEhound Resources
- [CVEhound Repository](https://github.com/evdenis/cvehound)
- [CVEhound Presentations](../docs/)
- [Existing Rules](../cvehound/cve/)
- [Rule Template](../contrib/template.cocci)

## Contributing

When contributing new CVE detection rules:

1. Follow the naming convention: `CVE-YYYY-NNNNN.cocci`
2. Place the file in `cvehound/cve/` (or `cvehound/cve/disputed/` for disputed CVEs —
   note those are skipped by the default `--cve assigned`)
3. Include complete metadata (`Files:`, `Fix:`, and one of `Fixes:`/`Detect-To:`)
4. Run `uv run pytest --runslow --cve=CVE-YYYY-NNNNN` — the suite picks the rule up
   automatically; don't add test functions
5. Submit a pull request with a clear description
6. Reference CVE sources and fix commits

## License

All CVE detection rules in CVEhound are licensed under GPLv2, following the Linux kernel license.
