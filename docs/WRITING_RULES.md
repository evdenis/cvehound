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

#### `Files:` (Required)
Specifies which kernel source files are affected by this CVE. Use relative paths from the kernel root.

```cocci
/// Files: drivers/net/wireless/ath/ath9k/htc_drv_main.c
/// Files: net/bluetooth/a2mp.c net/bluetooth/mgmt.c
/// Files: fs/btrfs/inode.c fs/btrfs/send.c
```

#### `Fix:` (Optional but Recommended)
The git commit hash that fixed the vulnerability in the mainline kernel. This helps with tracking and validation.

```cocci
/// Fix: 1b5e2ed9cf6d86a4a0c563bf5c31f48e6d7e53fc
```

#### `Fixes:` or `Detect-To:` (Optional)
- **Fixes**: The commit hash that introduced the vulnerability (if explicitly known)
- **Detect-To**: Used when the vulnerable commit is not marked explicitly in the commit message, or when we can only guess which commit is vulnerable. Indicates the rule should detect the vulnerability up to this commit.

```cocci
/// Fixes: 4e7c22d447bb6d7e37bfe39ff658486ae78e8d77
/// Detect-To: 6b44d9b8d96b37f72ccd7335b32f386a67b7f1f4
```

#### `Version:` (Optional)
Specifies the minimum required Coccinelle version if the rule uses specific features.

```cocci
/// Version: 1.0.8
```

### Virtual Mode Declaration

```cocci
virtual detect
```

This line declares a virtual mode that CVEhound uses to activate detection patterns. Always include this line after the metadata.

## Coccinelle Basics

Coccinelle uses a declarative pattern-matching language. Here are the fundamental concepts:

### Metavariables

Metavariables are used to match and capture code elements:

```cocci
@rule_name@
identifier func;          // Match any function/variable name
identifier var;           // Match any identifier
type T;                   // Match any type
expression E;             // Match any expression
statement S;              // Match any statement
position p;               // Capture source position (line/column)
symbol specific_func;     // Match a specific symbol name
@@
```

### Ellipsis (`...`)

The ellipsis matches zero or more statements or expressions:

```cocci
@rule@
identifier func, var;
@@

func(...)
{
    ...                  // Match any statements
    var = 0;            // Then this specific assignment
    ...                 // Then any more statements
}
```

### Wildcards (`*`)

The asterisk marks lines for debugging purposes (optional):

```cocci
@err@
position p;
@@

* dangerous_function@p(...)    // Asterisk is optional, aids in debugging
  dangerous_function@p(...)    // Also works without asterisk
```

Note: Asterisks are optional and only serve debugging purposes for pattern visualization.

### When Constraints

Control what can appear in matched regions:

```cocci
@rule@
identifier var;
@@

func(...)
{
    struct foo var;
    ... when != memset(&var, 0, sizeof(var));    // Must NOT have memset
    use_var(&var);
}
```

Common constraints:
- `when !=`: Must not match
- `when ==`: Must match
- `when any`: Match anything
- `when strict`: Strict matching (no other statements)

### Rule Dependencies

Rules can depend on other rules:

```cocci
@has_feature@
@@

feature_function(...)
{
    ...
}

@err depends on has_feature@    // Only check if has_feature matched
position p;
@@

* buggy_code@p();
```

Dependency keywords:
- `depends on rule_name`: Execute only if `rule_name` matched
- `depends on !rule_name`: Execute only if `rule_name` did NOT match
- `exists`: Relax matching constraints (more permissive)
- `ever exists`: Even more permissive matching

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

### Pattern 1: Uninitialized Variables

Detects when a variable is used without proper initialization:

```cocci
@err@
identifier var;
position p;
@@

func(...)
{
    struct foo var;
    ... when != memset(&var, 0, sizeof(var));
        when != var = ...;
*   use_variable(&var)@p;
}
```

**CVE Examples**: CVE-2020-12352, CVE-2020-29371

### Pattern 2: Missing Bounds Checking

Detects operations without proper validation:

```cocci
@err@
identifier arr, idx;
position p;
@@

func(...)
{
    ... when != if (idx >= ARRAY_SIZE(arr)) ...
        when != if (idx < 0 || idx >= MAX) ...
*   arr[idx]@p = ...;
}
```

**CVE Examples**: CVE-2014-0049, CVE-2021-3564

### Pattern 3: Incorrect Permission Values

Detects insecure permission settings:

```cocci
@err@
position p;
@@

some_visibility_func(...)
{
*   return 0777;@p    // Too permissive
}
```

**CVE Examples**: CVE-2020-12912

### Pattern 4: Missing NULL Checks

Detects pointer dereference without NULL validation:

```cocci
@err@
identifier ptr;
position p;
@@

func(...)
{
    ... when != if (ptr == NULL) ...
        when != if (!ptr) ...
        when != BUG_ON(!ptr);
*   ptr->field@p = ...;
}
```

**CVE Examples**: Various NULL pointer dereference CVEs

### Pattern 5: Use-After-Free

Detects variable usage after it has been freed:

```cocci
@err@
identifier x;
position p1, p2;
@@

* kfree@p1(x);
  ... when != x = ...
* use(x)@p2;
```

**CVE Examples**: Many UAF vulnerabilities

### Pattern 6: Missing Lock Protection

Detects access to shared data without proper locking:

```cocci
@locked@
identifier func;
@@

func(...)
{
    spin_lock(...);
    ...
    spin_unlock(...);
}

@err depends on !locked@
identifier shared_var;
position p;
@@

func(...)
{
*   shared_var@p = ...;
}
```

### Pattern 7: Integer Overflow

Detects potential integer overflow conditions:

```cocci
@err@
expression E1, E2;
identifier var;
position p;
@@

* var =@p E1 + E2;
  ... when != if (var < E1) ...
      when != if (var < E2) ...
  use(var);
```

### Pattern 8: Information Leak

Detects uninitialized data being copied to userspace:

```cocci
@err@
identifier var;
position p;
@@

func(...)
{
    struct foo var;
    ... when != memset(&var, 0, sizeof(var));
*   copy_to_user(..., &var, sizeof(var))@p;
}
```

**CVE Examples**: CVE-2020-29371, CVE-2020-12352

## Step-by-Step Guide

### Step 1: Understand the CVE

1. Read the CVE description
2. Find the fix commit in the kernel git repository
3. Use `git show <commit_hash>` to see the changes
4. Identify what makes the code vulnerable

Example:
```bash
git show 1b5e2ed9cf6d86a4a0c563bf5c31f48e6d7e53fc
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

### Do's

1. **Keep patterns specific**: Avoid overly generic patterns that cause false positives
2. **Use meaningful rule names**: `@err@`, `@missing_check@`, `@vuln_pattern@`
3. **Add comments**: Explain complex patterns
4. **Test thoroughly**: Test on both vulnerable and fixed versions
5. **Use position markers**: Always use `position p;` and `@p` for error reporting
6. **Match function context**: Include function name when possible
7. **Use constraints**: Leverage `when !=` to avoid false positives
8. **Consider variations**: Use alternatives for different code styles

### Don'ts

1. **Don't be too generic**: Avoid patterns like `return -1;` without context
2. **Don't assume formatting**: Code may have different spacing/indentation
3. **Don't forget edge cases**: Consider macro expansions, conditional compilation
4. **Don't over-constrain**: Too many constraints may miss valid matches
5. **Don't hardcode constants**: Unless they're part of the vulnerability
6. **Don't ignore context**: Always consider surrounding code

### Performance Tips

1. **Use `symbol` when possible**: Faster than `identifier` for known names
2. **Limit `...` scope**: Use constraints to reduce search space
3. **Use `depends on`**: Skip unnecessary checks
4. **Avoid nested `...`**: Can be slow on large files
5. **Specify file patterns**: Help CVEhound skip irrelevant files

### Accuracy Tips

1. **Validate against fix commit**: Ensure pattern matches the actual vulnerability
2. **Check false positives**: Test on unrelated code
3. **Consider backports**: Pattern should work on different kernel versions
4. **Handle macros**: Understand how macros expand
5. **Review similar CVEs**: Learn from existing rules

## Testing Your Rules

### Manual Testing with Spatch

Test directly with Coccinelle:

```bash
# Basic test
spatch --sp-file CVE-2020-12345.cocci file.c

# With CVEhound options
spatch --no-includes --include-headers -D detect \
    --very-quiet --no-show-diff \
    --cocci-file CVE-2020-12345.cocci \
    file.c
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

Add test cases to `tests/test_03_on_fix.py`:

```python
@pytest.mark.parametrize("cve,kernel,commit", [
    # ... existing tests ...
    ("CVE-2020-12345", "torvalds", "1b5e2ed9cf6d"),  # Your new test
])
def test_cve_on_fix(cve, kernel, commit):
    # Test will verify CVE is NOT detected on fixed commit
    pass
```

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

Report multiple vulnerable locations:

```cocci
@err@
position p1, p2;
@@

* vulnerable_call1@p1(...);
  ...
* vulnerable_call2@p2(...);

@script:python depends on detect@
p1 << err.p1;
p2 << err.p2;
@@

coccilib.report.print_report(p1[0], 'ERROR: CVE-YYYY-NNNNN (location 1)')
coccilib.report.print_report(p2[0], 'ERROR: CVE-YYYY-NNNNN (location 2)')
```

**Example**: CVE-2020-12352 - reports 10 different vulnerable function calls

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

### Context-Sensitive Matching

Match code only in specific contexts:

```cocci
@in_atomic@
@@

(
spin_lock(...);
|
rcu_read_lock(...);
)

@err depends on in_atomic@
position p;
@@

* might_sleep_function@p(...);  // Bug: sleeping in atomic context
```

### Handling Function Pointers

Match function pointer assignments:

```cocci
@err@
identifier ops, unsafe_func;
position p;
@@

struct file_operations ops = {
    ...
*   .open = unsafe_func,@p
    ...
};
```

### Variable Value Tracking

Track variable assignments and usage:

```cocci
@err@
identifier var, bad_value;
position p1, p2;
@@

* var =@p1 bad_value;
  ... when != var = ...
* use_var(var)@p2;  // Using bad value
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
2. Place file in `cvehound/cve/` directory
3. Include complete metadata (Files, Fix, Fixes)
4. Test thoroughly on vulnerable and fixed code
5. Add test cases to the test suite
6. Submit pull request with clear description
7. Reference CVE sources and fix commits

## License

All CVE detection rules in CVEhound are licensed under GPLv2, following the Linux kernel license.

---

**Document Version**: 1.0
**Last Updated**: November 2024
**Maintained By**: CVEhound Contributors
