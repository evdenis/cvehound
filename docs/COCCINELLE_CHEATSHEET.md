# Coccinelle CVE Detection Cheat Sheet

Quick reference for writing CVE detection rules in CVEhound.

## Basic Rule Structure

```cocci
/// Files: path/to/file.c
/// Fix: commit_hash
/// Fixes: commit_hash

virtual detect

@rule_name@
position p;
@@

* pattern@p;

@script:python depends on detect@
p << rule_name.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

## Metavariable Types

| Type | Description | Example |
|------|-------------|---------|
| `identifier id` | Variable/function name | `identifier func;` |
| `expression E` | Any expression | `expression E;` |
| `statement S` | Any statement | `statement S;` |
| `type T` | Any type | `type T;` |
| `symbol sym` | Specific symbol | `symbol kfree;` |
| `position p` | Source position | `position p;` |

## Pattern Matching

### Ellipsis (...)
```cocci
func(...)              // Match any arguments
{
    ...                // Match any statements
    code();
    ...                // More statements
}
```

### Wildcard (*)
```cocci
* dangerous_func@p();  // Asterisk is optional, aids in debugging
  dangerous_func@p();  // Also works without asterisk
```

**Note**: Asterisks are optional and only serve debugging purposes.

### Alternatives
```cocci
\(func1\|func2\|func3\)(...)  // Match any of these functions
```

### Disjunction
```cocci
(
  pattern1
|
  pattern2
)
```

## When Constraints

```cocci
... when != memset(...)           // Must NOT have memset
... when != var = ...             // Must NOT have assignment
... when == if (check) ...        // Must have this check
... when any                      // Match anything
... when strict                   // Strict matching
```

## Rule Dependencies

```cocci
@rule1@
@@
pattern1

@rule2 depends on rule1@          // Only if rule1 matched
@@
pattern2

@rule3 depends on !rule1@         // Only if rule1 did NOT match
@@
pattern3

@rule4 depends on rule1 && rule2@ // Both must match
@@
pattern4

@rule5 exists@                    // Relaxed matching
@@
pattern5
```

## Common Vulnerability Patterns

### Uninitialized Variable
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
*   use(&var)@p;
}
```

### Missing NULL Check
```cocci
@err@
identifier ptr;
position p;
@@

func(...)
{
    ... when != if (!ptr) ...
        when != if (ptr == NULL) ...
*   ptr->field@p;
}
```

### Missing Bounds Check
```cocci
@err@
identifier arr, idx;
position p;
@@

func(...)
{
    ... when != if (idx >= SIZE) ...
        when != if (idx < 0 || idx >= MAX) ...
*   arr[idx]@p;
}
```

### Use-After-Free
```cocci
@err@
identifier var;
position p1, p2;
@@

* kfree@p1(var);
  ... when != var = ...
* use(var)@p2;
```

### Information Leak
```cocci
@err@
identifier var;
position p;
@@

func(...)
{
    struct foo var;
    ... when != memset(&var, 0, sizeof(var));
*   copy_to_user(..., &var, ...)@p;
}
```

### Incorrect Permission
```cocci
@err@
position p;
@@

sysfs_func(...)
{
*   return 0777;@p  // Too permissive
}
```

### Missing Lock
```cocci
@locked@
@@

func(...)
{
    spin_lock(...);
    ...
    spin_unlock(...);
}

@err depends on !locked@
position p;
@@

func(...)
{
*   shared_data@p = ...;
}
```

### Integer Overflow
```cocci
@err@
expression E1, E2;
identifier var;
position p;
@@

* var =@p E1 + E2;
  ... when != if (var < E1) ...
  use(var);
```

## Matching Functions

### Function Call
```cocci
target_func(...);
target_func(arg1, arg2);
```

### Function Definition
```cocci
func(...)
{
    ...
}

int func(int param, char *buf)
{
    ...
}
```

### Multiple Functions
```cocci
\(func1\|func2\|func3\)(...)
```

## Matching Structures

### Field Access
```cocci
s->field = value;
s.field = value;
```

### Struct Initialization
```cocci
struct my_struct s = {
    .field1 = val1,
    .field2 = val2,
};
```

### Struct Definition
```cocci
struct foo {
    int field;
    ...
};
```

## Matching Conditionals

```cocci
if (condition)
    statement;

if (...)
    S

if (E1 && E2)
    return -ERROR;
```

## Matching Operators

### Assignment
```cocci
var = value;
*ptr = value;
```

### Bitwise
```cocci
var &= mask;
var |= flags;
var = a & b;
var = a | b;
```

### Arithmetic
```cocci
var = a + b;
var = a - b;
var = a * b;
var = a / b;
```

## Python Scripting

### Basic Report
```cocci
@script:python depends on detect@
p << rule.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')
```

### Multiple Positions
```cocci
@script:python depends on detect@
p1 << rule.p1;
p2 << rule.p2;
@@

coccilib.report.print_report(p1[0], 'ERROR: CVE-YYYY-NNNNN (part 1)')
coccilib.report.print_report(p2[0], 'ERROR: CVE-YYYY-NNNNN (part 2)')
```

### Conditional Reporting
```cocci
@script:python depends on detect@
func << rule.func;
p << rule.p;
@@

if func.startswith("unsafe_"):
    coccilib.report.print_report(p[0], f'ERROR: CVE-YYYY-NNNNN in {func}')
```

## Position Markers

```cocci
@rule@
position p;              // Declare position
@@

* code@p;                // Mark position

@script:python@
p << rule.p;             // Retrieve position
@@

coccilib.report.print_report(p[0], 'ERROR: ...')
```

## Testing Commands

### Basic Test
```bash
spatch --sp-file CVE.cocci file.c
```

### CVEhound Options
```bash
spatch --no-includes --include-headers -D detect \
    --very-quiet --no-show-diff \
    --cocci-file CVE.cocci file.c
```

### Test with CVEhound
```bash
cvehound --kernel /path/to/kernel --cve CVE-YYYY-NNNNN
```

## Common Spatch Options

| Option | Description |
|--------|-------------|
| `--sp-file` | Specify Coccinelle rule file |
| `--cocci-file` | Same as --sp-file |
| `-D detect` | Enable detect virtual mode |
| `--no-includes` | Don't process includes |
| `--include-headers` | Process headers |
| `--very-quiet` | Minimal output |
| `--no-show-diff` | Don't show diffs |
| `--debug` | Debug output |
| `-j N` | Use N parallel jobs |

## Metadata Fields

```cocci
/// Files: path/to/file.c [path/to/file2.c ...]
/// Fix: commit_hash_that_fixed_vulnerability
/// Fixes: commit_hash_that_introduced_bug (if explicitly known)
/// Detect-To: commit_hash (when vulnerable commit not explicitly known)
/// Version: 1.0.8
```

**Note on Detect-To**: Used when the vulnerable commit is not marked explicitly in the commit message, or when we can only guess which commit is vulnerable. The rule should detect the vulnerability up to this commit.

## Common Pitfalls

### Don't
```cocci
// Too generic - will have false positives
@err@
@@

* return -1;

// Missing position marker
@err@
@@

dangerous_func();  // No @p marker
```

### Do
```cocci
// Specific with context
@err@
position p;
@@

specific_func(...)
{
    ...
*   return -1;@p
}

// Always use position marker
@err@
position p;
@@

* dangerous_func@p();
```

## Quick Examples

### Example 1: Removed Function
```cocci
@err exists@
position p;
@@

* removed_vulnerable_func@p(...)
{
    ...
}
```

### Example 2: Wrong Value
```cocci
@err@
position p;
@@

visibility_func(...)
{
*   return 0444;@p  // Should be 0400
}
```

### Example 3: Missing Init
```cocci
@err@
identifier req;
position p;
@@

func(...)
{
    struct foo req;
    ... when != memset(&req, 0, sizeof(req));
*   send(..., &req)@p;
}
```

### Example 4: Dependency Chain
```cocci
@has_vuln_feature@
@@

vuln_feature_init(...)
{
    ...
}

@err depends on has_vuln_feature@
position p;
@@

* unsafe_usage@p(...);
```

## Resources

- Full Guide: [WRITING_RULES.md](WRITING_RULES.md)
- Enhanced Template: [../contrib/template.cocci](../contrib/template.cocci)
- Minimal Template: [../contrib/blank.cocci](../contrib/blank.cocci)
- Examples: [../cvehound/cve/](../cvehound/cve/)
- Coccinelle Docs: https://coccinelle.gitlabpages.inria.fr/website/docs/

---

**Quick Tip**: Start with the template, study similar CVEs, test frequently!
