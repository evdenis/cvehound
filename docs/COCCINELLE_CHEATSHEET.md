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

### Context marker (*)
```cocci
* dangerous_func@p();  // Marks the line to report
```

**Note**: `*` is the context marker, not a wildcard (that's `...`). It puts the whole
patch into match mode, which flips the default quantification of un-annotated `...` from
`forall` to `exists` — so adding or removing it can change what matches. It cannot be
mixed with `-`/`+`.

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
... when != memset(...)                       // region must NOT contain memset
... when != if (!ptr) return -EINVAL;         // ... nor this complete statement
... when != if (!ptr) S                        // S = a declared "statement S;"
... when any                                   // drop the shortest-path restriction
```

The constraint must be a **complete statement**. `when != if (cond) ...` — with a bare
trailing `...` — is a parse error, as is `when ==`. To require that something *is*
present, write a separate rule and gate on it with `depends on`.

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

The canonical catalog. Each entry names real rules in `cvehound/cve/` — read those
before copying a template; they are ground truth, these are sketches.

### Uninitialized Variable
Real rules: `CVE-2020-12352`, `CVE-2018-11508`
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
Real rules: `CVE-2019-15924`
```cocci
@err exists@
identifier ptr;
statement S;
position p;
@@

target_func(...)
{
    ... when != if (!ptr) S
        when != if (ptr == NULL) S
*   ptr->field@p;
}
```

### Missing Bounds Check
Real rules: `CVE-2014-0049`, `CVE-2020-29371`
```cocci
@err exists@
identifier arr, idx;
statement S;
position p;
@@

target_func(...)
{
    ... when != if (idx >= SIZE) S
        when != if (idx < 0 || idx >= MAX) S
*   arr[idx]@p;
}
```

### Use-After-Free
Real rules: `CVE-2021-3347`
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
Real rules: `CVE-2014-1738`, `CVE-2016-6156`
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
Real rules: `CVE-2020-12912`
```cocci
@err@
position p;
@@

sysfs_func(...)
{
*   return 0444;@p  // Too permissive (CVE-2020-12912: 0444 -> 0400)
}
```

### Missing Lock
Real rules: `CVE-2021-3564`
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
Real rules: `CVE-2015-8746`
```cocci
@err exists@
expression E1, E2;
identifier var, use;
statement S;
position p;
@@

* var =@p E1 + E2;
  ... when != if (var < E1) S
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
    ...,
    .field1 = val1,       // note the "...," - a bare "..." here is a parse error
    ...,
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

### Check syntax
```bash
spatch --parse-cocci CVE.cocci
```

### Run the rule
`-D detect` is required — report scripts are `depends on detect`, so without it the rule
matches but prints nothing.
```bash
spatch --no-includes --include-headers -D detect \
    --very-quiet --no-show-diff \
    --cocci-file CVE.cocci file.c
```
Output on a hit: `file:line:col-col: ERROR: CVE-YYYY-NNNNN`

### Test with CVEhound
```bash
cvehound --kernel /path/to/kernel --cve CVE-YYYY-NNNNN
uv run pytest --runslow --cve=CVE-YYYY-NNNNN   # the real validation
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
| `--parse-cocci` | Parse the rule only — first thing to run |
| `-j N` | N parallel jobs (CVEhound pins `-j 1` and parallelizes across CVEs instead) |

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
