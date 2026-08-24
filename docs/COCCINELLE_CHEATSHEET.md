# Coccinelle CVE Detection Cheat Sheet

Quick reference for writing CVE detection rules in CVEhound.

## Basic Rule Structure

```cocci
/// Files: path/to/file.c
/// Fix: commit_hash
/// Fixes: commit_hash

virtual detect

@rule_name@
@@

func(...)
{
*	pattern;
}
```

Rules are match rules only: the `*` lines *are* the report. spatch prints a unified diff of
them on a match, and nothing at all otherwise. No script rule, no `position` metavariable —
rules must run under a spatch built without Python.

## Metavariable Types

| Type | Description | Example |
|------|-------------|---------|
| `identifier id` | Variable/function name | `identifier func;` |
| `expression E` | Any expression | `expression E;` |
| `statement S` | Any statement | `statement S;` |
| `type T` | Any type | `type T;` |
| `symbol sym` | Specific symbol | `symbol kfree;` |

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
* dangerous_func();  // The line to report — this is the whole reporting mechanism
```

**Note**: `*` is the context marker, not a wildcard (that's `...`). It puts the whole
patch into match mode, which flips the default quantification of un-annotated `...` from
`forall` to `exists` — so adding or removing it can change what matches. It cannot be
mixed with `-`/`+`.

Two disciplines that decide whether a rule is correct:

- **Star only the rule that reports.** A starred rule prints whenever *it* matches, no
  matter what the other rules did — a `*` on a helper rule (e.g. one that recognises the
  fix) fires on fixed trees.
- **Star only the identifying line(s).** With several starred lines separated by `...`,
  spatch prints the prefix it managed to match even when the rest of the pattern fails.

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

`depends on` is how a rule expresses "all of these must hold": chain the rules so the last
one depends on the rest, and star only that last rule. Separate starred rules are an OR —
each reports on its own.

## Common Vulnerability Patterns

The canonical catalog. Each entry names real rules in `cvehound/cve/` — read those
before copying a template; they are ground truth, these are sketches.

### Uninitialized Variable
Real rules: `CVE-2020-12352`, `CVE-2018-11508`
```cocci
@err@
identifier var;
@@

func(...)
{
	struct foo var;
	... when != memset(&var, 0, sizeof(var));
		when != var = ...;
*	use(&var);
}
```

### Missing NULL Check
Real rules: `CVE-2019-15924`
```cocci
@err exists@
identifier ptr;
statement S;
@@

target_func(...)
{
	... when != if (!ptr) S
		when != if (ptr == NULL) S
*	ptr->field;
}
```

### Missing Bounds Check
Real rules: `CVE-2014-0049`, `CVE-2020-29371`
```cocci
@err exists@
identifier arr, idx;
statement S;
@@

target_func(...)
{
	... when != if (idx >= SIZE) S
		when != if (idx < 0 || idx >= MAX) S
*	arr[idx];
}
```

### Use-After-Free
Real rules: `CVE-2021-3347`
```cocci
@err@
identifier var;
@@

func(...)
{
	kfree(var);
	... when != var = ...
*	use(var);
}
```

Star the use, not the `kfree()`: two starred lines around a `...` let spatch report the
`kfree()` alone when no matching use follows.

### Information Leak
Real rules: `CVE-2014-1738`, `CVE-2016-6156`
```cocci
@err@
identifier var;
@@

func(...)
{
	struct foo var;
	... when != memset(&var, 0, sizeof(var));
*	copy_to_user(..., &var, ...);
}
```

### Incorrect Permission
Real rules: `CVE-2020-12912`
```cocci
@err@
@@

sysfs_func(...)
{
*	return 0444;  // Too permissive (CVE-2020-12912: 0444 -> 0400)
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
@@

func(...)
{
*	shared_data = ...;
}
```

### Integer Overflow
Real rules: `CVE-2015-8746`
```cocci
@err exists@
expression E1, E2;
identifier var, use;
statement S;
@@

func(...)
{
*	var = E1 + E2;
	... when != if (var < E1) S
	use(var);
}
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

## Without Python

Rules are scriptless, so the things a `@script:python@` rule used to do are expressed in
the match rules themselves.

### Report a match
```cocci
@err@
@@

func(...)
{
*	vulnerable_line;
}
```
The starred lines are the report — see the two disciplines under
[Pattern Matching](#pattern-matching) for where the `*` may go.

### Several conditions must hold
```cocci
@a@
@@
pattern_a

@b depends on a@
@@
pattern_b

@err depends on a && b@          // only this rule stars, so only it reports
@@

func(...)
{
*	vulnerable_line;
}
```

### Only inside particular functions
```cocci
@err exists@
@@

\(caller1\|caller2\)(...)
{
	... when any
*	vulnerable_line;
	... when any
}
```

Use `... when any`, not `<+... ...+>`, to wrap a *statement* pattern: both mean "anywhere in
the body, nested blocks included", but the `<+...+>` spelling is orders of magnitude slower
on stock spatch. `<+... e ...+>` is for expression contexts (`if (<+... e ...+>)`).

## Position Markers

Not used for reporting: `position` metavariables and `@p` bindings existed to feed
`@script:python@` report rules, and with the `*` lines carrying the report there is
nothing to bind. They remain valid as a *match constraint* — `cvehound/cve/CVE-2020-27777.cocci`
uses `position p != stub.p;` to exclude the empty-stub definition of a function — which is
the only reason to declare one.

## Testing Commands

### Check syntax
```bash
spatch --parse-cocci CVE.cocci
```

### Run the rule
Pass `-D detect` (the rule declares `virtual detect`; spatch aborts on an undeclared
virtual) and do **not** pass `--no-show-diff` — the diff is the report.
```bash
spatch --no-includes --include-headers -D detect \
    --very-quiet \
    --cocci-file CVE.cocci file.c
```
Output on a hit: a unified diff with the starred lines as `-` lines. No output at all
means the rule did not detect anything.

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
| `--very-quiet` | Minimal output (keeps the diff, drops the banners) |
| `--no-show-diff` | Suppress the diff — **do not use**, it suppresses the report |
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

// Nothing starred: the rule matches and reports nothing
@err@
@@

func(...)
{
	dangerous_func();
}

// Starred helper rule: fires on FIXED trees, because a starred rule
// reports whenever it matches, whatever the other rules did
@fix@
@@

*	safety_check(...);

@err depends on !fix@
@@
...
```

### Do
```cocci
// Specific with context
@err@
@@

specific_func(...)
{
	...
*	return -1;
}

// Star the identifying line only, in the rule that decides
@fix@
@@

	safety_check(...);

@err depends on !fix@
@@

specific_func(...)
{
*	dangerous_func();
}
```

## Quick Examples

### Example 1: Removed Function
```cocci
@err exists@
@@

* removed_vulnerable_func(...)
{
	...
}
```

### Example 2: Wrong Value
```cocci
@err@
@@

visibility_func(...)
{
*	return 0444;  // Should be 0400
}
```

### Example 3: Missing Init
```cocci
@err@
identifier req;
@@

func(...)
{
	struct foo req;
	... when != memset(&req, 0, sizeof(req));
*	send(..., &req);
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
@@

caller(...)
{
*	unsafe_usage(...);
}
```

## Resources

- Full Guide: [WRITING_RULES.md](WRITING_RULES.md)
- Enhanced Template: [../contrib/template.cocci](../contrib/template.cocci)
- Minimal Template: [../contrib/blank.cocci](../contrib/blank.cocci)
- Examples: [../cvehound/cve/](../cvehound/cve/)
- Coccinelle Docs: https://coccinelle.gitlabpages.inria.fr/website/docs/

---

**Quick Tip**: Start with the template, study similar CVEs, test frequently!
