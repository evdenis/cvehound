/// Files: <path/to/affected/file.c>
/// Fix: <git_commit_hash_that_fixed_the_vulnerability>
/// Fixes: <git_commit_hash_that_introduced_bug> OR Detect-To: <last_vulnerable_commit>
/// Version: <minimum_spatch_version> (optional, e.g., 1.0.8)

// Virtual mode declaration - always include this.
// CVEhound runs spatch with -D detect; without this line spatch aborts with
// "virtual rule detect not supported".
virtual detect

// Main detection rule
// Rule naming: use descriptive names like @err@, @missing_check@, @vuln_pattern@
@err@
// Metavariable declarations:
// identifier func, var;     // Match function/variable names
// expression E;             // Match any expression
// statement S;              // Match any statement
// type T;                   // Match any type
// symbol specific_name;     // Match specific symbol
@@

// Code pattern to match goes here.
// Use ... to match any intermediate code.
// Use * to mark the line(s) that identify the vulnerability: on a match spatch
// prints a diff of the starred lines, and that output IS the report. There is no
// script rule and no position metavariable.
//
// Example patterns:

// Pattern 1: Match a specific function with vulnerable code
// vulnerable_function(...)
// {
//	...
// *	unsafe_operation(...);
//	...
// }

// Pattern 2: Detect missing initialization
// func(...)
// {
//	struct foo var;
//	... when != memset(&var, 0, sizeof(var));
// *	use_var(&var);
// }

// Pattern 3: Detect incorrect return value
// some_function(...)
// {
// *	return UNSAFE_VALUE;
// }

// Pattern 4: Match multiple function alternatives
// \(function1\|function2\|function3\)(...)
// {
// *	vulnerable_code(...);
// }

// Star discipline - the two mistakes that cost the most time:
//
// 1. Star ONLY the rule that reports. A starred rule prints whenever IT matches,
//    no matter what the other rules did, so a * on a helper rule (say a @fix@ rule
//    that recognises the fix) fires on FIXED trees too - a false positive.
// 2. Star ONLY the identifying line(s), not the whole pattern. With several starred
//    lines separated by ..., spatch prints the prefix it managed to match even when
//    the rest of the pattern fails.

// For several INDEPENDENT vulnerable sites, write one starred rule per site.
// Separate starred rules are an OR: either one reports on its own.
//
// @err_site1 exists@
// @@
//
// func1(...)
// {
// *	vulnerable_code(...);
// }
//
// @err_site2 exists@
// @@
//
// func2(...)
// {
// *	other_vulnerable_code(...);
// }

// For conditions that must ALL hold, chain the rules with "depends on" and star
// only the last one. This is the AND:
//
// @has_feature@              // First, check if the feature exists
// @@
//
// feature_function(...)
// {
//	...
// }
//
// @not_fixed depends on has_feature@   // ... and that the fix is absent
// @@
//
// helper_function(...)
// {
//	...
// }
//
// @err depends on has_feature && not_fixed@   // only this rule reports
// @@
//
// * vulnerable_usage(...);

// To restrict a pattern to particular functions, anchor it in the function
// definition rather than filtering afterwards:
//
// @err exists@
// @@
//
// \(callers_fn1\|callers_fn2\)(...)
// {
//	... when any
// *	vulnerable_code(...);
//	... when any
// }
//
// Use "... when any" and not "<+... ...+>" around a statement pattern: they mean
// the same thing, but the <+...+> spelling is orders of magnitude slower on stock
// spatch. <+... e ...+> is for expression contexts, e.g. if (<+... e ...+>).

// For detailed guidance, see: docs/WRITING_RULES.md
