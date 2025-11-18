/// Files: <path/to/affected/file.c>
/// Fix: <git_commit_hash_that_fixed_the_vulnerability>
/// Fixes: <git_commit_hash_that_introduced_bug> OR Detect-To: <last_vulnerable_commit>
/// Version: <minimum_spatch_version> (optional, e.g., 1.0.8)

// Virtual mode declaration - always include this
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
position p;                  // Capture source location for reporting (required)
@@

// Code pattern to match goes here
// Use ... to match any intermediate code
// Use * to mark the vulnerable line
// Use @p to associate the position with a line
//
// Example patterns:

// Pattern 1: Match a specific function with vulnerable code
// vulnerable_function(...)
// {
//     ...
// *   unsafe_operation@p(...);
//     ...
// }

// Pattern 2: Detect missing initialization
// func(...)
// {
//     struct foo var;
//     ... when != memset(&var, 0, sizeof(var));
// *   use_var(&var)@p;
// }

// Pattern 3: Detect incorrect return value
// some_function(...)
// {
// *   return UNSAFE_VALUE;@p
// }

// Pattern 4: Match multiple function alternatives
// \(function1\|function2\|function3\)(...)
// {
// *   vulnerable_code@p(...);
// }


// Python reporting script - this prints the CVE error when pattern is found
@script:python depends on detect@
p << err.p;
@@

coccilib.report.print_report(p[0], 'ERROR: CVE-YYYY-NNNNN')

// For multiple detection points, add additional rules:
//
// @err2@
// position p2;
// @@
//
// another_pattern@p2(...)
//
// @script:python depends on detect@
// p2 << err2.p2;
// @@
//
// coccilib.report.print_report(p2[0], 'ERROR: CVE-YYYY-NNNNN')

// Rule dependencies example:
//
// @has_feature@              // First, check if feature exists
// @@
//
// feature_function(...)
// {
//     ...
// }
//
// @err depends on has_feature@   // Only check if feature exists
// position p;
// @@
//
// * vulnerable_usage@p(...);

// For detailed guidance, see: docs/WRITING_RULES.md
