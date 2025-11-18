/// Files: 
/// Fix: 
/// Fixes: 

virtual detect

@err@
position p;
@@


@script:python depends on detect@
p << err.p;
@@

coccilib.report.print_report(p[0], 'ERROR: ')
