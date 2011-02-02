// don't force a blank line afer every block of declarations
-nbad
// force a blank line after procedure bodies
-bap
// prefer to break long lines before && or || operators
-bbo
// Don't put newlines after commas in multiple declarations
// int foo, bar, baz;
-nbc
// K&R style braces
// if (foo) {
//     bar;
// }
-br
// cuddle 'else' to preceding }
// if (foo) {
//     bar;
// } else {
//     baz;
// }
-ce
// cuddle 'while' to preceding }
// do {
//    foo;
// } while (bar);
-cdw
// K&R style braces in struct declarations
// struct foo {
//    ...
// };
-brs
// BUT the opening brace of a function is at the
// start of it's own line.  Consistent?  Nope.
// int foo(int bar)
// {
//     ...
// }
-blf
// Start comments which follow code on a line, at column 33 (the
// default)
-c33
// Ditto for comments following declarations
-cd33
// Ditto for comments following cpp directives
-cp33
// Don't force comment delimiters onto their own lines
-ncdb
// 'case' statements are not indented relative to the switch
// switch (foo) {
// case BAR:
// }
-cli0
// Don't put a space after a cast operator
-ncs
// Indent block comments to their surrounding code
-d0
// put identifiers in declarations immediately after type
// int foo;
-di1
// Don't format comments starting in column 1
-nfc1
// Don't format comments starting after column 1
-nfca
// try to break long lines where the original code did
-hnl
// indentation is 4 characters
-i4
// tabs are 8 characters (the default)
-ts8
// Don't add extra indentation for multiple opening parens
// or K&R function declarations (not that we should have any)
-ip0
// Maximum line length of long code lines
-l75
// broken 2nd line of function arguments is indented
// to align with open parenthesis e.g.
// long_function_name(first_argument, second_argument,
//                    indented_third_argument)
-lp
// indent nested cpp directives
// #if X
// #    if Y
// #        define Z 1
-ppi4
// goto labels start in column 0
-il0
// No space between a called function name and its args
// function_call(arg1, arg2)
-npcs
// No space between 'sizeof' and its arg
// sizeof(struct foo);
-nbs
// No space inside parentheses
-nprs
// Put the type of a procedure at the start of the same
// line it's definition
// int foo(int bar)
// {
-npsl
// Force a space between 'for' and the following parenthesis
// for (i=0 ; i<5 ; i++) {
-saf
// Force a space between 'if' and the following parenthesis
// if (foo != bar) {
-sai
// Force a space between 'while' and the following parenthesis
// while (foo) {
-saw
// Don't force a * at the beginning of each line of box comments
-nsc
// Don't swallow "optional" blank lines in the original code
-nsob
// Don't force a space before the ';' when it's the entire
// body of a 'for' or 'while'.
-nss
