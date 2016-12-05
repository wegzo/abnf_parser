# abnf_parser
Recursive descent parser generator that generates parsers using abnf language. Generated parsers only parse LL grammar.

Usage:

```c++
abnf_parser parser;
matched_patterns_t matched;
parser.add_rule("DIGIT = \"0\"|\"1\"|\"2\"|\"3\"|\"4\"|\"5\"|\"6\"|\"7\"|\"8\"|\"9\"");
parser.add_rule("DIGITSTR = 1*DIGIT");
parser.generate("DIGITSTR");
parser.run("1929", matched);
std::cout << matched["DIGITSTR"] << std::endl;

// couts 1929 because the pattern matched
```
