#pragma once

#include <map>
#include <string>
#include <utility>
#include <vector>
#include <list>
#include <boost/shared_ptr.hpp>

// recursive descent parser generator that generates parsers using
// abnf language. generated parsers only parse LL grammar.

class abnf_parser;
typedef std::string::const_iterator str_const_iterator;
typedef std::map<std::string, std::string> matched_patterns_t;

// element encapsulates () and [] rules
class abnf_element
{
private:
    boost::shared_ptr<abnf_element> element;
    bool is_option;

    bool generate_group_or_option(
        str_const_iterator& it, const str_const_iterator& end, bool is_option);
protected:
    abnf_parser& parser;
public:
    abnf_element(abnf_parser&);

    virtual bool generate(str_const_iterator& it, const str_const_iterator& end);
    virtual bool run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t&) const;
};

class abnf_repetition : public abnf_element
{
private:
    // negative means the value doesn't exist
    bool has_repeat;
    std::pair<int /*n*/, int /*m*/> repetitions;
    abnf_element element;

    bool generate_repeat(str_const_iterator& it, const str_const_iterator& end);
public:
    abnf_repetition(abnf_parser&);

    bool generate(str_const_iterator& it, const str_const_iterator& end);
    bool run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t&) const;
};

class abnf_concatenation : public abnf_element
{
private:
    abnf_repetition left;
    std::vector<abnf_repetition> right;
public:
    abnf_concatenation(abnf_parser&);

    bool generate(str_const_iterator& it, const str_const_iterator& end);
    bool run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t&) const;
};

class abnf_alternation : public abnf_element
{
private:
    abnf_concatenation left;
    std::vector<abnf_concatenation> right;
public:
    abnf_alternation(abnf_parser&);

    bool generate(str_const_iterator& it, const str_const_iterator& end);
    bool run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t&) const;
};

// TODO: add function to alternation to add new element
class abnf_rule
{
private:
    bool generated;
    bool store_matched;

    abnf_parser& parser;
    // same as default element but without '(' and ')'
    abnf_alternation alternation; // elements = alternation *c-wsp
    bool incremental; // false: '=', true: '=/'
    // TODO: defined-as tells how to run the elements
public:
    std::string rulename;

    abnf_rule(abnf_parser&, bool store_matched);

    // elements = alternation *c-wsp
    // parses "rulename defined-as elements c-nl"
    bool generate(str_const_iterator& it, const str_const_iterator& end);
    // runs the stored method using these arguments;
    // returns whether the match was successful
    bool run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t&) const;
};

// rule names are case sensitive
// TODO: should be insensitive
class abnf_rulename : public abnf_element
{
private:
    abnf_rule* rule;
public:
    abnf_rulename(abnf_parser&);

    // stores the rulename to arg
    bool generate_rulename(str_const_iterator& it, const str_const_iterator& end, std::string&);
    // binds this rulename to the rule object
    bool generate(str_const_iterator& it, const str_const_iterator& end);
    bool run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t&) const;
};

class abnf_parser
{
private:
    abnf_rule entry;
public:
    std::list<abnf_rule> rules;

    abnf_parser();

    // syntax = rulename defined-as elements (no need for crlf)
    // add rule automatically generates the rule
    bool add_rule(std::string syntax, bool store_matched = true);
    // NULL if rule not found
    abnf_rule* get_rule(const std::string& rulename);
    const abnf_rule* get_rule(const std::string& rulename) const;

    // syntax is in a form of elements
    bool generate(const std::string& syntax);
    // runs the default entry object
    bool run(const std::string& input, matched_patterns_t&) const;
    bool run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t&) const;
};

// NOTE: numerals have 32 bit unsigned max ranges
// TODO: add binary support
class abnf_vals : public abnf_element
{
private:
    enum type_t {CHAR_VAL, RANGE_VAL};
    type_t type;
    std::string char_val, prose_val;
    std::pair<int, int> range;
    bool sensitive;
public:
    abnf_vals(abnf_parser&);

    bool generate(str_const_iterator& it, const str_const_iterator& end);
    bool run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t&) const;
};
