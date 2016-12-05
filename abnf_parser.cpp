#include "abnf_parser.h"
#include <cassert>
#include <sstream>

#define EXPR_MATCHED(_matched) {if(_matched) it = jt;}

#define IS_SP(c) (c == 0x20)
#define IS_HTAB(c) (c == 0x09)
#define IS_VCHAR(c) (c >= 0x21 && c <= 0x7e)
#define IS_DIGIT(c) (c >= 0x30 && c <= 0x39)
#define IS_ALPHA(c) ((c >= 0x41 && c <= 0x5a) || (c >= 0x61 && c <= 0x7a))

bool consume_crlf(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;
    if(jt == end || *jt != '\r')
        return false;
    jt++;

    if(jt == end || *jt != '\n')
        return false;
    jt++;

    EXPR_MATCHED(true);
    return true;
}

bool consume_wsp(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;
    if(jt == end || (!IS_SP(*jt) && !IS_HTAB(*jt)))
        return false;
    jt++;

    EXPR_MATCHED(true);
    return true;
}

bool consume_comment(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;
    if(jt == end || *jt != ';')
        return false;
    jt++;

    for(;;)
    {
        while(consume_wsp(jt, end));

        if(jt == end)
            return false;
        if(IS_VCHAR(*jt))
            jt++;

        if(consume_crlf(jt, end))
        {
            EXPR_MATCHED(true);
            return true;
        }
    }

    assert(false);
}

bool consume_c_nl(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;
    if(!consume_comment(jt, end) && !consume_crlf(jt, end))
        return false;

    EXPR_MATCHED(true);
    return true;
}

bool consume_c_wsp(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;
    if(consume_wsp(jt, end))
    {
        EXPR_MATCHED(true);
        return true;
    }

    if(!consume_c_nl(jt, end))
        return false;
    if(!consume_wsp(jt, end))
        return false;

    EXPR_MATCHED(true);
    return true;
}

abnf_element::abnf_element(abnf_parser& parser) : parser(parser)
{
}

bool abnf_element::generate_group_or_option(
    str_const_iterator& it, const str_const_iterator& end, bool is_option)
{
    str_const_iterator jt = it;
    if(jt == end || *jt != (is_option ? '[' : '('))
        return false;
    jt++;

    while(consume_c_wsp(jt, end));

    this->element.reset(new abnf_alternation(this->parser));
    if(!this->element->generate(jt, end))
        return false;

    while(consume_c_wsp(jt, end));

    if(jt == end || *jt != (is_option ? ']' : ')'))
        return false;
    jt++;

    this->is_option = is_option;
    EXPR_MATCHED(true);
    return true;
}

bool abnf_element::generate(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;
    
    // rulename
    this->element.reset(new abnf_rulename(this->parser));
    if(this->element->generate(jt, end))
    {
        EXPR_MATCHED(true);
        return true;
    }

    // group
    if(this->generate_group_or_option(jt, end, false))
    {
        EXPR_MATCHED(true);
        return true;
    }

    // option
    if(this->generate_group_or_option(jt, end, true))
    {
        EXPR_MATCHED(true);
        return true;
    }

    // vals
    this->element.reset(new abnf_vals(this->parser));
    if(this->element->generate(jt, end))
    {
        EXPR_MATCHED(true);
        return true;
    }

    return false;
}

bool abnf_element::run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t& r) const
{
    assert(this->element.get());

    str_const_iterator jt = it;
    bool m = (this->element->run(jt, end, r) || this->is_option);

    EXPR_MATCHED(m);
    return m;
}

abnf_vals::abnf_vals(abnf_parser& parser) :
    abnf_element(parser)
{
}

bool abnf_vals::generate(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;

    // parse char-val
    if(jt != end && *jt == '\"')
    {
        this->char_val = "";

        jt++;
        for(;;)
        {
            if(jt == end)
                return false;
            if(*jt == '\"')
            {
                jt++;
                this->type = CHAR_VAL;
                this->sensitive = false;
                EXPR_MATCHED(true);
                return true;
            }
            if((*jt >= 0x20 && *jt <= 0x21) || (*jt >= 0x23 && *jt <= 0x7e))
                this->char_val += *jt;
            else
                return false;
            jt++;
        }
    }
    else if(jt != end && *jt == '%')
    {
        abnf_parser parser;
        matched_patterns_t out;
        // spaces are omitted in some places to make the generation faster
        bool add = parser.add_rule("DIGIT = \"0\"|\"1\"|\"2\"|\"3\"|\"4\"|\"5\"|\"6\"|\"7\"|\"8\"|\"9\"");
        add = parser.add_rule("HEXDIG = DIGIT|\"A\"|\"B\"|\"C\"|\"D\"|\"E\"|\"F\"");
        add = parser.add_rule("BIT = \"0\"|\"1\"");
        add = parser.add_rule("DOT = \".\"");
        add = parser.add_rule("DASH = \"-\"");
        add = parser.add_rule("HEXSTR = 1*HEXDIG");
        add = parser.add_rule("DECSTR = 1*DIGIT");
        add = parser.add_rule("BINSTR = 1*BIT");

        add = parser.add_rule("hex-val = \"x\" HEXSTR [1*(DOT 1*HEXDIG)|(DASH 1*HEXDIG)]"); 
        add = parser.add_rule("dec-val = \"d\" DECSTR [1*(DOT 1*DIGIT)|(DASH 1*DIGIT)]");
        add = parser.add_rule("bin-val = \"b\" BINSTR [1*(DOT 1*BIT)|(DASH 1*BIT)]");
    
        add = parser.add_rule("num-val = bin-val|dec-val|hex-val");
        add = parser.generate("\"%\" num-val");

        if(parser.run(jt, end, out))
        {
            int num = -1;
            if(!out["bin-val"].empty())
            {
                assert(false); // bin not implemented
                parser.add_rule("STR = 1*BIT");
                num = 0;
            }
            else if(!out["dec-val"].empty())
            {
                parser.add_rule("STR = 1*DIGIT");
                num = 1;
            }
            else if(!out["hex-val"].empty())
            {
                parser.add_rule("STR = 1*HEXDIG");
                num = 2;
            }
            assert(num != -1);

            if(!out["DOT"].empty())
            {
                std::string num_val = out["num-val"];
                str_const_iterator kt = num_val.begin();

                if(num == 0)
                {
                    parser.add_rule("STR = 1*BIT");
                    parser.add_rule("iterator = [\"b\"] STR [\".\"]");
                }
                else if(num == 1)
                {
                    parser.add_rule("STR = 1*DIGIT");
                    parser.add_rule("iterator = [\"d\"] STR [\".\"]");
                }
                else if(num == 2)
                {
                    parser.add_rule("STR = 1*HEXDIG");
                    parser.add_rule("iterator = [\"x\"] STR [\".\"]");
                }

                out.clear();
                while(parser.get_rule("iterator")->run(kt, num_val.end(), out))
                {
                    unsigned int val;
                    std::stringstream sts;

                    if(num == 1)
                        sts << std::dec << out["STR"];
                    else if(num == 2)
                        sts << std::hex << out["STR"];

                    sts >> val;
                    this->char_val += (char)val;
                }

                this->type = CHAR_VAL;
                this->sensitive = true;
                EXPR_MATCHED(true);
                return true;
            }
            else if(!out["DASH"].empty())
            {
                std::string num_val = out["num-val"];
                str_const_iterator kt = num_val.begin();

                if(num == 0)
                {
                    parser.add_rule("STR = 1*BIT");
                    parser.add_rule("iterator = [\"b\"] STR [\"-\"]");
                }
                else if(num == 1)
                {
                    parser.add_rule("STR = 1*DIGIT");
                    parser.add_rule("iterator = [\"d\"] STR [\"-\"]");
                }
                else if(num == 2)
                {
                    parser.add_rule("STR = 1*HEXDIG");
                    parser.add_rule("iterator = [\"x\"] STR [\"-\"]");
                }

                int i = 0;
                unsigned int val[2];
                out.clear();
                while(parser.get_rule("iterator")->run(kt, num_val.end(), out))
                {
                    std::stringstream sts;

                    if(num == 1)
                        sts << std::dec << out["STR"];
                    else if(num == 2)
                        sts << std::hex << out["STR"];

                    sts >> val[i % 2];
                    i++;
                }
                assert(i == 2);

                this->type = RANGE_VAL;
                this->range.first = val[0];
                this->range.second = val[1];
                EXPR_MATCHED(true);
                return true;
            }
            else
            {
                std::stringstream sts;
                unsigned int val;
                if(num == 1)
                    sts << std::dec << out["DECSTR"];
                else if(num == 2)
                    sts << std::hex << out["HEXSTR"];
                sts >> val;

                this->type = RANGE_VAL;
                this->range.first = val;
                this->range.second = val;
                EXPR_MATCHED(true);
                return true;
            }
        }
    }
    else if(jt != end && *jt == '<')
    {
        abnf_parser parser;
        matched_patterns_t out;
        bool add = parser.add_rule("STR = *(%x20-3D|%x3F-7E)");
        add = parser.generate("\"<\" STR \">\"");

        if(parser.run(jt, end, out))
        {
            assert(!out["STR"].empty());
            this->type = CHAR_VAL;
            this->sensitive = false;
            this->char_val = out["STR"];
            EXPR_MATCHED(true);
            return true;
        }
    }

    return false;
}

bool abnf_vals::run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t& r) const
{
    str_const_iterator jt = it;
    if(this->type == CHAR_VAL)
    {
        for(auto kt = this->char_val.begin(); kt != this->char_val.end(); kt++, jt++)
            if(jt == end || (this->sensitive ? (*kt != *jt) : (tolower(*kt) != tolower(*jt))))
                return false;
        EXPR_MATCHED(true);
        return true;
    }
    else if(this->type == RANGE_VAL)
    {
        if(jt == end)
            return false;

        for(int i = this->range.first; i <= this->range.second; i++)
            if(*jt == (char)i)
            {
                jt++;
                EXPR_MATCHED(true);
                return true;
            }
        return false;
    }

    return false;
}

abnf_rulename::abnf_rulename(abnf_parser& parser) :
    abnf_element(parser)
{
}

bool abnf_rulename::generate_rulename(
    str_const_iterator& it, const str_const_iterator& end, std::string& rulename)
{
    str_const_iterator jt = it, kt = it;
    if(jt == end || !IS_ALPHA(*jt))
        return false;
    jt++;

    EXPR_MATCHED(true);

    for(;;)
    {
        if(jt == end || (!IS_ALPHA(*jt) && !IS_DIGIT(*jt) && *jt != '-'))
            break;
        jt++;
        EXPR_MATCHED(true);
    }

    rulename.assign(kt, it);

    return true;
}

bool abnf_rulename::generate(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;

    std::string rulename;
    if(!this->generate_rulename(jt, end, rulename))
        return false;

    this->rule = NULL;
    for(auto kt = this->parser.rules.begin(); kt != this->parser.rules.end(); kt++)
        if(kt->rulename == rulename)
        {
            this->rule = &(*kt);
            break;
        }
    if(!this->rule)
        return false;

    EXPR_MATCHED(true);
    return true;
}

bool abnf_rulename::run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t& r) const
{
    assert(this->rule);

    str_const_iterator jt = it;
    bool m = this->rule->run(jt, end, r);

    EXPR_MATCHED(m);
    return m;
}

abnf_repetition::abnf_repetition(abnf_parser& parser) :
    abnf_element(parser),
    element(parser)
{
}

bool abnf_repetition::generate_repeat(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;
    this->repetitions.first = -1;

    bool matched = false;

    if(jt != end && IS_DIGIT(*jt))
    {
        // parse specific repetition
        std::string buffer;

        for(;;)
        {
            buffer += *jt;
            jt++;
            if(jt == end || !IS_DIGIT(*jt))
                break;
        }

        std::stringstream sts;
        sts << buffer;
        sts >> this->repetitions.first;

        this->repetitions.second = this->repetitions.first;
        matched = true;
    }
    if(jt != end && *jt == '*')
    {
        // parse variable(general) repetition
        jt++;
        std::string buffer;
        for(;;)
        {
            if(jt == end || !IS_DIGIT(*jt))
                break;
            buffer += *jt;
            jt++;
        }
        if(!buffer.empty())
        {
            std::stringstream sts;
            sts << buffer;
            sts >> this->repetitions.second;
        }
        else
            this->repetitions.second = -1;

        matched = true;
    }

    EXPR_MATCHED(matched);
    return matched;
}

bool abnf_repetition::generate(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;

    if(this->generate_repeat(jt, end))
        this->has_repeat = true;
    else
        this->has_repeat = false;

    if(this->element.generate(jt, end))
    {
        EXPR_MATCHED(true);
        return true;
    }
    return false;
}

bool abnf_repetition::run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t& r) const
{
    str_const_iterator jt = it;

    if(!this->has_repeat)
    {
        bool m = this->element.run(jt, end, r);
        EXPR_MATCHED(m);
        return m;
    }
    else
    {
        // TODO: decide if use size_t instead of int
        int count = 0;
        while(this->element.run(jt, end, r)) count++;
        
        if(count < this->repetitions.first 
            || (count > this->repetitions.second && this->repetitions.second != -1))
            return false;

        EXPR_MATCHED(true);
        return true;
    }
}

abnf_concatenation::abnf_concatenation(abnf_parser& parser) :
    abnf_element(parser),
    left(parser)
{
}

bool abnf_concatenation::generate(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;
    if(!this->left.generate(jt, end))
        return false;

    EXPR_MATCHED(true);

    for(;;)
    {
        bool b = false;
        while(consume_c_wsp(jt, end)) b = true;
        if(!b)
            break;

        abnf_repetition right(this->parser);
        if(!right.generate(jt, end))
            break;
        this->right.push_back(right);

        EXPR_MATCHED(true);
    }

    return true;
}

bool abnf_concatenation::run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t& r) const
{
    str_const_iterator jt = it;

    if(!this->left.run(jt, end, r))
        return false;
    else
    {
        for(auto kt = this->right.begin(); kt != this->right.end(); kt++)
            if(!kt->run(jt, end, r))
                return false;
    }

    EXPR_MATCHED(true);
    return true;
}

abnf_alternation::abnf_alternation(abnf_parser& parser) : 
    abnf_element(parser),
    left(parser)
{
}

bool abnf_alternation::generate(str_const_iterator& it, const str_const_iterator& end)
{
    str_const_iterator jt = it;
    if(!this->left.generate(jt, end))
        return false;

    EXPR_MATCHED(true);

    for(;;)
    {
        while(consume_c_wsp(jt, end));
        if(jt == end || (*jt != '/' && *jt != '|'))
            break;
        jt++;

        while(consume_c_wsp(jt, end));

        abnf_concatenation right(this->parser);
        if(!right.generate(jt, end))
            break;
        this->right.push_back(right);

        EXPR_MATCHED(true);
    }

    return true;
}

bool abnf_alternation::run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t& r) const
{
    str_const_iterator jt = it;
    if(this->left.run(jt, end, r))
    {
        EXPR_MATCHED(true);
        return true;
    }
    else
    {
        for(auto kt = this->right.begin(); kt != this->right.end(); kt++)
        {
            if(kt->run(jt, end, r))
            {
                EXPR_MATCHED(true);
                return true;
            }
        }
    }
    return false;
}

abnf_rule::abnf_rule(abnf_parser& parser, bool store_matched) : 
    parser(parser), 
    alternation(parser),
    generated(false),
    store_matched(store_matched)
{
}

bool abnf_rule::generate(str_const_iterator& it, const str_const_iterator& end)
{
    assert(!this->generated);

    str_const_iterator jt = it;

    // validates and stores the rulename
    abnf_rulename rulename(this->parser);
    std::string rulename_str;
    if(!rulename.generate_rulename(jt, end, rulename_str))
        return false;
    this->rulename = rulename_str;

    // defined-as
    while(consume_c_wsp(jt, end));
    if(jt == end || *jt != '=')
        return false;
    jt++;
    if(jt != end && *jt == '/')
    {
        this->incremental = true;
        jt++;
    }
    while(consume_c_wsp(jt, end));

    // elements
    if(!this->alternation.generate(jt, end))
        return false;
    while(consume_c_wsp(jt, end));

    // c-nl
    if(!consume_c_nl(jt, end))
        return false;

    this->generated = true;
    EXPR_MATCHED(true);
    return true;
}

bool abnf_rule::run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t& out) const
{
    assert(this->generated);
    // TODO: incremental
    str_const_iterator jt = it;
    bool matched = this->alternation.run(jt, end, out);

    // store matched pattern and bind it to rulename
    if(this->store_matched && matched)
        out[this->rulename].assign(it, jt);

    EXPR_MATCHED(matched);
    return matched;
}

abnf_parser::abnf_parser() : entry(*this, false)
{
}

bool abnf_parser::add_rule(std::string syntax, bool store_matched)
{
    syntax += "\r\n";

    abnf_rule rule(*this, store_matched);
    if(!rule.generate(syntax.begin(), syntax.end()))
        return false;
    this->rules.push_back(rule);

    return true;
}

bool abnf_parser::generate(const std::string& syntax)
{
    std::string entry_syntax = "entry = ";
    entry_syntax += syntax;
    entry_syntax += "\r\n";

    return this->entry.generate(entry_syntax.begin(), entry_syntax.end());
}

bool abnf_parser::run(const std::string& input, matched_patterns_t& r) const
{
    return this->run(input.begin(), input.end(), r);
}

bool abnf_parser::run(str_const_iterator& it, const str_const_iterator& end, matched_patterns_t& r) const
{
    return this->entry.run(it, end, r);
}

abnf_rule* abnf_parser::get_rule(const std::string& rulename)
{
    for(auto it = this->rules.begin(); it != this->rules.end(); it++)
        if(it->rulename == rulename)
            return &(*it);
    return NULL;
}

const abnf_rule* abnf_parser::get_rule(const std::string& rulename) const
{
    for(auto it = this->rules.begin(); it != this->rules.end(); it++)
        if(it->rulename == rulename)
            return &(*it);
    return NULL;
}
