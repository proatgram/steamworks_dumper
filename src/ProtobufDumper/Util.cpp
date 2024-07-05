#include "ProtobufDumper/Util.h"

#include <sstream>

using namespace ProtobufDumper;

std::string Util::ToLiteral(const std::string &input) {
    std::stringstream literal;
    literal << '"';
    for (char c : input) {
        switch (c) {
            case '\a': literal << "\\a"; break;
            case '\b': literal << "\\b"; break;
            case '\f': literal << "\\f"; break;
            case '\n': literal << "\\n"; break;
            case '\r': literal << "\\r"; break;
            case '\t': literal << "\\t"; break;
            case '\v': literal << "\\v"; break;
            case '\\': literal << "\\\\"; break;
            case '\"': literal << "\\\""; break;
            default: literal << c; break;
        }
    }
    literal << '"';
    return literal.str();
}
