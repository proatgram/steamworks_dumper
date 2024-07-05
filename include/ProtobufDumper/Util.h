#pragma once

#include <string>

namespace ProtobufDumper {

class Util {
    public:
        static std::string ToLiteral(const std::string &input);
};

} // namespace ProtobufDumper
