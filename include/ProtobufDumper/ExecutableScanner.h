#pragma once

#include <regex>
#include <functional>
#include <filesystem>

namespace ProtobufDumper {

class ExecutableScanner {
    public:
        using ProcessCandidate = std::function<bool(const std::string &, std::istream &buffer)>;

        static void ScanFile(const std::filesystem::path &filePath, ProcessCandidate processCandidate);

    private:
        static const std::regex ProtoFileNameRegex;
};

} // namespace ProtobufDumper
