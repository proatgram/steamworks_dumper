#include "ProtobufDumper/ExecutableScanner.h"

#include <fstream>

using namespace ProtobufDumper;

const std::regex ExecutableScanner::ProtoFileNameRegex("^[a-zA-Z_0-9\\/.]+\\.proto$");

void ExecutableScanner::ScanFile(const std::filesystem::path &filePath, ProcessCandidate processCandidate) {
    static const constexpr char markerStart = '\n';
    static const constexpr uint8_t markerLength = 2;

    std::fstream file(filePath, std::ios_base::in | std::ios_base::binary);
    if (!file) {
        throw std::runtime_error("Can't open file for scanning.");
    }

    const std::size_t fileSize = std::filesystem::file_size(filePath);

    std::streampos scanSkipOffset = 0;

    for (int i = 0; i < fileSize; i++) {
        file.seekg(i, std::fstream::beg);

        char currentByte{};
        char expectedLength{};
        
        file.read(&currentByte, 1);
        file.read(&expectedLength, 1);

        if (currentByte != markerStart) {
            continue;
        }

        int y = i + scanSkipOffset;
        file.seekg(y, std::ios::beg);
        for (; y < fileSize; y++) {
            char data{};
            file.read(&data, 1);
            if (data == 0) {
                break;
            }
        }

        if (y == fileSize) {
            continue;
        }

        int length = y - i;

        if (length < markerLength || length - markerLength < expectedLength) {
            continue;
        }

        std::string protoName('\0', expectedLength);
        file.seekg(i + markerLength, std::ios::beg);
        file.read(protoName.data(), expectedLength);

        if (!std::regex_match(protoName, ProtoFileNameRegex)) {
            continue;
        }

        std::stringstream ss{};

        file.seekg(i, std::ios::beg);
        std::copy_n(std::istreambuf_iterator<char>(file), length, std::ostreambuf_iterator<char>(ss));

        if (!processCandidate(protoName, ss)) {
            scanSkipOffset = length + 1;
            i--;
        }
        else {
            i = y;
            scanSkipOffset = 0;
        }
    }
}
