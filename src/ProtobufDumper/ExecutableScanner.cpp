#include "ProtobufDumper/ExecutableScanner.h"

#include <fstream>
#include <iostream>

using namespace ProtobufDumper;

const std::regex ExecutableScanner::ProtoFileNameRegex("^[a-zA-Z_0-9\\/.]+\\.proto$");

void ExecutableScanner::ScanFile(const std::filesystem::path &filePath, ProcessCandidate processCandidate) {
    static const constexpr char markerStart = '\n';
    static const constexpr uint8_t markerLength = 2;

    std::ifstream file(filePath, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Can't open file for scanning.");
    }

    const std::size_t fileSize = std::filesystem::file_size(filePath);
    std::vector<char> data(fileSize);
    file.read(data.data(), fileSize);

    std::size_t scanSkipOffset = 0;

    for (std::size_t i = 0; i < fileSize - 1; i++) {
        char currentByte = data[i];
        char expectedLength = data[i + 1];

        if (currentByte != markerStart) {
            continue;
        }

        std::size_t y = i + scanSkipOffset;
        for (; y < fileSize; y++) {
            if (data[y] == 0) {
                break;
            }
        }

        if (y == fileSize) {
            continue;
        }

        std::size_t length = y - i;

        if (length < markerLength || length - markerLength < expectedLength) {
            continue;
        }

        std::string protoName(data.begin() + i + markerLength, data.begin() + i + markerLength + expectedLength);

        if (!std::regex_match(protoName, ProtoFileNameRegex)) {
            continue;
        }

        std::stringstream ss;
        ss.write(data.data() + i, length);

        if (!processCandidate(protoName, ss)) {
            scanSkipOffset = length + 1;
            i--;
        } else {
            i = y;
            scanSkipOffset = 0;
        }
    }
}
