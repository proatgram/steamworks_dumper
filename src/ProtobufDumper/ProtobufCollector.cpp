#include "ProtobufDumper/ProtobufCollector.h"

using namespace ProtobufDumper;

std::optional<std::pair<ProtobufCollector::CandidateResult, std::string>> ProtobufCollector::TryParseCandidate(const std::string &name, std::istream &data) {
    google::protobuf::FileDescriptorProto candidate;

    try {
        if (!candidate.ParseFromIstream(&data)) {
            throw std::runtime_error("Failed to parse protobuf message.");
        }
    }
    catch (const std::ios_base::failure &ex) {
        return std::make_pair(CandidateResult::Rescan, ex.what());
    }
    catch (const std::exception &ex) {
        return std::make_pair(CandidateResult::Invalid, ex.what());
    }

    m_candidates.push_back(candidate);

    return std::nullopt;
}
