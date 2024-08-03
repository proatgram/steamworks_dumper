#include "ProtobufDumper/ProtobufCollector.h"

using namespace ProtobufDumper;

std::optional<std::pair<ProtobufCollector::CandidateResult, std::string>> ProtobufCollector::TryParseCandidate(const std::string &name, std::istream &data) {
    google::protobuf::FileDescriptorProto candidate;

    try {
        // Can't determine if it needs a rescan from this due to length or if it just a failure.
        if (!candidate.ParseFromIstream(&data)) {
            throw std::runtime_error("Failed to parse protobuf message.");
        }
    }
    catch (const std::ios_base::failure &ex) {
        return std::make_pair(CandidateResult::Rescan, ex.what());
    }
    catch (const std::exception &ex) {
        return std::make_pair(CandidateResult::Rescan, ex.what());
    }

    m_candidates.push_back(candidate);

    return std::make_pair(CandidateResult::OK, "");
}

const std::list<google::protobuf::FileDescriptorProto>& ProtobufCollector::GetCandidates() const {
    return m_candidates;
}
