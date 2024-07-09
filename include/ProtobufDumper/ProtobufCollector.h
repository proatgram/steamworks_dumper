#pragma once

#include <google/protobuf/descriptor.pb.h>

#include <list>
#include <optional>

namespace ProtobufDumper {

class ProtobufCollector {
    public:
        enum class CandidateResult {
            OK,
            Rescan,
            Invalid
        };

        ProtobufCollector() = default;

        std::optional<std::pair<CandidateResult, std::string>> TryParseCandidate(const std::string &name, std::istream &data);

        const std::list<google::protobuf::FileDescriptorProto>& GetCandidates() const;

    private:
        std::list<google::protobuf::FileDescriptorProto> m_candidates;
};

} // namespace ProtobufDumper
