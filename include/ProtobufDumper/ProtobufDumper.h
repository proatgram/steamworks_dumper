#pragma once

#include <google/protobuf/message_lite.h>
#include <string>
#include <list>
#include <unordered_set>
#include <any>
#include <stack>
#include <map>
#include <optional>
#include <sstream>
#include <filesystem>

#include <google/protobuf/descriptor.pb.h>

// Comparitors for FileDescriptorProto to use in unordered_set
struct FileDescriptorProtoHash {
    inline std::size_t operator()(const google::protobuf::FileDescriptorProto &first) const noexcept {
        std::size_t hash1 = std::hash<std::string>{}(first.name());
        std::size_t hash2 = std::hash<std::string>{}(first.syntax());
        return hash1 ^ (hash2 << 1);
    }
};

struct FileDescriptorProtoCompare {
    inline constexpr bool operator()(const google::protobuf::FileDescriptorProto &first, const google::protobuf::FileDescriptorProto &second) const {
        return first.name() == second.name() && first.syntax() == second.syntax();
    }
};

namespace ProtobufDumper {
    class ProtobufDumper {
        public:
            // Delegate in C#, a std::function in C++
            using ProcessProtobuf = std::function<void(const std::string&, std::istream &buffer)>;
            using FileDescriptorProtoSet = std::unordered_set<google::protobuf::FileDescriptorProto, FileDescriptorProtoHash, FileDescriptorProtoCompare>;

            struct ProtoTypeNode {
                std::string Name;
                google::protobuf::FileDescriptorProto Proto;
                // any for now, object keyword in C#
                std::any Source;
                bool Defined;
            };

            struct ProtoNode {
                std::string Name;
                google::protobuf::FileDescriptorProto Proto;
                std::list<ProtoNode> Dependencies;
                FileDescriptorProtoSet AllPublicDependencies;
                std::list<std::shared_ptr<ProtoTypeNode>> Types;
                bool Defined;
            };

            static int DumpProtobufs(const std::list<std::filesystem::path> &targets, const std::filesystem::path &outputDirectory);

            ProtobufDumper(const std::list<google::protobuf::FileDescriptorProto> &protobufs);

            std::shared_ptr<ProtoTypeNode> GetOrCreateTypeNode(const std::string &name, const std::optional<google::protobuf::FileDescriptorProto> &proto = std::nullopt, const std::optional<std::any> &source = std::nullopt);

            bool Analyze();

            void RecursiveAddPublicDependencies(FileDescriptorProtoSet &set, const ProtoNode &node, int depth);

            void RecursiveAnalyzeMessageDescriptor(const google::protobuf::DescriptorProto &messageType, ProtoNode &protoNode, const std::string &packagePath);

            void DumpFiles(ProcessProtobuf callback);

            void DumpFileDescriptor(const google::protobuf::FileDescriptorProto &proto, std::stringstream &stringStream);

            std::map<std::string, std::string> DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::FileOptions &options);

            std::map<std::string, std::string> DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::FieldOptions &options);

            std::map<std::string, std::string> DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::MessageOptions &options);

            std::map<std::string, std::string> DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::EnumOptions &options);

            std::map<std::string, std::string> DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::EnumValueOptions &options);

            std::map<std::string, std::string> DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::ServiceOptions &options);

            std::map<std::string, std::string> DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::MethodOptions &options);

            void DumpOptionsFieldRecursive(const google::protobuf::FieldDescriptorProto &field, const google::protobuf::Message &options, std::map<std::string, std::string> &optionsKv, const std::string &path);

            void DumpOptionsMatching(const google::protobuf::FileDescriptorProto &source, const std::string &typeName, const google::protobuf::Message &options, std::map<std::string, std::string> optionsKv);

            void DumpExtensionDescriptors(const google::protobuf::FileDescriptorProto &source, const google::protobuf::RepeatedPtrField<google::protobuf::FieldDescriptorProto> &fields, std::stringstream &ss, int level, bool &marker);

            void DumpDescriptor(const google::protobuf::FileDescriptorProto &source, const google::protobuf::DescriptorProto &proto, std::stringstream &ss, int level, bool &marker);

            void DumpEnumDescriptor(const google::protobuf::FileDescriptorProto &source, const google::protobuf::EnumDescriptorProto &field, std::stringstream &ss, int level, bool &marker);

            void DumpService(const google::protobuf::FileDescriptorProto &source, const google::protobuf::ServiceDescriptorProto &service, std::stringstream &ss, bool &marker);

            std::string BuildDescriptorDeclaration(const google::protobuf::FileDescriptorProto &source, const google::protobuf::FieldDescriptorProto &field, bool emitFieldLabel = true);

            static constexpr bool IsNamedType(google::protobuf::FieldDescriptorProto::Type type);

            // Take deepr look into this
            static std::string GetPackagePath(std::string package, std::string name);

            static std::string GetLabel(google::protobuf::FieldDescriptorProto::Label label);

            static std::string GetType(google::protobuf::FieldDescriptorProto::Type type);

            static bool ExtractType(const google::protobuf::Message &data, const google::protobuf::FieldDescriptorProto &field, std::string& value);

            static std::string ResolveType(const google::protobuf::FieldDescriptorProto &field);

            static void AppendHeadingSpace(std::stringstream &ss, bool &marker);

            void PushDescriptorName(const google::protobuf::FileDescriptorProto &file);

            void PushDescriptorName(const google::protobuf::DescriptorProto &proto);

            void PushDescriptorName(const google::protobuf::FieldDescriptorProto &field);

            void PopDescriptorName();

        private:
            std::list<google::protobuf::FileDescriptorProto> m_protobufs;
            std::stack<std::string> m_messageNameStack;
            std::map<std::string, ProtoNode> m_protobufMap;
            std::map<std::string, std::shared_ptr<ProtoTypeNode>> m_protobufTypeMap;
    };
} // namespace ProtobufDumper
