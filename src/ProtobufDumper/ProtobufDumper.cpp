#include "ProtobufDumper/ProtobufDumper.h"
#include <google/protobuf/descriptor.pb.h>
#include <google/protobuf/message.h>

#include "ProtobufDumper/Util.h"
#include "ProtobufDumper/ProtobufCollector.h"
#include "ProtobufDumper/ExecutableScanner.h"

#include <fstream>

namespace ProtobufDumper {

ProtobufDumper::ProtobufDumper(const std::list<google::protobuf::FileDescriptorProto> &protobufs) :
    m_protobufs(protobufs),
    m_messageNameStack(),
    m_protobufMap(),
    m_protobufTypeMap()
{

}

int ProtobufDumper::DumpProtobufs(const std::list<std::filesystem::path> &targets, const std::filesystem::path &outputDirectory) {
    std::error_code err{};
    for (const std::filesystem::path &target : targets) {
        if (!std::filesystem::exists(target, err)) {
            throw std::filesystem::filesystem_error(std::string("Cannot dump file: " + target.string() + ": "), err);
        }
    }

    if (!std::filesystem::exists(outputDirectory)) {
        std::filesystem::create_directories(outputDirectory);
    }

    ProtobufCollector collector = ProtobufCollector();
    for (const std::filesystem::path &target : targets) {
        std::cout << "Loading binary " << target.string() << "..." << std::endl;
        ExecutableScanner::ScanFile(target, [&collector, hasDumpCandidates = !targets.empty(), &outputDirectory](const std::string &name, std::istream &buffer) -> bool {
            auto iterator = std::find_if(std::cbegin(collector.GetCandidates()), std::cend(collector.GetCandidates()), [&name](const google::protobuf::FileDescriptorProto &proto) -> bool {
                return proto.name() == name;
            });
            
            if (iterator != std::cend(collector.GetCandidates())) {
                return true;
            }

            std::optional<std::pair<ProtobufCollector::CandidateResult, std::string>> result;
            try {
                result = collector.TryParseCandidate(name, buffer);
            }
            catch (const std::runtime_error &ex) {
                std::cerr << "Failed to dump Protobuf \"" << name << "\": " << ex.what() << std::endl;
            }

            if (!result.has_value()) {
                throw std::runtime_error("Failed to dump Protobuf: Unknown error from ProtobufCollector::TryParseCandidate");
            }

            switch (result.value().first) {
                case ProtobufCollector::CandidateResult::OK: {
                    std::cout << "\033[32m" << "Scanning OK for " << name << "\033[0m" << std::endl;
                    break;
                }
                case ProtobufCollector::CandidateResult::Rescan: {
                    std::cerr << "\033[36m" << name << " needs rescan: " << result.value().second << "\033[0m" << std::endl;
                    break;
                }
                case ProtobufCollector::CandidateResult::Invalid: {
                    std::cerr << "\033[31m" << name << " is invalid: " << result.value().second << "\033[0m" << std::endl;
                    break;
                }
            }

            if (hasDumpCandidates && result.value().first == ProtobufCollector::CandidateResult::OK || result.value().first == ProtobufCollector::CandidateResult::Invalid) {
                std::filesystem::path fileName = outputDirectory;
                fileName += std::string(name + ".dump");

                try {
                    std::fstream file;
                    file.exceptions(std::fstream::badbit);
                    file.open(fileName);

                    buffer.seekg(0, std::ios::beg);
                    file << buffer.rdbuf();
                    file.flush();
                }
                catch (const std::exception &ex) {
                    std::cerr << "Unable to dump: " << ex.what() << std::endl;
                }
            }

            return result.value().first == ProtobufCollector::CandidateResult::OK || result.value().first == ProtobufCollector::CandidateResult::Invalid;
        });

        ProtobufDumper dumper(collector.GetCandidates());

        if (dumper.Analyze()) {
            dumper.DumpFiles([&outputDirectory](const std::string &name, std::istream &buffer) -> void {
                std::filesystem::path outputFile = outputDirectory;
                outputFile += "/" + name;

                std::cout << "  ! Outputting proto to '" << outputFile << "'" << std::endl;
                std::fstream file(outputFile);
                file << buffer.rdbuf();
            });
        }
        else {
            std::cerr << "\033[31m" << "Dump failed. Not all dependencies and types were found." << "\033[0m" << std::endl;
            return -1;
        }
    }
    return 0;
}

ProtobufDumper::ProtoTypeNode ProtobufDumper::GetOrCreateTypeNode(const std::string &name, const std::optional<google::protobuf::FileDescriptorProto> &proto, const std::optional<std::any> &source) {
    auto iterator = m_protobufTypeMap.find(name);
    ProtoTypeNode node;
    
    if (iterator != std::cend(m_protobufTypeMap)) {
        node = iterator->second;
    }

    if (iterator == std::cend(m_protobufTypeMap)) {
        node = {
            .Name = name,
            .Proto = proto.value_or(google::protobuf::FileDescriptorProto{}),
            .Source = source.value_or(std::any{}),
            .Defined = source->has_value()
        };

        m_protobufTypeMap.insert(std::make_pair(name, node));
    }
    else if (source->has_value()) {
        if (node.Defined == false) {
            throw std::runtime_error("Node is not defined.");
        }

        node.Proto = proto.value_or(google::protobuf::FileDescriptorProto{});
        node.Source = source;
        node.Defined = true;
    }
    
    return node;
}

bool ProtobufDumper::Analyze() {
    for (auto proto : m_protobufs) {
        ProtoNode protoNode = {
            .Name = proto.name(),
            .Proto = proto,
            .Dependencies = {},
            .AllPublicDependencies = {},
            .Types = {},
            .Defined = true
        };

        for (const auto &extension : proto.extension()) {
            protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(proto.package(), extension.name()), proto, extension));
            if (IsNamedType(extension.type()) && !extension.name().empty()) {
                protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(proto.package(), extension.type_name())));
            }

            if (!extension.extendee().empty()) {
                protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(proto.package(), extension.extendee())));
            }
        }

        for (const auto &enumType : proto.enum_type()) {
            protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(proto.package(), enumType.name()), proto, enumType));
        }

        for (const auto &messageType : proto.message_type()) {
            RecursiveAnalyzeMessageDescriptor(messageType, protoNode, proto.package());
        }

        for (const auto &service : proto.service()) {
            protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(proto.package(), service.name()), proto, service));

            for (auto method : service.method()) {
                if (!method.input_type().empty()) {
                    protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(proto.package(), method.input_type())));
                }

                if (!method.output_type().empty()) {
                    protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(proto.package(), method.output_type())));
                }
            }
        }

        m_protobufMap.insert(std::make_pair(proto.name(), protoNode));
    }

    std::list<ProtoNode> missingDependencies{};

    /* Inspect the file dependencies */
    for (auto &[name, protoNode] : m_protobufMap) {
        for (const auto &dependency : protoNode.Proto.dependency()) {
            if (dependency.compare(0, 6, "google")== 0) {
                continue;
            }

            std::map<std::string, ProtoNode>::iterator iterator;

            if ((iterator = m_protobufMap.find(dependency)) != std::cend(m_protobufMap)) {
                protoNode.Dependencies.push_back(iterator->second);
            }
            else {
                std::cerr << "\033[36m" << "Unknown dependency: " << dependency << " for " << protoNode.Proto.name() << "\033[0m" << std::endl;

                auto missing = std::find_if(missingDependencies.cbegin(), missingDependencies.cend(), [dependency](const ProtoNode &protoNode) -> bool {return protoNode.Name == dependency;});
                ProtoNode missingDependency{};
                if (missing == std::cend(missingDependencies)) {
                    missingDependency.Name = dependency;
                    missingDependency.Defined = false;
                }
                else {
                    missingDependency = *missing;
                }

                protoNode.Dependencies.push_back(missingDependency);
            }
        }
    }

    for (const ProtoNode &depend : missingDependencies) {
        m_protobufMap.insert(std::make_pair(depend.Name, depend));
    }

    for (auto &[name, protoNode] : m_protobufMap) {
        std::list<ProtoNode> undefinedFiles{};
        for (const ProtoNode& dependency : protoNode.Dependencies) {
            if (!dependency.Defined) {
                undefinedFiles.push_back(dependency);
            }
        }

        if (undefinedFiles.size() > 0) {
            std::cerr << "\033[1;4;41m" << "Not all dependencies were found for" << name << "\033[0m" << std::endl;
            
            std::cerr << "\033[41m";
            for (const ProtoNode &file : undefinedFiles) {
                std::cerr << "Dependency not found: " << file.Name << std::endl;
            }
            std::cerr << "\033[0m";
            std::cerr.flush();

            return false;
        }

        std::list<ProtoTypeNode> undefinedTypes{};
        for (const ProtoTypeNode &typeNode : protoNode.Types) {
            if (!typeNode.Defined) {
                undefinedTypes.push_back(typeNode);
            }
        }

        if (undefinedTypes.size() > 0) {
            std::cerr << "\033[1;4;41m" << "Not all types were found for" << name << "\033[0m" << std::endl;
            
            std::cerr << "\033[41m";
            for (const ProtoTypeNode &type : undefinedTypes) {
                std::cerr << "Type not found: " << type.Name << std::endl;
            }
            std::cerr << "\033[0m";
            std::cerr.flush();

            return false;
        }

        // Build the list of all publicly accessible types from each file
        RecursiveAddPublicDependencies(protoNode.AllPublicDependencies, protoNode, 0);
    }

    return true;
}

void ProtobufDumper::RecursiveAddPublicDependencies(FileDescriptorProtoSet &set, const ProtoNode &node, int depth) {
    if (depth == 0) {
        for (const std::string &dependency : node.Proto.dependency()) {
            ProtoNode depend = m_protobufMap.at(dependency);
            set.insert(depend.Proto);
            RecursiveAddPublicDependencies(set, depend, depth + 1);
        }
    }
    else {
        for (const int32_t idx : node.Proto.public_dependency()) {
            ProtoNode depend = m_protobufMap.at(node.Proto.dependency().at(idx));
            set.insert(depend.Proto);
            RecursiveAddPublicDependencies(set, depend, depth + 1);
        }
    }
}

void ProtobufDumper::RecursiveAnalyzeMessageDescriptor(const google::protobuf::DescriptorProto &messageType, ProtoNode &protoNode, const std::string &packagePath) {
    protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath( packagePath, messageType.name()), protoNode.Proto, messageType));

    for (auto extension : messageType.extension()) {
        if (!extension.extendee().empty()) {
            protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(packagePath, extension.extendee())));
        }
    }

    for (auto enumType : messageType.enum_type()) {
        protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(GetPackagePath(packagePath, messageType.name()), enumType.name()), protoNode.Proto, enumType));
    }

    for (auto field : messageType.field()) {
        if (IsNamedType(field.type()) && !field.type_name().empty()) {
            protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(packagePath, field.type_name())));
        }

        if (!field.extendee().empty()) {
            protoNode.Types.push_back(GetOrCreateTypeNode(GetPackagePath(packagePath, field.extendee())));
        }
    }

    for (auto nested : messageType.nested_type()) {
        RecursiveAnalyzeMessageDescriptor(nested, protoNode, GetPackagePath(packagePath, messageType.name()));
    }
}

void ProtobufDumper::DumpFiles(ProcessProtobuf callback) {
    for (const google::protobuf::FileDescriptorProto &proto : m_protobufs) {
        std::stringstream ss;
        DumpFileDescriptor(proto, ss);
        callback(proto.name(), ss);
    }
}

void ProtobufDumper::DumpFileDescriptor(const google::protobuf::FileDescriptorProto &proto, std::stringstream &ss) {
    if (!proto.package().empty()) {
        PushDescriptorName(proto);
    }

    bool marker = false;

    for (int i = 0; i < proto.dependency().size(); i++) {
        std::string dependency = proto.dependency().at(i);
        std::string modifier = std::find(proto.public_dependency().cbegin(), proto.public_dependency().cend(), i) == std::end(proto.public_dependency()) ? "public" : "";
        ss << "import " << modifier << "\"" << dependency << "\";" << std::endl;
        marker = true;
    }

    if (!proto.package().empty()) {
        AppendHeadingSpace(ss, marker);
        ss << "package " << proto.package() << ";" << std::endl;
    }

    std::map<std::string, std::string> options = DumpOptions(proto, proto.options());

    for (const auto &[key, value] : options) {
        AppendHeadingSpace(ss, marker);
        ss << "option " << key << " = " << value << std::endl;
    }

    if (options.size() > 0) {
        marker = true;
    }

    DumpExtensionDescriptors(proto, proto.extension(), ss, 0, marker);

    for (const auto &field : proto.enum_type()) {
        DumpEnumDescriptor(proto, field, ss, 0, marker);
    }

    for (const auto &message : proto.message_type()) {
        DumpDescriptor(proto, message, ss, 0, marker);
    }

    for (const auto &service : proto.service()) {
        DumpService(proto, service, ss, marker);
    }

    if (!proto.package().empty()) {
        PopDescriptorName();
    }
}

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::FileOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    // Use emplace
    if (options.has_deprecated()) {
        optionsKv.insert(std::make_pair("dpericated", (options.deprecated() ? "true" : "false")));
    }

    if (options.has_optimize_for()) {
        switch (options.optimize_for()) {
            case google::protobuf::FileOptions_OptimizeMode::FileOptions_OptimizeMode_SPEED: {
                optionsKv.insert(std::make_pair("optimize_for", "SPEED"));
                break;
            }
            case google::protobuf::FileOptions_OptimizeMode::FileOptions_OptimizeMode_CODE_SIZE: {
                optionsKv.insert(std::make_pair("optimize_for", "CODE_SIZE"));
                break;
            }
            case google::protobuf::FileOptions_OptimizeMode::FileOptions_OptimizeMode_LITE_RUNTIME: {
                optionsKv.insert(std::make_pair("optimize_for", "LITE_RUNTIME"));
                break;
            }
        }
    }
    
    if (options.has_cc_generic_services()) {
        optionsKv.insert(std::make_pair("cc_generic_services", (options.cc_generic_services() ? "true" : "false")));
    }

    if (options.has_go_package()) {
        std::stringstream ss;
        ss << "\"" << options.go_package() << "\"";
        ss.flush();
        optionsKv.insert(std::make_pair("go_package", ss.str().c_str()));
    }
    
    if (options.has_java_package()) {
        std::stringstream ss;
        ss << "\"" << options.java_package() << "\"";
        ss.flush();
        optionsKv.insert(std::make_pair("java_package", ss.str().c_str()));
    }

    if (options.has_java_outer_classname()) {
        std::stringstream ss;
        ss << "\"" << options.java_outer_classname() << "\"";
        ss.flush();
        optionsKv.insert(std::make_pair("java_outer_classname", ss.str().c_str()));
    }

    if (options.has_java_generic_services()) {
        optionsKv.insert(std::make_pair("java_generic_services", (options.java_generic_services() ? "true" : "false")));
    }

    if (options.has_java_multiple_files()) {
        optionsKv.insert(std::make_pair("java_multiple_files", (options.java_multiple_files() ? "true" : "false")));
    }

    if (options.has_java_string_check_utf8()) {
        optionsKv.insert(std::make_pair("java_string_check_utf8", (options.java_string_check_utf8() ? "true" : "false")));
    }

    if (options.has_py_generic_services()) {
        optionsKv.insert(std::make_pair("py_generic_services", (options.py_generic_services() ? "true" : "false")));
    }

    DumpOptionsMatching(source, ".google.protobuf.FileOptions", options, optionsKv);

    return optionsKv;
}

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::MessageOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_message_set_wire_format()) {
        optionsKv.insert(std::make_pair("message_set_wire_format", (options.message_set_wire_format() ? "true" : "false")));
    }

    if (options.has_no_standard_descriptor_accessor()) {
        optionsKv.insert(std::make_pair("no_standard_descriptor_accessor", (options.no_standard_descriptor_accessor() ? "true" : "false")));
    }

    if (options.has_deprecated()) {
        optionsKv.insert(std::make_pair("depricated", (options.deprecated() ? "true" : "false")));
    }

    DumpOptionsMatching(source, ".google.protobuf.MessageOptions", options, optionsKv);

    return optionsKv;
}

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::EnumOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_allow_alias()) {
        optionsKv.insert(std::make_pair("allow_alias", (options.allow_alias() ? "true" : "false")));
    }

    if (options.has_deprecated()) {
        optionsKv.insert(std::make_pair("depricated", (options.deprecated() ? "true" : "false")));
    }

    DumpOptionsMatching(source, ".google.protobuf.EnumOptions", options, optionsKv);

    return optionsKv;
} 

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::EnumValueOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_deprecated()) {
        optionsKv.insert(std::make_pair("depricated", (options.deprecated() ? "true" : "false")));
    }

    DumpOptionsMatching(source, ".google.protobuf.EnumValueOptions", options, optionsKv);

    return optionsKv;
}

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::ServiceOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_deprecated()) {
        optionsKv.insert(std::make_pair("depricated", (options.deprecated() ? "true" : "false")));
    }

    DumpOptionsMatching(source, ".google.protobuf.ServiceOptions", options, optionsKv);

    return optionsKv;
}

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::MethodOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_deprecated()) {
        optionsKv.insert(std::make_pair("depricated", (options.deprecated() ? "true" : "false")));
    }

    DumpOptionsMatching(source, ".google.protobuf.MethodOptions", options, optionsKv);

    return optionsKv;
}

// THIS FLUFFER RIGHT HERE UGH
bool TryGetValue(const google::protobuf::Message &options, int fieldNumber, int& value) {
    const google::protobuf::Reflection *reflection = options.GetReflection();
    const google::protobuf::Descriptor *descriptor = options.GetDescriptor();

    const google::protobuf::FieldDescriptor *fieldDescriptor = descriptor->FindFieldByNumber(fieldNumber);

    if (fieldDescriptor && fieldDescriptor->cpp_type() == google::protobuf::FieldDescriptor::CppType::CPPTYPE_INT32) {
        value = reflection->GetInt32(options, fieldDescriptor);
        return true;
    }

    return false;
}

void ProtobufDumper::DumpOptionsFieldRecursive(const google::protobuf::FieldDescriptorProto &field, const google::protobuf::Message &options, std::map<std::string, std::string> &optionsKv, const std::string &path) {
    std::string key = (path.empty() ? '(' + field.name() + ')' : path + '.' + field.name());

    if (IsNamedType(field.type()) && !field.type_name().empty()) {
        std::any fieldData = m_protobufTypeMap.at(field.type_name()).Source;

        if (fieldData.has_value()) {
            if (fieldData.type() == typeid(google::protobuf::EnumDescriptorProto)) {
                google::protobuf::EnumDescriptorProto enumProto = std::any_cast<google::protobuf::EnumDescriptorProto>(fieldData);
                int idx{};
                if (TryGetValue(options, field.number(), idx)) {
                    auto value = std::find_if(std::cbegin(enumProto.value()), std::cend(enumProto.value()), [idx](const google::protobuf::EnumValueDescriptorProto &value) -> bool {return value.number() == idx;});
                    if (value != std::cend(enumProto.value())) {
                        std::cerr << "Index not found error!" << std::endl;
                    }
                    else {
                        optionsKv.insert(std::make_pair(key, value->name()));
                    }
                }

            }
            else if (fieldData.type() == typeid(google::protobuf::DescriptorProto)) {
                google::protobuf::DescriptorProto messageProto = std::any_cast<google::protobuf::DescriptorProto>(fieldData);

                const google::protobuf::Descriptor *descriptor = messageProto.GetDescriptor();
                const google::protobuf::Reflection *reflection = messageProto.GetReflection();

                const google::protobuf::FieldDescriptor *fieldDescriptor = descriptor->FindFieldByNumber(field.number());
                
                if (reflection->HasField(options, fieldDescriptor)) {
                    for (auto subField : messageProto.field()) {
                        DumpOptionsFieldRecursive(subField, reflection->GetMessage(options, fieldDescriptor), optionsKv, key);
                    }
                }
            }
        }
    }
    else {
        std::string value{};

        if(ExtractType(options, field, value)) {
            optionsKv.insert(std::make_pair(key, value));
        }
    }
}

void ProtobufDumper::DumpOptionsMatching(const google::protobuf::FileDescriptorProto &source, const std::string &typeName, const google::protobuf::Message &options, std::map<std::string, std::string> optionsKv) {
    FileDescriptorProtoSet dependencies = FileDescriptorProtoSet(m_protobufMap.at(source.name()).AllPublicDependencies);
    dependencies.insert(source);

    for (const auto &[name, typeNode] : m_protobufTypeMap) {
        if (dependencies.find(typeNode.Proto) != std::end(dependencies) && typeNode.Source.type() == typeid(google::protobuf::FieldDescriptorProto)) {
            google::protobuf::FieldDescriptorProto field = std::any_cast<google::protobuf::FieldDescriptorProto>(typeNode.Source);

            if (!field.extendee().empty() && field.extendee() == typeName) {
                DumpOptionsFieldRecursive(field, options, optionsKv, {});
            }
        }
    }
}

void ProtobufDumper::DumpExtensionDescriptors(const google::protobuf::FileDescriptorProto &source, const google::protobuf::RepeatedPtrField<google::protobuf::FieldDescriptorProto> &fields, std::stringstream &ss, int level, bool &marker) {
    std::string levelSpace = std::string('\t', level);

    // Replicate C# GroupBy
    std::map<std::string, std::list<google::protobuf::FieldDescriptorProto>> mappings;
    for (auto& field : fields) {
        auto iterator = std::find_if(std::begin(mappings), std::end(mappings), [field](std::pair<std::string, std::list<google::protobuf::FieldDescriptorProto>> item) -> bool {return item.first == field.extendee();});
        if (iterator == std::end(mappings)) {
            mappings.insert(std::make_pair(field.extendee(), std::list<google::protobuf::FieldDescriptorProto>({field})));
        }
        else {
            iterator->second.push_back(field);
        }
    }

    for (const auto &[extendee, fields] : mappings) {
        if (extendee.empty()) {
            throw std::runtime_error("Empty extendee in extension, this should not be possible.");
        }

        AppendHeadingSpace(ss, marker);
        ss << levelSpace << "extend " << extendee << " {" << std::endl;

        for (const auto &field : fields) {
            ss << levelSpace << '\t' << BuildDescriptorDeclaration(source, field) << std::endl;
        }
        ss << '}' << std::endl;
        marker = true;
    }
}

void ProtobufDumper::DumpDescriptor(const google::protobuf::FileDescriptorProto &source, const google::protobuf::DescriptorProto &proto, std::stringstream &ss, int level, bool &marker) {
    PushDescriptorName(proto);

    std::string levelSpace = std::string('\t', level);
    bool innerMarker = false;

    AppendHeadingSpace(ss, marker);

    ss << levelSpace << "'message " << proto.name() << " {" << std::endl;

    std::map<std::string, std::string> options = DumpOptions(source, proto.options());

    for (const auto &[key, value] : options) {
        AppendHeadingSpace(ss, innerMarker);
        ss << levelSpace << '\t' << "option " << key << " = " << value << ';' << std::endl;
    }

    if (options.size() > 0) {
        innerMarker = true;
    }

    if (proto.extension().size() > 0) {
        DumpExtensionDescriptors(source, proto.extension(), ss, level + 1, innerMarker);
    }

    for (const auto &field : proto.nested_type()) {
        DumpDescriptor(source, field, ss, level + 1, innerMarker);
    }

    for (const auto &field : proto.enum_type()) {
        DumpEnumDescriptor(source, field, ss, level + 1, innerMarker);
    }

    // Replicate C# Where().ToList()
    std::list<google::protobuf::FieldDescriptorProto> rootFields{};
    for (const auto &field : proto.field()) {
        if (field.has_oneof_index()) {
            rootFields.push_back(field);
        }
    }

    for (const auto &field : rootFields) {
        AppendHeadingSpace(ss, innerMarker);
        ss << levelSpace << '\t' << BuildDescriptorDeclaration(source, field) << std::endl;
    }

    if (rootFields.size() > 0) {
        innerMarker = true;
    }

    for (int i = 0; i < proto.oneof_decl_size(); i++) {
        google::protobuf::OneofDescriptorProto oneof = proto.oneof_decl().at(i);

        std::list<google::protobuf::FieldDescriptorProto> fields{};
        for (const auto &field : proto.field()) {
            if (field.has_oneof_index() && field.oneof_index() == i) {
                fields.push_back(field);
            }
        }

        AppendHeadingSpace(ss, innerMarker);
        ss << levelSpace << '\t' << "oneof " << oneof.name() << " {" << std::endl;

        for (const auto &field : fields) {
            ss << levelSpace << "\t\t"
               << BuildDescriptorDeclaration(source, field, false) << std::endl;
        }

        ss << levelSpace << "\t}" << std::endl;
        innerMarker = true;
    }

    for (const auto &range : proto.extension_range()) {
        AppendHeadingSpace(ss, innerMarker);

        // http://code.google.com/apis/protocolbuffers/docs/proto.html#extensions
        // If your numbering convention might involve extensions having very large numbers as tags, you can specify
        // that your extension range goes up to the maximum possible field number using the max keyword:
        // max is 2^29 - 1, or 536,870,911. 
        ss << levelSpace << '\t' << "extensions " << range.start() << " to " << (range.end() >= 536870911 ? "max" : std::to_string(range.end()));
    }

    ss << levelSpace << '}' << std::endl;
    marker = true;

    PopDescriptorName();
}

void ProtobufDumper::DumpEnumDescriptor(const google::protobuf::FileDescriptorProto &source, const google::protobuf::EnumDescriptorProto &field, std::stringstream &ss, int level, bool &marker) {
    std::string levelSpace('\t', level);

    AppendHeadingSpace(ss, marker);
    ss << levelSpace << "enum " << field.name() << " {" << std::endl;

    for (const auto &[key, value] : DumpOptions(source, field.options())) {
        ss << levelSpace << '\t' << "option " << key << " = " << value << ";" << std::endl;
    }

    for (const auto &enumValue : field.value()) {
        std::map<std::string, std::string> options = DumpOptions(source, enumValue.options());

        std::stringstream parameters{};
        if (options.size() > 0) {
            parameters << '[';
            bool first = true;
            for (const auto &[key, value] : options) {
                if (!first) {
                    parameters << ", ";
                }

                parameters << key << " = " << value;
            }
            parameters << ']';
            parameters.flush();
        }

        ss << levelSpace << '\t' << enumValue.name() << " = " << enumValue.number() << parameters.str() << std::endl;
    }

    ss << levelSpace << "}" << std::endl;
    marker = true;
}

void ProtobufDumper::DumpService(const google::protobuf::FileDescriptorProto &source, const google::protobuf::ServiceDescriptorProto &service, std::stringstream &ss, bool &marker) {
    bool innerMarker = false;

    AppendHeadingSpace(ss, marker);
    ss << "service " << service.name() << '{' << std::endl;

    std::map<std::string, std::string> rootOptions = DumpOptions(source, service.options());

    for (const auto &[key, value] : rootOptions) {
        ss << '\t' << "option " << key << " = " << value << ';' << std::endl;
    }

    if (rootOptions.size() > 0) {
        innerMarker = true;
    }

    for (const auto &method : service.method()) {
        std::string declaration = std::string("\trpc ") + method.name() + std::string(" (") + method.input_type() + std::string(") ") + std::string("returns") + std::string(" (") + method.output_type() + std::string(")");
        std::map<std::string, std::string> options = DumpOptions(source, method.options());

        AppendHeadingSpace(ss, innerMarker);

        if (options.size() == 0) {
            ss << declaration << std::endl;
        }
        else {
            ss << declaration << " {" << std::endl;

            for (const auto &[key, value] : options) {
                ss << "\t\t" << "option " << key << " = " << value << ';' << std::endl;
            }

            ss << "\t}" << std::endl;
            innerMarker = true;
        }
    }

    ss << "}" << std::endl;
    marker = true;
}

std::string ProtobufDumper::BuildDescriptorDeclaration(const google::protobuf::FileDescriptorProto &source, const google::protobuf::FieldDescriptorProto &field, bool emitFieldLabel) {
    PushDescriptorName(field);

    std::string type = ResolveType(field);
    std::map<std::string, std::string> options{};

    if (!field.default_value().empty()) {
        std::string defaultValue = field.default_value();

        if (field.type() == google::protobuf::FieldDescriptorProto_Type::FieldDescriptorProto_Type_TYPE_STRING) {
            defaultValue = Util::ToLiteral(defaultValue);
        }

        options.insert(std::make_pair("default", defaultValue));
    }
    else if (field.type() == google::protobuf::FieldDescriptorProto_Type::FieldDescriptorProto_Type_TYPE_ENUM && field.label() != google::protobuf::FieldDescriptorProto_Label::FieldDescriptorProto_Label_LABEL_REPEATED) {
        ProtoTypeNode lookup = m_protobufTypeMap.at(field.type_name());

        if (lookup.Source.type() == typeid(google::protobuf::EnumDescriptorProto)) {
            google::protobuf::EnumDescriptorProto enumDescriptor = std::any_cast<google::protobuf::EnumDescriptorProto>(lookup.Source);
            if (enumDescriptor.value().size() > 0) {
                options.insert(std::make_pair("default", enumDescriptor.value().at(0).name()));
            }
        }
    }

    std::map<std::string, std::string> fieldOptions = DumpOptions(source, field.options());

    for (const auto &[key, value] : fieldOptions) {
        options.insert_or_assign(key, value);
    }

    std::stringstream parameters{};
    if (options.size() > 0) {
        if (options.size() > 0) {
            parameters << '[';
            bool first = true;
            for (const auto &[key, value] : options) {
                if (!first) {
                    parameters << ", ";
                }

                parameters << key << " = " << value;
            }
            parameters << ']';
            parameters.flush();
        }
    }

    PopDescriptorName();

    std::stringstream descriptorDeclarationBuilder{};

    if (emitFieldLabel) {
        descriptorDeclarationBuilder << GetLabel(field.label()) << " ";
    }

    descriptorDeclarationBuilder << type << " " << field.name() << " = " << field.number() << parameters.str() << ";";

    return descriptorDeclarationBuilder.str();
}

constexpr bool ProtobufDumper::IsNamedType(google::protobuf::FieldDescriptorProto::Type type) {
    return type == google::protobuf::FieldDescriptorProto::Type::FieldDescriptorProto_Type_TYPE_MESSAGE || type == google::protobuf::FieldDescriptorProto::Type::FieldDescriptorProto_Type_TYPE_ENUM;
}

std::string ProtobufDumper::GetPackagePath(std::string package, std::string name) {
    if (package.empty() || package[0] == '.') {
        return name;
    }

    return package + "." + name;
}

std::string ProtobufDumper::GetLabel(google::protobuf::FieldDescriptorProto_Label label) {
    switch (label) {
        case google::protobuf::FieldDescriptorProto_Label::FieldDescriptorProto_Label_LABEL_OPTIONAL: {
            return "optional";
        }
        case google::protobuf::FieldDescriptorProto_Label::FieldDescriptorProto_Label_LABEL_REQUIRED: {
            return "required";
        }
        case google::protobuf::FieldDescriptorProto_Label::FieldDescriptorProto_Label_LABEL_REPEATED: {
            return "repeated";
        }
        default: {
            return {};
        }
    }
}

std::string ProtobufDumper::GetType(google::protobuf::FieldDescriptorProto_Type type ) {
    switch ( type ) {
        case google::protobuf::FieldDescriptorProto_Type_TYPE_INT32: {
            return "int32";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_INT64: {
            return "int64";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_SINT32: {
            return "sint32";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_SINT64: {
            return "sint64";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_UINT32: {
            return "uint32";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_UINT64: {
            return "uint64";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_STRING: {
            return "string";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_BOOL: {
            return "bool";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_BYTES: {
            return "bytes";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_DOUBLE: {
            return "double";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_ENUM: {
            return "enum";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_FLOAT: {
            return "float";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_GROUP: {
            return "GROUP";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_MESSAGE: {
            return "message";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_FIXED32: {
            return "fixed32";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_FIXED64: {
            return "fixed64";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_SFIXED32: {
            return "sfixed32";
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_SFIXED64: {
            return "sfixed64";
        }
        default: {
            // C# Used ToString on... something?
            return {};
        }
    }
}

bool ProtobufDumper::ExtractType(const google::protobuf::Message &data, const google::protobuf::FieldDescriptorProto &field, std::string &value) {
    const google::protobuf::Reflection *reflection = data.GetReflection();
    const google::protobuf::Descriptor *descriptor = data.GetDescriptor();
    const google::protobuf::FieldDescriptor *fieldDescriptor = descriptor->FindFieldByNumber(field.number());

    switch (field.type()) {
        case google::protobuf::FieldDescriptorProto_Type_TYPE_DOUBLE: {
            value = std::to_string(reflection->GetDouble(data, fieldDescriptor));
            return true;
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_FLOAT: {
            value = std::to_string(reflection->GetFloat(data, fieldDescriptor));
            return true;
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_SFIXED64:
        case google::protobuf::FieldDescriptorProto_Type_TYPE_SINT64:
        case google::protobuf::FieldDescriptorProto_Type_TYPE_INT64: {
            value = std::to_string(reflection->GetInt64(data, fieldDescriptor));
            return true;
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_FIXED64:
        case google::protobuf::FieldDescriptorProto_Type_TYPE_UINT64: {
            value = std::to_string(reflection->GetUInt64(data, fieldDescriptor));
            return true;
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_SFIXED32:
        case google::protobuf::FieldDescriptorProto_Type_TYPE_SINT32:
        case google::protobuf::FieldDescriptorProto_Type_TYPE_INT32: {
            value = std::to_string(reflection->GetInt32(data, fieldDescriptor));
            return true;
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_BOOL: {
            value = (reflection->GetBool(data, fieldDescriptor) ? "true" : "false");
            return true;
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_STRING: {
            value = Util::ToLiteral(reflection->GetString(data, fieldDescriptor));
            return true;
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_BYTES: {
            // Apperently BYTES are represented as std::string's??
            value = reflection->GetString(data, fieldDescriptor);
            return true;
        }
        case google::protobuf::FieldDescriptorProto_Type_TYPE_FIXED32:
        case google::protobuf::FieldDescriptorProto_Type_TYPE_UINT32: {
            value = reflection->GetUInt32(data, fieldDescriptor);
            return true;
        }
        default: {
            value.clear();
            return false;
        }
    }
}

std::string ProtobufDumper::ResolveType(const google::protobuf::FieldDescriptorProto &field) {
    if (IsNamedType(field.type())) {
        return field.type_name();
    }

    return GetType(field.type());
}

void ProtobufDumper::AppendHeadingSpace(std::stringstream &ss, bool &marker) {
    if (marker) {
        ss << std::endl;
        marker = false;
    }
}

void ProtobufDumper::PushDescriptorName(const google::protobuf::FileDescriptorProto &file) {
    m_messageNameStack.push(file.package());
}

void ProtobufDumper::PushDescriptorName(const google::protobuf::DescriptorProto &proto) {
    m_messageNameStack.push(proto.name());
}

void ProtobufDumper::PushDescriptorName(const google::protobuf::FieldDescriptorProto &field) {
    m_messageNameStack.push(field.name());
}

void ProtobufDumper::PopDescriptorName() {
    m_messageNameStack.pop();
}

} // namespace ProtobufDumper
