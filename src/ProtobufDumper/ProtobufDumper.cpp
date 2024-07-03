#include "ProtobufDumper/ProtobufDumper.h"
#include <google/protobuf/descriptor.pb.h>

namespace ProtobufDumper {

ProtobufDumper::ProtobufDumper(const std::list<google::protobuf::FileDescriptorProto> &protobufs) :
    m_protobufs(protobufs),
    m_messageNameStack(),
    m_protobufMap(),
    m_protobufTypeMap()
{

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

void ProtobufDumper::DumpFile(ProcessProtobuf callback) {
    for (const google::protobuf::FileDescriptorProto &proto : m_protobufs) {
        std::stringstream ss;
        DumpFileDescriptor(proto, ss);
        callback(proto.name(), ss.str());
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
        optionsKv.insert("dpericated", (options.deprecated() ? "true" : "false"));
    }

    if (options.has_optimize_for()) {
        switch (options.optimize_for()) {
            case google::protobuf::FileOptions_OptimizeMode::FileOptions_OptimizeMode_SPEED: {
                optionsKv.insert("optimize_for", "SPEED");
                break;
            }
            case google::protobuf::FileOptions_OptimizeMode::FileOptions_OptimizeMode_CODE_SIZE: {
                optionsKv.insert("optimize_for", "CODE_SIZE");
                break;
            }
            case google::protobuf::FileOptions_OptimizeMode::FileOptions_OptimizeMode_LITE_RUNTIME: {
                optionsKv.insert("optimize_for", "LITE_RUNTIME");
                break;
            }
        }
    }
    
    if (options.has_cc_generic_services()) {
        optionsKv.insert("cc_generic_services", (options.cc_generic_services() ? "true" : "false"));
    }

    if (options.has_go_package()) {
        std::stringstream ss;
        ss << "\"" << options.go_package() << "\"";
        ss.flush();
        optionsKv.insert("go_package", ss.str().c_str());
    }
    
    if (options.has_java_package()) {
        std::stringstream ss;
        ss << "\"" << options.java_package() << "\"";
        ss.flush();
        optionsKv.insert("java_package", ss.str().c_str());
    }

    if (options.has_java_outer_classname()) {
        std::stringstream ss;
        ss << "\"" << options.java_outer_classname() << "\"";
        ss.flush();
        optionsKv.insert("java_outer_classname", ss.str().c_str());
    }

    if (options.has_java_generic_services()) {
        optionsKv.insert("java_generic_services", (options.java_generic_services() ? "true" : "false"));
    }

    if (options.has_java_multiple_files()) {
        optionsKv.insert("java_multiple_files", (options.java_multiple_files() ? "true" : "false"));
    }

    if (options.has_java_string_check_utf8()) {
        optionsKv.insert("java_string_check_utf8", (options.java_string_check_utf8() ? "true" : "false"));
    }

    if (options.has_py_generic_services()) {
        optionsKv.insert("py_generic_services", (options.py_generic_services() ? "true" : "false"));
    }

    DumpOptionsMatching(source, ".google.protobuf.FileOptions", options, optionsKv);

    return optionsKv;
}

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::MessageOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_message_set_wire_format()) {
        optionsKv.insert("message_set_wire_format", (options.message_set_wire_format() ? "true" : "false"));
    }

    if (options.has_no_standard_descriptor_accessor()) {
        optionsKv.insert("no_standard_descriptor_accessor", (options.no_standard_descriptor_accessor() ? "true" : "false"));
    }

    if (options.has_deprecated()) {
        optionsKv.insert("depricated", (options.deprecated() ? "true" : "false"));
    }

    DumpOptionsMatching(source, ".google.protobuf.MessageOptions", options, optionsKv);

    return optionsKv;
}

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::EnumOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_allow_alias()) {
        optionsKv.insert("allow_alias", (options.allow_alias() ? "true" : "false"));
    }

    if (options.has_deprecated()) {
        optionsKv.insert("depricated", (options.deprecated() ? "true" : "false"));
    }

    DumpOptionsMatching(source, ".google.protobuf.EnumOptions", options, optionsKv);

    return optionsKv;
} 

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::EnumValueOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_deprecated()) {
        optionsKv.insert("depricated", (options.deprecated() ? "true" : "false"));
    }

    DumpOptionsMatching(source, ".google.protobuf.EnumValueOptions", options, optionsKv);

    return optionsKv;
}

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::ServiceOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_deprecated()) {
        optionsKv.insert("depricated", (options.deprecated() ? "true" : "false"));
    }

    DumpOptionsMatching(source, ".google.protobuf.ServiceOptions", options, optionsKv);

    return optionsKv;
}

std::map<std::string, std::string> ProtobufDumper::DumpOptions(const google::protobuf::FileDescriptorProto &source, const google::protobuf::MethodOptions &options) {
    std::map<std::string, std::string> optionsKv{};

    if (options.has_deprecated()) {
        optionsKv.insert("depricated", (options.deprecated() ? "true" : "false"));
    }

    DumpOptionsMatching(source, ".google.protobuf.MethodOptions", options, optionsKv);

    return optionsKv;
}

std::string ProtobufDumper::GetPackagePath(std::string package, std::string name) {
    if (package.empty() || package[0] == '.') {
        return name;
    }

    return package + "." + name;
}

constexpr bool ProtobufDumper::IsNamedType(google::protobuf::FieldDescriptorProto::Type type) {
    return type == google::protobuf::FieldDescriptorProto::Type::FieldDescriptorProto_Type_TYPE_MESSAGE || type == google::protobuf::FieldDescriptorProto::Type::FieldDescriptorProto_Type_TYPE_ENUM;
}

std::string ProtobufDumper::ResolveType(const google::protobuf::FieldDescriptorProto &field) {
    if (IsNamedType(field.type())) {
        return field.type_name();
    }

    //return GetType(field.type());
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
