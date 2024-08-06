#include "argparse/argparse.hpp"

#include "steamworks_dumper.h"
#include "ProtobufDumper/ProtobufDumper.h"

int main(int argc, char **argv) {
    argparse::ArgumentParser program("steamworks_dumper");
    program.add_argument("--dump-offsets")
            .default_value(false)
            .implicit_value(true)
            .help("include relative offsets/addresses in dumps");

    program.add_argument("in")
            .help(".so in")
            .required();

    program.add_argument("out")
            .help("output path")
            .required();

    try
    {
        program.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err)
    {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }

    Dump(program.get<std::string>("in"), program.get<std::string>("out"), program.get<bool>("--dump-offsets"));
    ProtobufDumper::ProtobufDumper::DumpProtobufs({std::filesystem::path(program.get<std::string>("in"))}, program.get<std::string>("out") + "/protobufs");
}
