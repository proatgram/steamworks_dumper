#ifndef CLIENTINTERFACEDUMPER_H
#define CLIENTINTERFACEDUMPER_H
#include "dumperbase.h"

struct InterfaceFunction
{
    std::string m_name;
    int m_argc;
    size_t m_addr;
    uint8_t m_interfaceid;
    uint32_t m_functionid;
    uint32_t m_fencepost;
    std::vector<std::string> m_serializedargs;
    std::vector<std::string> m_serializedreturns;
    std::string m_serializedreturn;
    bool m_cannotcallincrossprocess;
};

struct ClientInterface
{
    size_t m_foundAt;
    std::vector<InterfaceFunction> m_functions;
};

class ClientInterfaceDumper: public DumperBase
{
public:
    ClientInterfaceDumper(ClientModule* t_module);
    ~ClientInterfaceDumper();

    size_t FindClientInterfaces();
    const std::map<std::string, ClientInterface>* GetInterfaces();

private:
    ClientInterfaceDumper();

    void ParseVTable(std::string t_typeName, size_t t_vtoffset);
    bool GetSerializedFuncInfo(std::string t_iname, size_t t_offset, size_t* t_argc, std::string* t_name, uint8_t* interfaceid, uint32_t* functionid, uint32_t* fencepost, std::vector<std::string>* serializedArgs, std::vector<std::string>* serializedReturns, std::string *serializedReturn, bool *cannotCallInCrossProcess);
    bool CheckIfPutStringFunc(csh csHandle, size_t funcOffset);
    bool CheckIfGetStringFunc(csh csHandle, size_t funcOffset);
    bool CheckIfAssertCannotCallInCrossProcessFunc(csh csHandle, size_t funcOffset);
    size_t GetIClientEngine();

    const Elf32_Shdr* m_relRoShdr;
    const Elf32_Shdr* m_relRoLocalShdr;
    const Elf32_Shdr* m_txtShdr;
    const Elf32_Shdr* m_roShdr;

    size_t m_steamFree;
    size_t m_ipcClientFreeFuncCallReturnBuffer;
    size_t m_logIPCCallFailure;

    size_t m_utlbufferPutUtlvector;
    size_t m_utlbufferPutSteamNetworkingIdentity;
    size_t m_utlbufferPutUtlbuffer;
    size_t m_utlbufferGetUtlbuffer;
    size_t m_utlbufferPutProtobuf;
    size_t m_utlbufferGetProtobuf;
    size_t m_assertCannotCallInCrossProcess;
    size_t m_utlbufferGetString;
    size_t m_utlbufferPutString;
    size_t m_utlbufferPutUnsignedInt64Offset;
    size_t m_utlbufferGetUnsignedInt64Offset;
    size_t m_utlbufferGetBytes;
    size_t m_utlbufferPutBytes;
    size_t m_utlbufferPutByte;

    size_t m_sendSerializedFnOffset;
    size_t m_clientApiInitGlobal;

    size_t m_strlen;

    std::map<std::string, ClientInterface> m_interfaces;
};

#endif // CLIENTINTERFACEDUMPER_H
