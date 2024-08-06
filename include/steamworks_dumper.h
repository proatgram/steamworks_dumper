#include "clientmodule.h"

void DumpEnums(ClientModule* t_module, const std::string& t_outPath);
void DumpInterfaces(ClientModule* t_module, const std::string& t_outPath, bool t_includeOffsets);
void DumpCallbacks(ClientModule* t_module, const std::string& t_outPath, bool t_includeOffsets);
void DumpLegacyEMsgList(ClientModule* t_module, const std::string& t_outPath);

int Dump(const std::string &modulePath, const std::string &outputPath, bool includeOffsets);
