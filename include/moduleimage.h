#ifndef MODULEIMAGE_H
#define MODULEIMAGE_H

#include <string>
#include <string_view>
#include <elf.h>
#include <fstream>
#include <map>

class ModuleImage
{
public:
    ModuleImage(std::string_view t_path);
    ~ModuleImage();

    bool Load();

    const Elf32_Shdr *GetSectionHeader(std::string_view t_section);
    const char* GetImage();
    size_t GetImageSize();
    size_t GetImportRelocByName(std::string_view name);

private:
    ModuleImage();
    ModuleImage(const ModuleImage&);
    ModuleImage& operator=(const ModuleImage&);

    bool IsValid();

    size_t GetFileSize();

    Elf32_Sym* GetSymbolAtOffset(size_t t_offset);

    bool ReadSectionHeaders();
    void LoadModuleImage();

    bool ProcessRelocations();
    bool ProcessDynSymtab();
    void UpdatePltSymbols();

    std::string m_modulePath;
    std::ifstream m_moduleStream;
    size_t m_moduleFileSize;
    bool m_loaded;

    Elf32_Ehdr m_hdr;
    Elf32_Shdr* m_sections;
    char* m_sectStrTab;

    char* m_image;
    size_t m_imageSize;
    std::map<std::string, size_t> locatedSymbols;
};

#endif // MODULEIMAGE_H
