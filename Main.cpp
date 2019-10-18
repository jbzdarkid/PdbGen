#pragma warning(push)
#pragma warning(disable : 4141)
#pragma warning(disable : 4146)
#pragma warning(disable : 4244)
#pragma warning(disable : 4267)
#pragma warning(disable : 4996)
#pragma warning(disable : 4624)
#include <llvm/DebugInfo/CodeView/StringsAndChecksums.h>
#include <llvm/DebugInfo/MSF/MSFBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiModuleDescriptorBuilder.h>
#include <llvm/DebugInfo/PDB/Native/DbiStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/GSIStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/InfoStreamBuilder.h>
#include <llvm/DebugInfo/PDB/Native/PDBFileBuilder.h>
#include <llvm/DebugInfo/PDB/Native/TpiStreamBuilder.h>
#include <llvm/Object/Binary.h>
#include <llvm/Object/COFF.h>
#pragma warning(pop)

#include <charconv>
#include <fstream>
#include <sstream>

namespace cv = llvm::codeview;

namespace
{
llvm::ExitOnError ExitOnErr;

struct ModuleInfo
{
    bool is64Bit{};
    std::vector<llvm::object::coff_section> sections;
    cv::GUID guid{};
    uint32_t age{};
    uint32_t signature{};
};

llvm::Error ReadModuleInfo(const std::string& modulePath, ModuleInfo& info)
{
    using namespace llvm;
    using namespace llvm::object;

    auto expectedBinary = createBinary(modulePath);
    if (!expectedBinary)
        return expectedBinary.takeError();

    OwningBinary<Binary> binary = std::move(*expectedBinary);

    if (binary.getBinary()->isCOFF()) {
        auto const obj = llvm::cast<COFFObjectFile>(binary.getBinary());
        for (auto const& sectionRef : obj->sections())
            info.sections.push_back(*obj->getCOFFSection(sectionRef));

        info.is64Bit = obj->is64();
        for (auto const& debugDir : obj->debug_directories()) {
            info.signature = debugDir.TimeDateStamp;
            if (debugDir.Type == COFF::IMAGE_DEBUG_TYPE_CODEVIEW) {
                cv::DebugInfo const* debugInfo;
                StringRef pdbFileName;
                if (auto const ec =
                        obj->getDebugPDBInfo(&debugDir, debugInfo, pdbFileName))
                    return errorCodeToError(ec);

                switch (debugInfo->Signature.CVSignature) {
                case OMF::Signature::PDB70:
                    info.age = debugInfo->PDB70.Age;
                    std::memcpy(&info.guid, debugInfo->PDB70.Signature,
                                sizeof(info.guid));
                    break;
                }
            }
        }

        return Error::success();
    }

    return errorCodeToError(std::make_error_code(std::errc::not_supported));
}

bool ReadSymbolEntry(llvm::BumpPtrAllocator& allocator, std::string_view line,
                     llvm::StringRef& name, uint32_t& rva)
{
    size_t const delim = line.find('\t');
    if (delim == std::string::npos)
        return false;

    auto const nameStr = std::string_view(line).substr(0, delim);
    auto const rvaStr = std::string_view(line).substr(delim + 1);

    std::stringstream ss;
    ss << std::hex << rvaStr;
    ss >> rva;

    auto const nameBuffer = allocator.Allocate<char>(nameStr.length() * nameStr[0]);
    std::copy_n(nameStr.data(), nameStr.length(), nameBuffer);
    name = llvm::StringRef(nameBuffer, nameStr.length());
    return true;
}

void ReadSymbols(llvm::BumpPtrAllocator& allocator, char const* symbolListFile,
                 std::vector<cv::PublicSym32>& publics)
{
    std::ifstream input;
    input.open(symbolListFile, std::ios_base::in);

    std::string line;
    while (std::getline(input, line)) {
        llvm::StringRef name;
        uint32_t rva;
        if (!ReadSymbolEntry(allocator, line, name, rva))
            continue;
        cv::PublicSym32& ps = publics.emplace_back(cv::SymbolRecordKind::PublicSym32);
        ps.Offset = rva;
        ps.Segment = 1;
        ps.Flags = cv::PublicSymFlags::Function;
        ps.Name = name;
    }
}

void GeneratePDB(llvm::BumpPtrAllocator& allocator, ModuleInfo const& moduleInfo,
                 std::vector<cv::PublicSym32>& publics, char const* outputFileName)
{
    char const* const moduleName = "d:\\dummy.obj";

    llvm::pdb::PDBFileBuilder builder(allocator);

    uint32_t const blockSize = 4096;
    ExitOnErr(builder.initialize(blockSize));

    // Add each of the reserved streams.  We might not put any data in them,
    // but at least they have to be present.
    for (uint32_t i = 0; i < llvm::pdb::kSpecialStreamCount; ++i)
        ExitOnErr(builder.getMsfBuilder().addStream(0));

    auto& infoBuilder = builder.getInfoBuilder();
    infoBuilder.setAge(moduleInfo.age);
    infoBuilder.setGuid(moduleInfo.guid);
    infoBuilder.setSignature(moduleInfo.signature);
    infoBuilder.setVersion(llvm::pdb::PdbImplVC70);
    infoBuilder.addFeature(llvm::pdb::PdbRaw_FeatureSig::VC140);

    auto& dbiBuilder = builder.getDbiBuilder();
    dbiBuilder.setAge(moduleInfo.age);
    dbiBuilder.setBuildNumber(35584);
    dbiBuilder.setFlags(2);
    dbiBuilder.setMachineType(moduleInfo.is64Bit ? llvm::pdb::PDB_Machine::Amd64
                                                 : llvm::pdb::PDB_Machine::x86);
    dbiBuilder.setPdbDllRbld(1);
    dbiBuilder.setPdbDllVersion(1);
    dbiBuilder.setVersionHeader(llvm::pdb::PdbDbiV70);

    auto const sectionMap =
        llvm::pdb::DbiStreamBuilder::createSectionMap(moduleInfo.sections);
    dbiBuilder.setSectionMap(sectionMap);

    ExitOnErr(dbiBuilder.addDbgStream(
        llvm::pdb::DbgHeaderType::SectionHdr,
        {reinterpret_cast<uint8_t const*>(moduleInfo.sections.data()),
         moduleInfo.sections.size() * sizeof(moduleInfo.sections[0])}));

    auto& modiBuilder = ExitOnErr(dbiBuilder.addModuleInfo(moduleName));
    modiBuilder.setObjFileName(moduleName);

    auto& gsiBuilder = builder.getGsiBuilder();

    std::sort(publics.begin(), publics.end(),
              [](auto const& l, auto const& r) { return l.Name < r.Name; });
    for (cv::PublicSym32 const& pub : publics)
        gsiBuilder.addPublicSymbol(pub);

    auto& tpiBuilder = builder.getTpiBuilder();
    tpiBuilder.setVersionHeader(llvm::pdb::PdbTpiV80);

    auto& ipiBuilder = builder.getIpiBuilder();
    ipiBuilder.setVersionHeader(llvm::pdb::PdbTpiV80);

    cv::StringsAndChecksums strings;
    strings.setStrings(std::make_shared<cv::DebugStringTableSubsection>());
    strings.strings()->insert("");
    builder.getStringTableBuilder().setStrings(*strings.strings());

    dbiBuilder.setPublicsStreamIndex(gsiBuilder.getPublicsStreamIndex());
    // dbiBuilder.setGlobalsStreamIndex(gsiBuilder.getGlobalsStreamIndex());
    // dbiBuilder.setSymbolRecordStreamIndex(gsiBuilder.getRecordStreamIdx());

    auto mutableGuid = moduleInfo.guid;
    ExitOnErr(builder.commit(outputFileName, &mutableGuid));
}

} // namespace

int main(int argc, char** argv)
{
    llvm::BumpPtrAllocator allocator;

    ModuleInfo moduleInfo;
    ExitOnErr(ReadModuleInfo("PDBTest.exe", moduleInfo));

    std::vector<cv::PublicSym32> publics;
    ReadSymbols(allocator, "symbols.txt", publics);
    if (publics.empty()) {
        return 1;
    }

    GeneratePDB(allocator, moduleInfo, publics, "PDBTest.pdb");
    return 0;
}
