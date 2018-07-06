//===- InputFiles.cpp -----------------------------------------------------===//
//
//                             The LLVM Linker
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#include "InputFiles.h"
#include "Chunks.h"
#include "Config.h"
#include "Driver.h"
#include "SymbolTable.h"
#include "Symbols.h"
#include "lld/Common/ErrorHandler.h"
#include "lld/Common/Memory.h"
#include "llvm-c/lto.h"
#include "llvm/ADT/SmallVector.h"
#include "llvm/ADT/Triple.h"
#include "llvm/ADT/Twine.h"
#include "llvm/BinaryFormat/COFF.h"
#include "llvm/Object/Binary.h"
#include "llvm/Object/COFF.h"
#include "llvm/Support/Casting.h"
#include "llvm/Support/Endian.h"
#include "llvm/Support/Error.h"
#include "llvm/Support/ErrorOr.h"
#include "llvm/Support/FileSystem.h"
#include "llvm/Target/TargetOptions.h"
#include <cstring>
#include <system_error>
#include <utility>

using namespace llvm;
using namespace llvm::COFF;
using namespace llvm::object;
using namespace llvm::support::endian;

using llvm::Triple;
using llvm::support::ulittle32_t;

namespace lld {
namespace coff {

std::vector<ObjFile *> ObjFile::Instances;
std::vector<ImportFile *> ImportFile::Instances;
std::vector<BitcodeFile *> BitcodeFile::Instances;

/// Checks that Source is compatible with being a weak alias to Target.
/// If Source is Undefined and has no weak alias set, makes it a weak
/// alias to Target.
static void checkAndSetWeakAlias(SymbolTable *Symtab, InputFile *F,
                                 Symbol *Source, Symbol *Target) {
  if (auto *U = dyn_cast<Undefined>(Source)) {
    if (U->WeakAlias && U->WeakAlias != Target)
      Symtab->reportDuplicate(Source, F);
    U->WeakAlias = Target;
  }
}

ArchiveFile::ArchiveFile(MemoryBufferRef M) : InputFile(ArchiveKind, M) {}

void ArchiveFile::parse() {
  // Parse a MemoryBufferRef as an archive file.
  File = CHECK(Archive::create(MB), this);

  // Read the symbol table to construct Lazy objects.
  for (const Archive::Symbol &Sym : File->symbols())
    Symtab->addLazy(this, Sym);
}

// Returns a buffer pointing to a member file containing a given symbol.
void ArchiveFile::addMember(const Archive::Symbol *Sym) {
  const Archive::Child &C =
      CHECK(Sym->getMember(),
            "could not get the member for symbol " + Sym->getName());

  // Return an empty buffer if we have already returned the same buffer.
  if (!Seen.insert(C.getChildOffset()).second)
    return;

  Driver->enqueueArchiveMember(C, Sym->getName(), getName());
}

std::vector<MemoryBufferRef> getArchiveMembers(Archive *File) {
  std::vector<MemoryBufferRef> V;
  Error Err = Error::success();
  for (const ErrorOr<Archive::Child> &COrErr : File->children(Err)) {
    Archive::Child C =
        CHECK(COrErr,
              File->getFileName() + ": could not get the child of the archive");
    MemoryBufferRef MBRef =
        CHECK(C.getMemoryBufferRef(),
              File->getFileName() +
                  ": could not get the buffer for a child of the archive");
    V.push_back(MBRef);
  }
  if (Err)
    fatal(File->getFileName() +
          ": Archive::children failed: " + toString(std::move(Err)));
  return V;
}

void ObjFile::parse() {
  // Parse a memory buffer as a COFF file.
  std::unique_ptr<Binary> Bin = CHECK(createBinary(MB), this);

  if (auto *Obj = dyn_cast<COFFObjectFile>(Bin.get())) {
    Bin.release();
    COFFObj.reset(Obj);
  } else {
    fatal(toString(this) + " is not a COFF file");
  }

  // Read section and symbol tables.
  initializeChunks();
  initializeSymbols();
}

// We set SectionChunk pointers in the SparseChunks vector to this value
// temporarily to mark comdat sections as having an unknown resolution. As we
// walk the object file's symbol table, once we visit either a leader symbol or
// an associative section definition together with the parent comdat's leader,
// we set the pointer to either nullptr (to mark the section as discarded) or a
// valid SectionChunk for that section.
static SectionChunk *const PendingComdat = reinterpret_cast<SectionChunk *>(1);

void ObjFile::initializeChunks() {
  uint32_t NumSections = COFFObj->getNumberOfSections();
  Chunks.reserve(NumSections);
  SparseChunks.resize(NumSections + 1);
  for (uint32_t I = 1; I < NumSections + 1; ++I) {
    const coff_section *Sec;
    if (auto EC = COFFObj->getSection(I, Sec))
      fatal("getSection failed: #" + Twine(I) + ": " + EC.message());

    if (Sec->Characteristics & IMAGE_SCN_LNK_COMDAT)
      SparseChunks[I] = PendingComdat;
    else
      SparseChunks[I] = readSection(I, nullptr);
  }
}

SectionChunk *ObjFile::readSection(uint32_t SectionNumber,
                                   const coff_aux_section_definition *Def) {
  const coff_section *Sec;
  StringRef Name;
  if (auto EC = COFFObj->getSection(SectionNumber, Sec))
    fatal("getSection failed: #" + Twine(SectionNumber) + ": " + EC.message());
  if (auto EC = COFFObj->getSectionName(Sec, Name))
    fatal("getSectionName failed: #" + Twine(SectionNumber) + ": " +
          EC.message());
  if (Name == ".sxdata") {
    ArrayRef<uint8_t> Data;
    COFFObj->getSectionContents(Sec, Data);
    if (Data.size() % 4 != 0)
      fatal(".sxdata must be an array of symbol table indices");
    SXData = {reinterpret_cast<const ulittle32_t *>(Data.data()),
              Data.size() / 4};
    return nullptr;
  }
  if (Name == ".drectve") {
    ArrayRef<uint8_t> Data;
    COFFObj->getSectionContents(Sec, Data);
    Directives = std::string((const char *)Data.data(), Data.size());
    return nullptr;
  }

  // Object files may have DWARF debug info or MS CodeView debug info
  // (or both).
  //
  // DWARF sections don't need any special handling from the perspective
  // of the linker; they are just a data section containing relocations.
  // We can just link them to complete debug info.
  //
  // CodeView needs a linker support. We need to interpret and debug
  // info, and then write it to a separate .pdb file.

  // Ignore debug info unless /debug is given.
  if (!Config->Debug && Name.startswith(".debug"))
    return nullptr;

  if (Sec->Characteristics & llvm::COFF::IMAGE_SCN_LNK_REMOVE)
    return nullptr;
  auto *C = make<SectionChunk>(this, Sec);
  if (Def)
    C->Checksum = Def->CheckSum;

  // CodeView sections are stored to a different vector because they are not
  // linked in the regular manner.
  if (C->isCodeView())
    DebugChunks.push_back(C);
  else
    Chunks.push_back(C);

  return C;
}

void ObjFile::readAssociativeDefinition(
    COFFSymbolRef Sym, const coff_aux_section_definition *Def) {
  SectionChunk *Parent = SparseChunks[Def->getNumber(Sym.isBigObj())];

  // If the parent is pending, it probably means that its section definition
  // appears after us in the symbol table. Leave the associated section as
  // pending; we will handle it during the second pass in initializeSymbols().
  if (Parent == PendingComdat)
    return;

  // Check whether the parent is prevailing. If it is, so are we, and we read
  // the section; otherwise mark it as discarded.
  int32_t SectionNumber = Sym.getSectionNumber();
  if (Parent) {
    SparseChunks[SectionNumber] = readSection(SectionNumber, Def);
    if (SparseChunks[SectionNumber])
      Parent->addAssociative(SparseChunks[SectionNumber]);
  } else {
    SparseChunks[SectionNumber] = nullptr;
  }
}

Symbol *ObjFile::createRegular(COFFSymbolRef Sym) {
  SectionChunk *SC = SparseChunks[Sym.getSectionNumber()];
  if (Sym.isExternal()) {
    StringRef Name;
    COFFObj->getSymbolName(Sym, Name);
    if (SC)
      return Symtab->addRegular(this, Name, Sym.getGeneric(), SC);
    return Symtab->addUndefined(Name, this, false);
  }
  if (SC)
    return make<DefinedRegular>(this, /*Name*/ "", false,
                                /*IsExternal*/ false, Sym.getGeneric(), SC);
  return nullptr;
}

void ObjFile::initializeSymbols() {
  uint32_t NumSymbols = COFFObj->getNumberOfSymbols();
  Symbols.resize(NumSymbols);

  SmallVector<std::pair<Symbol *, uint32_t>, 8> WeakAliases;
  std::vector<uint32_t> PendingIndexes;
  PendingIndexes.reserve(NumSymbols);

  std::vector<const coff_aux_section_definition *> ComdatDefs(
      COFFObj->getNumberOfSections() + 1);

  for (uint32_t I = 0; I < NumSymbols; ++I) {
    COFFSymbolRef COFFSym = check(COFFObj->getSymbol(I));
    if (COFFSym.isUndefined()) {
      Symbols[I] = createUndefined(COFFSym);
    } else if (COFFSym.isWeakExternal()) {
      Symbols[I] = createUndefined(COFFSym);
      uint32_t TagIndex = COFFSym.getAux<coff_aux_weak_external>()->TagIndex;
      WeakAliases.emplace_back(Symbols[I], TagIndex);
    } else if (Optional<Symbol *> OptSym = createDefined(COFFSym, ComdatDefs)) {
      Symbols[I] = *OptSym;
    } else {
      // createDefined() returns None if a symbol belongs to a section that
      // was pending at the point when the symbol was read. This can happen in
      // two cases:
      // 1) section definition symbol for a comdat leader;
      // 2) symbol belongs to a comdat section associated with a section whose
      //    section definition symbol appears later in the symbol table.
      // In both of these cases, we can expect the section to be resolved by
      // the time we finish visiting the remaining symbols in the symbol
      // table. So we postpone the handling of this symbol until that time.
      PendingIndexes.push_back(I);
    }
    I += COFFSym.getNumberOfAuxSymbols();
  }

  for (uint32_t I : PendingIndexes) {
    COFFSymbolRef Sym = check(COFFObj->getSymbol(I));
    if (auto *Def = Sym.getSectionDefinition())
      if (Def->Selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE)
        readAssociativeDefinition(Sym, Def);
    Symbols[I] = createRegular(Sym);
  }

  for (auto &KV : WeakAliases) {
    Symbol *Sym = KV.first;
    uint32_t Idx = KV.second;
    checkAndSetWeakAlias(Symtab, this, Sym, Symbols[Idx]);
  }
}

Symbol *ObjFile::createUndefined(COFFSymbolRef Sym) {
  StringRef Name;
  COFFObj->getSymbolName(Sym, Name);
  return Symtab->addUndefined(Name, this, Sym.isWeakExternal());
}

Optional<Symbol *> ObjFile::createDefined(
    COFFSymbolRef Sym,
    std::vector<const coff_aux_section_definition *> &ComdatDefs) {
  StringRef Name;
  if (Sym.isCommon()) {
    auto *C = make<CommonChunk>(Sym);
    Chunks.push_back(C);
    COFFObj->getSymbolName(Sym, Name);
    Symbol *S =
        Symtab->addCommon(this, Name, Sym.getValue(), Sym.getGeneric(), C);
    return S;
  }
  if (Sym.isAbsolute()) {
    COFFObj->getSymbolName(Sym, Name);
    // Skip special symbols.
    if (Name == "@comp.id")
      return nullptr;
    // COFF spec 5.10.1. The .sxdata section.
    if (Name == "@feat.00") {
      if (Sym.getValue() & 1)
        SEHCompat = true;
      return nullptr;
    }
    if (Sym.isExternal())
      return Symtab->addAbsolute(Name, Sym);
    else
      return make<DefinedAbsolute>(Name, Sym);
  }
  int32_t SectionNumber = Sym.getSectionNumber();
  if (SectionNumber == llvm::COFF::IMAGE_SYM_DEBUG)
    return nullptr;

  // Reserved sections numbers don't have contents.
  if (llvm::COFF::isReservedSectionNumber(SectionNumber))
    fatal("broken object file: " + toString(this));

  // This symbol references a section which is not present in the section
  // header.
  if ((uint32_t)SectionNumber >= SparseChunks.size())
    fatal("broken object file: " + toString(this));

  // Handle comdat leader symbols.
  if (const coff_aux_section_definition *Def = ComdatDefs[SectionNumber]) {
    ComdatDefs[SectionNumber] = nullptr;
    Symbol *Leader;
    bool Prevailing;
    if (Sym.isExternal()) {
      COFFObj->getSymbolName(Sym, Name);
      std::tie(Leader, Prevailing) =
          Symtab->addComdat(this, Name, Sym.getGeneric());
    } else {
      Leader = make<DefinedRegular>(this, /*Name*/ "", false,
                                    /*IsExternal*/ false, Sym.getGeneric());
      Prevailing = true;
    }
    if (Prevailing) {
      SectionChunk *C = readSection(SectionNumber, Def);
      SparseChunks[SectionNumber] = C;
      C->Sym = cast<DefinedRegular>(Leader);
      cast<DefinedRegular>(Leader)->Data = &C->Repl;
    } else {
      SparseChunks[SectionNumber] = nullptr;
    }
    return Leader;
  }

  // Read associative section definitions and prepare to handle the comdat
  // leader symbol by setting the section's ComdatDefs pointer if we encounter a
  // non-associative comdat.
  if (SparseChunks[SectionNumber] == PendingComdat) {
    if (auto *Def = Sym.getSectionDefinition()) {
      if (Def->Selection == IMAGE_COMDAT_SELECT_ASSOCIATIVE)
        readAssociativeDefinition(Sym, Def);
      else
        ComdatDefs[SectionNumber] = Def;
    }
  }

  if (SparseChunks[SectionNumber] == PendingComdat)
    return None;
  return createRegular(Sym);
}

MachineTypes ObjFile::getMachineType() {
  if (COFFObj)
    return static_cast<MachineTypes>(COFFObj->getMachine());
  return IMAGE_FILE_MACHINE_UNKNOWN;
}

StringRef ltrim1(StringRef S, const char *Chars) {
  if (!S.empty() && strchr(Chars, S[0]))
    return S.substr(1);
  return S;
}

void ImportFile::parse() {
  const char *Buf = MB.getBufferStart();
  const char *End = MB.getBufferEnd();
  const auto *Hdr = reinterpret_cast<const coff_import_header *>(Buf);

  // Check if the total size is valid.
  if ((size_t)(End - Buf) != (sizeof(*Hdr) + Hdr->SizeOfData))
    fatal("broken import library");

  // Read names and create an __imp_ symbol.
  StringRef Name = Saver.save(StringRef(Buf + sizeof(*Hdr)));
  StringRef ImpName = Saver.save("__imp_" + Name);
  const char *NameStart = Buf + sizeof(coff_import_header) + Name.size() + 1;
  DLLName = StringRef(NameStart);
  StringRef ExtName;
  switch (Hdr->getNameType()) {
  case IMPORT_ORDINAL:
    ExtName = "";
    break;
  case IMPORT_NAME:
    ExtName = Name;
    break;
  case IMPORT_NAME_NOPREFIX:
    ExtName = ltrim1(Name, "?@_");
    break;
  case IMPORT_NAME_UNDECORATE:
    ExtName = ltrim1(Name, "?@_");
    ExtName = ExtName.substr(0, ExtName.find('@'));
    break;
  }

  this->Hdr = Hdr;
  ExternalName = ExtName;

  ImpSym = Symtab->addImportData(ImpName, this);

  if (Hdr->getType() == llvm::COFF::IMPORT_CONST)
    static_cast<void>(Symtab->addImportData(Name, this));

  // If type is function, we need to create a thunk which jump to an
  // address pointed by the __imp_ symbol. (This allows you to call
  // DLL functions just like regular non-DLL functions.)
  if (Hdr->getType() == llvm::COFF::IMPORT_CODE)
    ThunkSym = Symtab->addImportThunk(Name, ImpSym, Hdr->Machine);
}

void BitcodeFile::parse() {
  Obj = check(lto::InputFile::create(MemoryBufferRef(
      MB.getBuffer(), Saver.save(ParentName + MB.getBufferIdentifier()))));
  std::vector<std::pair<Symbol *, bool>> Comdat(Obj->getComdatTable().size());
  for (size_t I = 0; I != Obj->getComdatTable().size(); ++I)
    Comdat[I] = Symtab->addComdat(this, Saver.save(Obj->getComdatTable()[I]));
  for (const lto::InputFile::Symbol &ObjSym : Obj->symbols()) {
    StringRef SymName = Saver.save(ObjSym.getName());
    int ComdatIndex = ObjSym.getComdatIndex();
    Symbol *Sym;
    if (ObjSym.isUndefined()) {
      Sym = Symtab->addUndefined(SymName, this, false);
    } else if (ObjSym.isCommon()) {
      Sym = Symtab->addCommon(this, SymName, ObjSym.getCommonSize());
    } else if (ObjSym.isWeak() && ObjSym.isIndirect()) {
      // Weak external.
      Sym = Symtab->addUndefined(SymName, this, true);
      std::string Fallback = ObjSym.getCOFFWeakExternalFallback();
      Symbol *Alias = Symtab->addUndefined(Saver.save(Fallback));
      checkAndSetWeakAlias(Symtab, this, Sym, Alias);
    } else if (ComdatIndex != -1) {
      if (SymName == Obj->getComdatTable()[ComdatIndex])
        Sym = Comdat[ComdatIndex].first;
      else if (Comdat[ComdatIndex].second)
        Sym = Symtab->addRegular(this, SymName);
      else
        Sym = Symtab->addUndefined(SymName, this, false);
    } else {
      Sym = Symtab->addRegular(this, SymName);
    }
    SymbolBodies.push_back(Sym);
  }
  Directives = Obj->getCOFFLinkerOpts();
}

MachineTypes BitcodeFile::getMachineType() {
  switch (Triple(Obj->getTargetTriple()).getArch()) {
  case Triple::x86_64:
    return AMD64;
  case Triple::x86:
    return I386;
  case Triple::arm:
    return ARMNT;
  case Triple::aarch64:
    return ARM64;
  default:
    return IMAGE_FILE_MACHINE_UNKNOWN;
  }
}
} // namespace coff
} // namespace lld

// Returns the last element of a path, which is supposed to be a filename.
static StringRef getBasename(StringRef Path) {
  size_t Pos = Path.find_last_of("\\/");
  if (Pos == StringRef::npos)
    return Path;
  return Path.substr(Pos + 1);
}

// Returns a string in the format of "foo.obj" or "foo.obj(bar.lib)".
std::string lld::toString(const coff::InputFile *File) {
  if (!File)
    return "<internal>";
  if (File->ParentName.empty())
    return File->getName();

  return (getBasename(File->ParentName) + "(" + getBasename(File->getName()) +
          ")")
      .str();
}
