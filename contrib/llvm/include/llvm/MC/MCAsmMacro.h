//===- MCAsmMacro.h - Assembly Macros ---------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#ifndef LLVM_MC_MCASMMACRO_H
#define LLVM_MC_MCASMMACRO_H

#include "llvm/MC/MCParser/MCAsmLexer.h"

namespace llvm {

struct MCAsmMacroParameter {
  StringRef Name;
  std::vector<AsmToken> Value;
  bool Required = false;
  bool Vararg = false;

  MCAsmMacroParameter() = default;
};

typedef std::vector<MCAsmMacroParameter> MCAsmMacroParameters;
struct MCAsmMacro {
  StringRef Name;
  StringRef Body;
  MCAsmMacroParameters Parameters;

public:
  MCAsmMacro(StringRef N, StringRef B, MCAsmMacroParameters P)
      : Name(N), Body(B), Parameters(std::move(P)) {}
};
}; // namespace llvm

#endif
