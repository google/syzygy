// Copyright 2012 Google Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// This header is an extension to the cvinfo.h file from the CCI project.

#ifndef SYZYGY_PDB_CVINFO_EXT_H_
#define SYZYGY_PDB_CVINFO_EXT_H_

#include "third_party/cci/files/cvinfo.h"

// This macro allow the easy construction of switch statements over the symbol
// type enum. It define the case table, the first parameter of each entry is the
// type of the symbol and the second one is the type of structure used to
// represent this symbol.
#define SYM_TYPE_CASE_TABLE(decl) \
      decl(S_OEM, Unknown) \
      decl(S_REGISTER_ST, Unknown) \
      decl(S_CONSTANT_ST, Unknown) \
      decl(S_UDT_ST, Unknown) \
      decl(S_COBOLUDT_ST, Unknown) \
      decl(S_MANYREG_ST, Unknown) \
      decl(S_BPREL32_ST, Unknown) \
      decl(S_LDATA32_ST, Unknown) \
      decl(S_GDATA32_ST, Unknown) \
      decl(S_PUB32_ST, Unknown) \
      decl(S_LPROC32_ST, Unknown) \
      decl(S_GPROC32_ST, Unknown) \
      decl(S_VFTABLE32, Unknown) \
      decl(S_REGREL32_ST, Unknown) \
      decl(S_LTHREAD32_ST, Unknown) \
      decl(S_GTHREAD32_ST, Unknown) \
      decl(S_LPROCMIPS_ST, Unknown) \
      decl(S_GPROCMIPS_ST, Unknown) \
      decl(S_FRAMEPROC, Unknown) \
      decl(S_COMPILE2_ST, Unknown) \
      decl(S_MANYREG2_ST, Unknown) \
      decl(S_LPROCIA64_ST, Unknown) \
      decl(S_GPROCIA64_ST, Unknown) \
      decl(S_LOCALSLOT_ST, Unknown) \
      decl(S_PARAMSLOT_ST, Unknown) \
      decl(S_ANNOTATION, Unknown) \
      decl(S_GMANPROC_ST, Unknown) \
      decl(S_LMANPROC_ST, Unknown) \
      decl(S_RESERVED1, Unknown) \
      decl(S_RESERVED2, Unknown) \
      decl(S_RESERVED3, Unknown) \
      decl(S_RESERVED4, Unknown) \
      decl(S_LMANDATA_ST, Unknown) \
      decl(S_GMANDATA_ST, Unknown) \
      decl(S_MANFRAMEREL_ST, Unknown) \
      decl(S_MANREGISTER_ST, Unknown) \
      decl(S_MANSLOT_ST, Unknown) \
      decl(S_MANMANYREG_ST, Unknown) \
      decl(S_MANREGREL_ST, Unknown) \
      decl(S_MANMANYREG2_ST, Unknown) \
      decl(S_MANTYPREF, Unknown) \
      decl(S_UNAMESPACE_ST, Unknown) \
      decl(S_ST_MAX, Unknown) \
      decl(S_OBJNAME, Unknown) \
      decl(S_THUNK32, Unknown) \
      decl(S_BLOCK32, Unknown) \
      decl(S_WITH32, Unknown) \
      decl(S_LABEL32, Unknown) \
      decl(S_REGISTER, Unknown) \
      decl(S_CONSTANT, Unknown) \
      decl(S_UDT, Unknown) \
      decl(S_COBOLUDT, Unknown) \
      decl(S_MANYREG, Unknown) \
      decl(S_BPREL32, Unknown) \
      decl(S_LDATA32, DatasSym32) \
      decl(S_GDATA32, DatasSym32) \
      decl(S_PUB32, DatasSym32) \
      decl(S_LPROC32, Unknown) \
      decl(S_GPROC32, Unknown) \
      decl(S_REGREL32, Unknown) \
      decl(S_LTHREAD32, Unknown) \
      decl(S_GTHREAD32, Unknown) \
      decl(S_LPROCMIPS, Unknown) \
      decl(S_GPROCMIPS, Unknown) \
      decl(S_COMPILE2, Unknown) \
      decl(S_MANYREG2, Unknown) \
      decl(S_LPROCIA64, Unknown) \
      decl(S_GPROCIA64, Unknown) \
      decl(S_LOCALSLOT, Unknown) \
      decl(S_PARAMSLOT, Unknown) \
      decl(S_LMANDATA, DatasSym32) \
      decl(S_GMANDATA, DatasSym32) \
      decl(S_MANFRAMEREL, Unknown) \
      decl(S_MANREGISTER, Unknown) \
      decl(S_MANSLOT, Unknown) \
      decl(S_MANMANYREG, Unknown) \
      decl(S_MANREGREL, Unknown) \
      decl(S_MANMANYREG2, Unknown) \
      decl(S_UNAMESPACE, Unknown) \
      decl(S_PROCREF, RefSym2) \
      decl(S_DATAREF, RefSym2) \
      decl(S_LPROCREF, RefSym2) \
      decl(S_ANNOTATIONREF, Unknown) \
      decl(S_TOKENREF, Unknown) \
      decl(S_GMANPROC, Unknown) \
      decl(S_LMANPROC, Unknown) \
      decl(S_TRAMPOLINE, Unknown) \
      decl(S_MANCONSTANT, Unknown) \
      decl(S_ATTR_FRAMEREL, Unknown) \
      decl(S_ATTR_REGISTER, Unknown) \
      decl(S_ATTR_REGREL, Unknown) \
      decl(S_ATTR_MANYREG, Unknown) \
      decl(S_SEPCODE, Unknown) \
      decl(S_LOCAL, Unknown) \
      decl(S_DEFRANGE, Unknown) \
      decl(S_DEFRANGE2, Unknown) \
      decl(S_SECTION, Unknown) \
      decl(S_COFFGROUP, Unknown) \
      decl(S_EXPORT, Unknown) \
      decl(S_CALLSITEINFO, Unknown) \
      decl(S_FRAMECOOKIE, Unknown) \
      decl(S_DISCARDED, Unknown) \
      decl(S_RECTYPE_MAX, Unknown)

#endif  // SYZYGY_PDB_CVINFO_EXT_H_
