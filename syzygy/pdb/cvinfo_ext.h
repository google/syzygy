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
      decl(S_OEM, OemSymbol) \
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
      decl(S_VFTABLE32, VpathSym32) \
      decl(S_REGREL32_ST, Unknown) \
      decl(S_LTHREAD32_ST, Unknown) \
      decl(S_GTHREAD32_ST, Unknown) \
      decl(S_LPROCMIPS_ST, Unknown) \
      decl(S_GPROCMIPS_ST, Unknown) \
      decl(S_FRAMEPROC, FrameProcSym) \
      decl(S_COMPILE2_ST, Unknown) \
      decl(S_MANYREG2_ST, Unknown) \
      decl(S_LPROCIA64_ST, Unknown) \
      decl(S_GPROCIA64_ST, Unknown) \
      decl(S_LOCALSLOT_ST, Unknown) \
      decl(S_PARAMSLOT_ST, Unknown) \
      decl(S_ANNOTATION, AnnotationSym) \
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
      decl(S_MANTYPREF, ManyTypRef) \
      decl(S_UNAMESPACE_ST, Unknown) \
      decl(S_ST_MAX, Unknown) \
      decl(S_OBJNAME, ObjNameSym) \
      decl(S_THUNK32, ThunkSym32) \
      decl(S_BLOCK32, BlockSym32) \
      decl(S_WITH32, WithSym32) \
      decl(S_LABEL32, LabelSym32) \
      decl(S_REGISTER, RegSym) \
      decl(S_CONSTANT, ConstSym) \
      decl(S_UDT, UdtSym) \
      decl(S_COBOLUDT, UdtSym) \
      decl(S_MANYREG, ManyRegSym) \
      decl(S_BPREL32, BpRelSym32) \
      decl(S_LDATA32, DatasSym32) \
      decl(S_GDATA32, DatasSym32) \
      decl(S_PUB32, DatasSym32) \
      decl(S_LPROC32, ProcSym32) \
      decl(S_GPROC32, ProcSym32) \
      decl(S_REGREL32, RegRel32) \
      decl(S_LTHREAD32, ThreadSym32) \
      decl(S_GTHREAD32, ThreadSym32) \
      decl(S_LPROCMIPS, ProcSymMips) \
      decl(S_GPROCMIPS, ProcSymMips) \
      decl(S_COMPILE2, CompileSym) \
      decl(S_MANYREG2, ManyRegSym2) \
      decl(S_LPROCIA64, ProcSymIa64) \
      decl(S_GPROCIA64, ProcSymIa64) \
      decl(S_LOCALSLOT, SlotSym32) \
      decl(S_PARAMSLOT, SlotSym32) \
      decl(S_LMANDATA, DatasSym32) \
      decl(S_GMANDATA, DatasSym32) \
      decl(S_MANFRAMEREL, FrameRelSym) \
      decl(S_MANREGISTER, AttrRegSym) \
      decl(S_MANSLOT, AttrSlotSym) \
      decl(S_MANMANYREG, AttrManyRegSym) \
      decl(S_MANREGREL, AttrRegRel) \
      decl(S_MANMANYREG2, AttrManyRegSym2) \
      decl(S_UNAMESPACE, UnamespaceSym) \
      decl(S_PROCREF, RefSym2) \
      decl(S_DATAREF, RefSym2) \
      decl(S_LPROCREF, RefSym2) \
      decl(S_ANNOTATIONREF, Unknown) \
      decl(S_TOKENREF, Unknown) \
      decl(S_GMANPROC, ManProcSym) \
      decl(S_LMANPROC, ManProcSym) \
      decl(S_TRAMPOLINE, TrampolineSym) \
      decl(S_MANCONSTANT, ConstSym) \
      decl(S_ATTR_FRAMEREL, FrameRelSym) \
      decl(S_ATTR_REGISTER, AttrRegSym) \
      decl(S_ATTR_REGREL, AttrRegRel) \
      decl(S_ATTR_MANYREG, AttrManyRegSym2) \
      decl(S_SEPCODE, SepCodSym) \
      decl(S_LOCAL, LocalSym) \
      decl(S_DEFRANGE, DefRangeSym) \
      decl(S_DEFRANGE2, DefRangeSym2) \
      decl(S_SECTION, SectionSym) \
      decl(S_COFFGROUP, CoffGroupSym) \
      decl(S_EXPORT, ExportSym) \
      decl(S_CALLSITEINFO, CallsiteInfo) \
      decl(S_FRAMECOOKIE, FrameCookie) \
      decl(S_DISCARDED, DiscardedSym) \
      decl(S_RECTYPE_MAX, Unknown)

// This macro allows the easy construction of switch statements over the
// numeric leaves types.
#define NUMERIC_LEAVES_CASE_TABLE(decl) \
      decl(LF_CHAR, LeafChar) \
      decl(LF_SHORT, LeafShort) \
      decl(LF_USHORT, LeafUShort) \
      decl(LF_LONG, LeafLong) \
      decl(LF_ULONG, LeafULong) \
      decl(LF_REAL32, LeafReal32) \
      decl(LF_REAL64, LeafReal64) \
      decl(LF_REAL80, LeafReal80) \
      decl(LF_REAL128, LeafReal128) \
      decl(LF_QUADWORD, LeafQuad) \
      decl(LF_UQUADWORD, LeafUQuad) \
      decl(LF_COMPLEX32, LeafCmplx32) \
      decl(LF_COMPLEX64, LeafCmplx64) \
      decl(LF_COMPLEX80, LeafCmplx80) \
      decl(LF_COMPLEX128, LeafCmplx128)

#endif  // SYZYGY_PDB_CVINFO_EXT_H_
