// Copyright 2012 Google Inc. All Rights Reserved.
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

#ifndef SYZYGY_PE_CVINFO_EXT_H_
#define SYZYGY_PE_CVINFO_EXT_H_

#include <windows.h>

#include "base/basictypes.h"
#include "syzygy/common/assertions.h"
#include "third_party/cci/files/cvinfo.h"

namespace Microsoft_Cci_Pdb {

// CodeView2 symbols. These are superseded in CodeView4 symbol streams.
// Taken from the Visual C++ 5.0 Symbolic Debug Information Specification.
const uint16 S_COMPILE_CV2 = 0x0001;  // Compile flags symbol.
const uint16 S_SSEARCH = 0x0005;  // Start search.
const uint16 S_SKIP = 0x0007;  // Skip - Reserve symbol space.
const uint16 S_CVRESERVE = 0x0008;  // Reserved for CodeView internal use.
const uint16 S_OBJNAME_CV2 = 0x0009;  // Name of object file.
const uint16 S_ENDARG = 0x000A;  // End of arguments in function symbols.
const uint16 S_COBOLUDT_CV2 = 0x000B;  // Microfocus COBOL user-defined type.
const uint16 S_MANYREG_CV2 = 0x000C;  // Many register symbol.
const uint16 S_RETURN = 0x000D;  // Function return description.
const uint16 S_ENTRYTHIS = 0x000E;  // Description of this pointer at entry.

// Symbols that are not in the enum in the cv_info file.
const uint16 S_COMPILE3 = 0x113C;
const uint16 S_MSTOOLENV_V3 = 0x113D;

// Since VS2013 it seems that the compiler isn't emitting the same value as
// those in cvinfo.h for the S_GPROC32 and S_LPROC32 types, the following 2
// values should be used instead.
const uint16 S_LPROC32_VS2013 = 0x1146;
const uint16 S_GPROC32_VS2013 = 0x1147;

}  // namespace Microsoft_Cci_Pdb

// This macro allow the easy construction of switch statements over the symbol
// type enum. It define the case table, the first parameter of each entry is the
// type of the symbol and the second one is the type of structure used to
// represent this symbol.
#define SYM_TYPE_CASE_TABLE(decl) \
    decl(S_COMPILE_CV2, CompileSymCV2) \
    decl(S_SSEARCH, SearchSym) \
    decl(S_SKIP, Unknown) \
    decl(S_CVRESERVE, Unknown) \
    decl(S_OBJNAME_CV2, ObjNameSym) \
    decl(S_ENDARG, EndArgSym) \
    decl(S_COBOLUDT_CV2, UdtSym) \
    decl(S_MANYREG_CV2, ManyRegSym) \
    decl(S_RETURN, ReturnSym) \
    decl(S_ENTRYTHIS, EntryThisSym) \
    decl(S_END, Unknown) \
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
    decl(S_LPROC32_ST, ProcSym32) \
    decl(S_GPROC32_ST, ProcSym32) \
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
    decl(S_COMPILE3, CompileSym2) \
    decl(S_MSTOOLENV_V3, MSToolEnvV3) \
    decl(S_LPROC32_VS2013, ProcSym32) \
    decl(S_GPROC32_VS2013, ProcSym32)

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

// This macro allow the easy construction of switch statements over the leaf
// enum. It define the case table, the first parameter of each entry is the type
// of the leaf record and the second one is the type of structure used to
// represent this leaf.
#define LEAF_CASE_TABLE(decl) \
    decl(LF_VTSHAPE, LeafVTShape) \
    decl(LF_COBOL1, LeafCobol1) \
    decl(LF_LABEL, LeafLabel) \
    decl(LF_NULL, UnknownLeaf) \
    decl(LF_NOTTRAN, UnknownLeaf) \
    decl(LF_ENDPRECOMP, LeafEndPreComp) \
    decl(LF_TYPESERVER_ST, UnknownLeaf) \
    decl(LF_LIST, LeafList) \
    decl(LF_REFSYM, LeafRefSym) \
    decl(LF_ENUMERATE_ST, UnknownLeaf) \
    decl(LF_TI16_MAX, UnknownLeaf) \
    decl(LF_MODIFIER, LeafModifier) \
    decl(LF_POINTER, LeafPointer) \
    decl(LF_ARRAY_ST, UnknownLeaf) \
    decl(LF_CLASS_ST, UnknownLeaf) \
    decl(LF_STRUCTURE_ST, UnknownLeaf) \
    decl(LF_UNION_ST, UnknownLeaf) \
    decl(LF_ENUM_ST, UnknownLeaf) \
    decl(LF_PROCEDURE, LeafProc) \
    decl(LF_MFUNCTION, LeafMFunc) \
    decl(LF_COBOL0, LeafCobol0) \
    decl(LF_BARRAY, LeafBArray) \
    decl(LF_DIMARRAY_ST, UnknownLeaf) \
    decl(LF_VFTPATH, LeafVFTPath) \
    decl(LF_PRECOMP_ST, UnknownLeaf) \
    decl(LF_OEM, LeafOEM) \
    decl(LF_ALIAS_ST, UnknownLeaf) \
    decl(LF_OEM2, LeafOEM2) \
    decl(LF_SKIP, LeafSkip) \
    decl(LF_ARGLIST, LeafArgList) \
    decl(LF_DEFARG_ST, UnknownLeaf) \
    decl(LF_FIELDLIST, LeafFieldList) \
    decl(LF_DERIVED, LeafDerived) \
    decl(LF_BITFIELD, LeafBitfield) \
    decl(LF_METHODLIST, LeafMethodList) \
    decl(LF_DIMCONU, LeafDimCon) \
    decl(LF_DIMCONLU, LeafDimCon) \
    decl(LF_DIMVARU, LeafDimVar) \
    decl(LF_DIMVARLU, LeafDimVar) \
    decl(LF_BCLASS, LeafBClass) \
    decl(LF_VBCLASS, LeafVBClass) \
    decl(LF_IVBCLASS, LeafVBClass) \
    decl(LF_FRIENDFCN_ST, UnknownLeaf) \
    decl(LF_INDEX, LeafIndex) \
    decl(LF_MEMBER_ST, UnknownLeaf) \
    decl(LF_STMEMBER_ST, UnknownLeaf) \
    decl(LF_METHOD_ST, UnknownLeaf) \
    decl(LF_NESTTYPE_ST, UnknownLeaf) \
    decl(LF_VFUNCTAB, LeafVFuncTab) \
    decl(LF_FRIENDCLS, UnknownLeaf) \
    decl(LF_ONEMETHOD_ST, UnknownLeaf) \
    decl(LF_VFUNCOFF, LeafVFuncOff) \
    decl(LF_NESTTYPEEX_ST, UnknownLeaf) \
    decl(LF_MEMBERMODIFY_ST, UnknownLeaf) \
    decl(LF_MANAGED_ST, UnknownLeaf) \
    decl(LF_TYPESERVER, LeafTypeServer) \
    decl(LF_ENUMERATE, LeafEnumerate) \
    decl(LF_ARRAY, LeafArray) \
    decl(LF_CLASS, LeafClass) \
    decl(LF_STRUCTURE, LeafClass) \
    decl(LF_UNION, LeafUnion) \
    decl(LF_ENUM, LeafEnum) \
    decl(LF_DIMARRAY, LeafDimArray) \
    decl(LF_PRECOMP, LeafPreComp) \
    decl(LF_ALIAS, LeafAlias) \
    decl(LF_DEFARG, LeafDefArg) \
    decl(LF_FRIENDFCN, LeafFriendFcn) \
    decl(LF_MEMBER, LeafMember) \
    decl(LF_STMEMBER, LeafSTMember) \
    decl(LF_METHOD, LeafMethod) \
    decl(LF_NESTTYPE, LeafNestType) \
    decl(LF_ONEMETHOD, LeafOneMethod) \
    decl(LF_NESTTYPEEX, LeafNestTypeEx) \
    decl(LF_MEMBERMODIFY, LeafMemberModify) \
    decl(LF_MANAGED, LeafManaged) \
    decl(LF_TYPESERVER2, LeafTypeServer2) \
    decl(LF_VARSTRING, LeafVarString)

// This macro allow the easy construction of switch statements over the special
// types enum. It define the case table, the parameter of each entry is the type
// of the special type record.
#define SPECIAL_TYPE_CASE_TABLE(decl) \
    decl(T_NOTYPE) \
    decl(T_ABS) \
    decl(T_SEGMENT) \
    decl(T_VOID) \
    decl(T_HRESULT) \
    decl(T_32PHRESULT) \
    decl(T_64PHRESULT) \
    decl(T_PVOID) \
    decl(T_PFVOID) \
    decl(T_PHVOID) \
    decl(T_32PVOID) \
    decl(T_64PVOID) \
    decl(T_CURRENCY) \
    decl(T_NOTTRANS) \
    decl(T_BIT) \
    decl(T_PASCHAR) \
    decl(T_CHAR) \
    decl(T_32PCHAR) \
    decl(T_64PCHAR) \
    decl(T_UCHAR) \
    decl(T_32PUCHAR) \
    decl(T_64PUCHAR) \
    decl(T_RCHAR) \
    decl(T_32PRCHAR) \
    decl(T_64PRCHAR) \
    decl(T_WCHAR) \
    decl(T_32PWCHAR) \
    decl(T_64PWCHAR) \
    decl(T_INT1) \
    decl(T_32PINT1) \
    decl(T_64PINT1) \
    decl(T_UINT1) \
    decl(T_32PUINT1) \
    decl(T_64PUINT1) \
    decl(T_SHORT) \
    decl(T_32PSHORT) \
    decl(T_64PSHORT) \
    decl(T_USHORT) \
    decl(T_32PUSHORT) \
    decl(T_64PUSHORT) \
    decl(T_INT2) \
    decl(T_32PINT2) \
    decl(T_64PINT2) \
    decl(T_UINT2) \
    decl(T_32PUINT2) \
    decl(T_64PUINT2) \
    decl(T_LONG) \
    decl(T_ULONG) \
    decl(T_32PLONG) \
    decl(T_32PULONG) \
    decl(T_64PLONG) \
    decl(T_64PULONG) \
    decl(T_INT4) \
    decl(T_32PINT4) \
    decl(T_64PINT4) \
    decl(T_UINT4) \
    decl(T_32PUINT4) \
    decl(T_64PUINT4) \
    decl(T_QUAD) \
    decl(T_32PQUAD) \
    decl(T_64PQUAD) \
    decl(T_UQUAD) \
    decl(T_32PUQUAD) \
    decl(T_64PUQUAD) \
    decl(T_INT8) \
    decl(T_32PINT8) \
    decl(T_64PINT8) \
    decl(T_UINT8) \
    decl(T_32PUINT8) \
    decl(T_64PUINT8) \
    decl(T_OCT) \
    decl(T_32POCT) \
    decl(T_64POCT) \
    decl(T_UOCT) \
    decl(T_32PUOCT) \
    decl(T_64PUOCT) \
    decl(T_INT16) \
    decl(T_32PINT16) \
    decl(T_64PINT16) \
    decl(T_UINT16) \
    decl(T_32PUINT16) \
    decl(T_64PUINT16) \
    decl(T_REAL32) \
    decl(T_32PREAL32) \
    decl(T_64PREAL32) \
    decl(T_REAL64) \
    decl(T_32PREAL64) \
    decl(T_64PREAL64) \
    decl(T_REAL80) \
    decl(T_32PREAL80) \
    decl(T_64PREAL80) \
    decl(T_REAL128) \
    decl(T_32PREAL128) \
    decl(T_64PREAL128) \
    decl(T_CPLX32) \
    decl(T_32PCPLX32) \
    decl(T_64PCPLX32) \
    decl(T_CPLX64) \
    decl(T_32PCPLX64) \
    decl(T_64PCPLX64) \
    decl(T_CPLX80) \
    decl(T_32PCPLX80) \
    decl(T_64PCPLX80) \
    decl(T_CPLX128) \
    decl(T_32PCPLX128) \
    decl(T_64PCPLX128) \
    decl(T_BOOL08) \
    decl(T_32PBOOL08) \
    decl(T_64PBOOL08) \
    decl(T_BOOL16) \
    decl(T_32PBOOL16) \
    decl(T_64PBOOL16) \
    decl(T_BOOL32) \
    decl(T_32PBOOL32) \
    decl(T_64PBOOL32) \
    decl(T_BOOL64) \
    decl(T_32PBOOL64) \
    decl(T_64PBOOL64)

// All of the data structures below need to have tight alignment so that they
// can be overlaid directly onto byte streams.
#pragma pack(push, 1)

// This structure represent a bitfields for a leaf member attribute field as
// it is describet in the document "Microsoft Symbol and Type Information". Here
// is the bit format:
// mprop       :3 Specifies the properties for methods
//             0 Vanilla method
//             1 Virtual method
//             2 Static method
//             3 Friend method
//             4 Introducing virtual method
//             5 Pure virtual method
//             6 Pure introducing virtual method
//             7 Reserved
// pseudo      :1 True if the method is never instantiated by the compiler
// noinherit   :1 True if the class cannot be inherited
// noconstruct :1 True if the class cannot be constructed
// reserved    :8
union LeafMemberAttributeField {
  // This is effectively the same as CV_access_e in cvconst.h, but with a value
  // defined for 0.
  enum AccessProtection {
    no_access_protection = 0,
    private_access = 1,
    protected_access = 2,
    public_access = 3,
  };
  uint16 raw;
  struct {
    uint16 access      : 2;  // Of type AccessProtection.
    uint16 mprop       : 3;  // Of type CV_methodprop.
    uint16 pseudo      : 1;
    uint16 noinherit   : 1;
    uint16 noconstruct : 1;
    uint16 compgenx    : 1;
    uint16 reserved    : 7;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(LeafMemberAttributeField, 2);

// This structure represent a bitfield for a leaf property field.
union LeafPropertyField {
  uint16 raw;
  struct {
    uint16 packed : 1;
    uint16 ctor : 1;
    uint16 ovlops : 1;
    uint16 isnested : 1;
    uint16 cnested : 1;
    uint16 opassign : 1;
    uint16 opcast : 1;
    uint16 fwdref : 1;
    uint16 scoped : 1;
    uint16 decorated_name_present : 1;
    uint16 reserved : 6;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(LeafPropertyField, 2);

// This structure represent a bitfield for a leaf modifier attribute.
union LeafModifierAttribute {
  uint16 raw;
  struct {
    uint16 mod_const : 1;
    uint16 mod_volatile : 1;
    uint16 mod_unaligned : 1;
    uint16 reserved : 13;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(LeafModifierAttribute, 2);

// This defines flags used in compiland details. See COMPILANDSYM_FLAGS for
// detail.
union CompileSymFlags {
  uint32 raw;
  struct {
    // Language index. See CV_CFL_LANG.
    uint16 iLanguage : 8;
    // Compiled with edit and continue support.
    uint16 fEC : 1;
    // Not compiled with debug info.
    uint16 fNoDbgInfo : 1;
    // Compiled with LTCG.
    uint16 fLTCG : 1;
    // Compiled with -Bzalign.
    uint16 fNoDataAlign : 1;
    // Managed code/data present.
    uint16 fManagedPresent : 1;
    // Compiled with /GS.
    uint16 fSecurityChecks : 1;
    // Compiled with /hotpatch.
    uint16 fHotPatch : 1;
    // Converted with CVTCIL.
    uint16 fCVTCIL : 1;
    // MSIL netmodule
    uint16 fMSILModule : 1;
    uint16 reserved : 15;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 4 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(CompileSymFlags, 4);

// This is a new compiland details symbol type seen in MSVS 2010 and later.
struct CompileSym2 {
  // uint16 reclen;  // Record length.
  // uint16 rectyp;  // S_COMPILE3.
  CompileSymFlags flags;
  // Target processor. See CV_CPU_TYPE_e enum.
  uint16 machine;
  // Front-end major version number.
  uint16 verFEMajor;
  // Front-end minor version number.
  uint16 verFEMinor;
  // Front-end build version number.
  uint16 verFEBuild;
  // Front-end revision number.
  uint16 verFERevision;
  // Back-end major version number.
  uint16 verMajor;
  // Back-end minor version number.
  uint16 verMinor;
  // Back-end build version number.
  uint16 verBuild;
  // Back-end revision number.
  uint16 verRevision;
  // Zero-terminated compiler version string. This is followed by zero or more
  // zero-terminated strings 'verArgs'. The whole list is terminated by an
  // empty verArg string (a double-zero).
  char verSt[1];
};
COMPILE_ASSERT_IS_POD_OF_SIZE(CompileSym2, 23);

// This is a new compiland details symbol type seen in MSVS 2010 and later.
struct MSToolEnvV3 {
  // uint16 reclen;  // Record length.
  // uint16 rectyp;  // S_MSTOOLENV_V3.
  char leading_zero;
  // An array of key-value pairs, encoded as null terminated strings.
  char key_values[1];
};
COMPILE_ASSERT_IS_POD_OF_SIZE(MSToolEnvV3, 2);

// Length prefixed string.
struct LPString {
  uint8 length;
  uint8 string[1];
};
COMPILE_ASSERT_IS_POD_OF_SIZE(LPString, 2);

// Symbols seen in CodeView2 symbol streams.
struct CompileSymCV2 {
  // Machine type. See CV_CPU_TYPE_e enum.
  uint8 machine;
  union {
    // Raw flags.
    uint8 flags[3];
    // Parsed flags.
    struct {
      // Language index. See CV_CFL_LANG.
      uint8 language : 8;
      uint8 pcode_present : 1;
      // 0: ???
      // 1: ANSI C floating point rules.
      // 2-3: Reserved.
      uint8 float_precision : 2;
      // 0: Hardware processor.
      // 1: Emulator.
      // 2: Altmath.
      // 3: Reserved.
      uint8 float_package : 2;
      // 0: Near.
      // 1: Far.
      // 2: Huge.
      // 3-7: Reserved.
      uint8 ambient_data : 3;
      uint8 ambient_code : 3;
      // Compiled for 32-bit addresses.
      uint8 mode32 : 1;
      uint8 reserved : 4;
    };
  };
  // Length-prefixed version string.
  LPString version;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(CompileSymCV2, 6);

#pragma pack(pop)

#endif  // SYZYGY_PE_CVINFO_EXT_H_
