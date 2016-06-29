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

#include <stdint.h>
#include <windows.h>

#include "syzygy/common/assertions.h"
#include "third_party/cci/files/cvinfo.h"

// TODO(siggi): Replace this with the bona-fide Microsoft file.
#include "third_party/microsoft-pdb-copy/files/cvinfo.h"

namespace Microsoft_Cci_Pdb {

// CodeView2 symbols. These are superseded in CodeView4 symbol streams.
// Taken from the Visual C++ 5.0 Symbolic Debug Information Specification.
const uint16_t S_COMPILE_CV2 = 0x0001;  // Compile flags symbol.
const uint16_t S_SSEARCH = 0x0005;  // Start search.
const uint16_t S_SKIP = 0x0007;  // Skip - Reserve symbol space.
const uint16_t S_CVRESERVE = 0x0008;  // Reserved for CodeView internal use.
const uint16_t S_OBJNAME_CV2 = 0x0009;  // Name of object file.
const uint16_t S_ENDARG = 0x000A;  // End of arguments in function symbols.
const uint16_t S_COBOLUDT_CV2 = 0x000B;  // Microfocus COBOL user-defined type.
const uint16_t S_MANYREG_CV2 = 0x000C;  // Many register symbol.
const uint16_t S_RETURN = 0x000D;  // Function return description.
const uint16_t S_ENTRYTHIS = 0x000E;  // Description of this pointer at entry.

// Symbols that are not in the enum in the cv_info file.
const uint16_t S_COMPILE3 = 0x113C;  // Replacement for S_COMPILE2.
const uint16_t S_MSTOOLENV_V3 = 0x113D;  // Environment block split off from
                                       // S_COMPILE2.
const uint16_t S_LOCAL_VS2013 = 0x113E;  // Defines a local symbol in optimized
                                       // code.

// Since VS2013 it seems that the compiler isn't emitting the same value as
// those in cvinfo.h for the S_GPROC32 and S_LPROC32 types, the following 2
// values should be used instead.
const uint16_t S_LPROC32_VS2013 = 0x1146;
const uint16_t S_GPROC32_VS2013 = 0x1147;

}  // namespace Microsoft_Cci_Pdb

// This macro enables the easy construction of switch statements over the
// symbol type enum. It defines the case table, the first parameter of each
// entry is the type of the symbol and the second one is the type of structure
// used to represent this symbol.
// NOTE: All _ST suffixed symbols are identical to those symbols without the
//       _ST suffix. However, the trailing string they contain is encoded as
//       uint16_t length prefixed string, versus a zero-terminated string.
// NOTE: This overrides the association from S_FRAMECOOKIE to the FrameCookie
//       struct (associating FrameCookieSym instead) as observed data does not
//       match the cvinfo struct.
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
    decl(S_UDT_ST, UdtSym) \
    decl(S_COBOLUDT_ST, Unknown) \
    decl(S_MANYREG_ST, Unknown) \
    decl(S_BPREL32_ST, BpRelSym32) \
    decl(S_LDATA32_ST, DatasSym32) \
    decl(S_GDATA32_ST, DatasSym32) \
    decl(S_PUB32_ST, DatasSym32) \
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
    decl(S_PUB32, PubSym32) \
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
    decl(S_FRAMECOOKIE, FrameCookieSym) \
    decl(S_DISCARDED, DiscardedSym) \
    decl(S_COMPILE3, CompileSym2) \
    decl(S_MSTOOLENV_V3, MSToolEnvV3) \
    decl(S_LOCAL_VS2013, LocalSym2013) \
    decl(S_DEFRANGE_REGISTER, DefrangeSymRegister) \
    decl(S_DEFRANGE_FRAMEPOINTER_REL, DefRangeSymFramePointerRel) \
    decl(S_DEFRANGE_SUBFIELD_REGISTER, DefRangeSymSubfieldRegister) \
    decl(S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE, FPOffs2013) \
    decl(S_DEFRANGE_REGISTER_REL, DefRangeSymRegisterRel) \
    decl(S_LPROC32_VS2013, ProcSym32) \
    decl(S_GPROC32_VS2013, ProcSym32) \
    decl(S_INLINESITE, InlineSiteSym) \
    decl(S_INLINESITE_END, Unknown)

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
    decl(LF_VARSTRING, LeafVarString)  \
    decl(LF_FUNC_ID, LeafFunctionId)  \
    decl(LF_MFUNC_ID, LeafMemberFunctionId)  \
    decl(LF_BUILDINFO, LeafBuildInfo)  \
    decl(LF_SUBSTR_LIST, LeafArgList)  \
    decl(LF_STRING_ID, LeafStringId)  \
    decl(LF_UDT_SRC_LINE, LeafUdtSourceLine)  \
    decl(LF_UDT_MOD_SRC_LINE, LeafUdtModuleSourceLine)

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

// This macro allow the easy construction of switch statements over the special
// types enum when constructing their names and sizes.
#define SPECIAL_TYPE_NAME_CASE_TABLE(decl) \
    decl(T_NOTYPE, NoType, 0) \
    decl(T_ABS, Abs, 0) \
    decl(T_SEGMENT, Segment, 0) \
    decl(T_VOID, void, 0) \
    decl(T_PVOID, nullptr_t, 0) \
    decl(T_HRESULT, HRESULT, 4) \
    decl(T_CURRENCY, Currency, 8) \
    decl(T_NOTTRANS, NotTransposed, 0) \
    decl(T_BIT, Bit, 0) \
    decl(T_PASCHAR, char, 1) \
    decl(T_CHAR, int8_t, 1) \
    decl(T_UCHAR, uint8_t, 1) \
    decl(T_RCHAR, char, 1) \
    decl(T_WCHAR, wchar_t, 2) \
    decl(T_INT1, int8_t, 1) \
    decl(T_UINT1, uint8_t, 1) \
    decl(T_SHORT, int16_t, 2) \
    decl(T_USHORT, uint16_t, 2) \
    decl(T_INT2, int16_t, 2) \
    decl(T_UINT2, uint16_t, 2) \
    decl(T_LONG, int32_t, 4) \
    decl(T_ULONG, uint32_t, 4) \
    decl(T_INT4, int32_t, 4) \
    decl(T_UINT4, uint32_t, 4) \
    decl(T_QUAD, int64_t, 8) \
    decl(T_UQUAD, uint64_t, 8) \
    decl(T_INT8, int64_t, 8) \
    decl(T_UINT8, uint64_t, 8) \
    decl(T_OCT, int128_t, 16) \
    decl(T_UOCT, uint128_t, 16) \
    decl(T_INT16, int128_t, 16) \
    decl(T_UINT16, uint128_t, 16) \
    decl(T_REAL32, float, 4) \
    decl(T_REAL64, double, 8) \
    decl(T_REAL80, double80, 10) \
    decl(T_REAL128, double128, 16) \
    decl(T_CPLX32, Complex32, 8) \
    decl(T_CPLX64, Complex64, 16) \
    decl(T_CPLX80, Complex80, 20) \
    decl(T_CPLX128, Complex128, 32) \
    decl(T_BOOL08, bool, 1) \
    decl(T_BOOL16, Bool16, 2) \
    decl(T_BOOL32, Bool32, 4) \
    decl(T_BOOL64, Bool64, 8)

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
// compgenx    :1 True if compiler generated fcn and does exist.
// sealed      :1 True if method cannot be overridden.
// unused      :6
union LeafMemberAttributeField {
  // This is effectively the same as CV_access_e in cvconst.h, but with a value
  // defined for 0.
  enum AccessProtection {
    no_access_protection = 0,
    private_access = 1,
    protected_access = 2,
    public_access = 3,
  };
  uint16_t raw;
  struct {
    uint16_t access      : 2;  // Of type AccessProtection.
    uint16_t mprop       : 3;  // Of type CV_methodprop.
    uint16_t pseudo      : 1;
    uint16_t noinherit   : 1;
    uint16_t noconstruct : 1;
    uint16_t compgenx    : 1;
    uint16_t sealed      : 1;
    uint16_t unused      : 6;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(LeafMemberAttributeField, 2);

// This structure represent a bitfield for a leaf property field.
union LeafPropertyField {
  uint16_t raw;
  struct {
    uint16_t packed : 1;
    uint16_t ctor : 1;
    uint16_t ovlops : 1;
    uint16_t isnested : 1;
    uint16_t cnested : 1;
    uint16_t opassign : 1;
    uint16_t opcast : 1;
    uint16_t fwdref : 1;
    uint16_t scoped : 1;
    uint16_t decorated_name_present : 1;
    uint16_t reserved : 6;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(LeafPropertyField, 2);

// This structure represent a bitfield for a leaf pointer attribute.
union LeafPointerAttribute {
  uint32_t raw;
  struct {
    uint32_t ptrtype : 5;  // Of type CV_ptrtype.
    uint32_t ptrmode : 3;  // Of type CV_ptrmode.
    uint32_t isflat32 : 1;
    uint32_t isvolatile : 1;
    uint32_t isconst : 1;
    uint32_t isunaligned : 1;
    uint32_t isrestrict : 1;
    uint32_t reserved : 19;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 4 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(LeafPointerAttribute, 4);

// This structure represent a bitfield for a leaf modifier attribute.
union LeafModifierAttribute {
  uint16_t raw;
  struct {
    uint16_t mod_const : 1;
    uint16_t mod_volatile : 1;
    uint16_t mod_unaligned : 1;
    uint16_t reserved : 13;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(LeafModifierAttribute, 2);

// This defines flags used in compiland details. See COMPILANDSYM_FLAGS for
// detail.
union CompileSymFlags {
  uint32_t raw;
  struct {
    // Language index. See CV_CFL_LANG.
    uint16_t iLanguage : 8;
    // Compiled with edit and continue support.
    uint16_t fEC : 1;
    // Not compiled with debug info.
    uint16_t fNoDbgInfo : 1;
    // Compiled with LTCG.
    uint16_t fLTCG : 1;
    // Compiled with -Bzalign.
    uint16_t fNoDataAlign : 1;
    // Managed code/data present.
    uint16_t fManagedPresent : 1;
    // Compiled with /GS.
    uint16_t fSecurityChecks : 1;
    // Compiled with /hotpatch.
    uint16_t fHotPatch : 1;
    // Converted with CVTCIL.
    uint16_t fCVTCIL : 1;
    // MSIL netmodule
    uint16_t fMSILModule : 1;
    uint16_t reserved : 15;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 4 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(CompileSymFlags, 4);

// Altough S_FRAMECOOKIE is supposed to use the cvinfo FrameCookie struct, in
// practice we observe a different struct.
struct FrameCookieSym {
  uint32_t off;
  uint16_t reg;
  uint16_t cookietype;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(FrameCookieSym, 8);

// This is a new compiland details symbol type seen in MSVS 2010 and later.
struct CompileSym2 {
  // uint16_t reclen;  // Record length.
  // uint16_t rectyp;  // S_COMPILE3.
  CompileSymFlags flags;
  // Target processor. See CV_CPU_TYPE_e enum.
  uint16_t machine;
  // Front-end major version number.
  uint16_t verFEMajor;
  // Front-end minor version number.
  uint16_t verFEMinor;
  // Front-end build version number.
  uint16_t verFEBuild;
  // Front-end revision number.
  uint16_t verFERevision;
  // Back-end major version number.
  uint16_t verMajor;
  // Back-end minor version number.
  uint16_t verMinor;
  // Back-end build version number.
  uint16_t verBuild;
  // Back-end revision number.
  uint16_t verRevision;
  // Zero-terminated compiler version string. This is followed by zero or more
  // zero-terminated strings 'verArgs'. The whole list is terminated by an
  // empty verArg string (a double-zero).
  char verSt[1];
};
COMPILE_ASSERT_IS_POD_OF_SIZE(CompileSym2, 23);

// This is a new compiland details symbol type seen in MSVS 2010 and later.
struct MSToolEnvV3 {
  // uint16_t reclen;  // Record length.
  // uint16_t rectyp;  // S_MSTOOLENV_V3.
  char leading_zero;
  // An array of key-value pairs, encoded as null terminated strings.
  char key_values[1];
};
COMPILE_ASSERT_IS_POD_OF_SIZE(MSToolEnvV3, 2);

// Length prefixed string.
struct LPString {
  uint8_t length;
  uint8_t string[1];
};
COMPILE_ASSERT_IS_POD_OF_SIZE(LPString, 2);

// Symbols seen in CodeView2 symbol streams.
struct CompileSymCV2 {
  // Machine type. See CV_CPU_TYPE_e enum.
  uint8_t machine;
  union {
    // Raw flags.
    uint8_t flags[3];
    // Parsed flags.
    struct {
      // Language index. See CV_CFL_LANG.
      uint8_t language : 8;
      uint8_t pcode_present : 1;
      // 0: ???
      // 1: ANSI C floating point rules.
      // 2-3: Reserved.
      uint8_t float_precision : 2;
      // 0: Hardware processor.
      // 1: Emulator.
      // 2: Altmath.
      // 3: Reserved.
      uint8_t float_package : 2;
      // 0: Near.
      // 1: Far.
      // 2: Huge.
      // 3-7: Reserved.
      uint8_t ambient_data : 3;
      uint8_t ambient_code : 3;
      // Compiled for 32-bit addresses.
      uint8_t mode32 : 1;
      uint8_t reserved : 4;
    };
  };
  // Length-prefixed version string.
  LPString version;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(CompileSymCV2, 6);

// This defines flags used for local variables. See CV_LVARFLAGS for detail.
union LocalVarFlags {
  uint16_t raw;
  struct {
    uint16_t fIsParam : 1;
    uint16_t fAddrTaken : 1;
    uint16_t fCompGenx : 1;
    uint16_t fIsAggregate : 1;
    uint16_t fIsAggregated : 1;
    uint16_t fIsAliased : 1;
    uint16_t fIsAlias : 1;
    uint16_t fIsRetValue : 1;      // represents a function return value
    uint16_t fIsOptimizedOut : 1;  // variable has no lifetimes
    uint16_t fIsEnregGlob : 1;     // variable is an enregistered global
    uint16_t fIsEnregStat : 1;     // variable is an enregistered static
    uint16_t reserved : 5;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(LocalVarFlags, 2);

// New symbol used for local symbols.
struct LocalSym2013 {
  uint32_t typind;        // (type index) type index
  LocalVarFlags flags;  // local var flags
  uint8_t name[1];        // Name of this symbol.
};
COMPILE_ASSERT_IS_POD_OF_SIZE(LocalSym2013, 7);

// Frame pointer offset for LocalSym2013 variable.
struct FPOffs2013 {
  int offs;
};
COMPILE_ASSERT_IS_POD_OF_SIZE(FPOffs2013, 4);

// Range for symbol address as register + offset.
struct DefRangeSymRegisterRel {
  uint16_t baseReg;  // Register to hold the base pointer of the symbol.
  uint16_t spilledUdtMember : 1;  // Spilled member for s.i.
  uint16_t padding : 3;           // Padding for future use.
  uint16_t offsetParent : 12;     // Offset in parent variable.
  int32_t offBasePointer;        // Offset to register.
  CvLvarAddrRange range;  // Range of addresses where this program is valid.
  CvLvarAddrGap gaps[1];  // The value is not available in following gaps.
};
COMPILE_ASSERT_IS_POD_OF_SIZE(DefRangeSymRegisterRel, 20);

// Defines flags used for export symbols, see EXPORTSYM_FLAGS.
union ExportVarFlags {
  uint16_t raw;
  struct {
    uint16_t fConstant : 1;
    uint16_t fData : 1;
    uint16_t fPrivate : 1;
    uint16_t fNoName : 1;
    uint16_t fOrdinal : 1;
    uint16_t fForwarder : 1;
    uint16_t reserved : 10;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(ExportVarFlags, 2);

// Defines flags used for fram proc symbols, see FRAMEPROCSYM_FLAGS.
union FrameProcSymFlags {
  uint16_t raw;
  struct {
    uint16_t fHasAlloca : 1;
    uint16_t fHasSetJmp : 1;
    uint16_t fHasLongJmp : 1;
    uint16_t fHasInlAsm : 1;
    uint16_t fHasEH : 1;
    uint16_t fInlSpec : 1;
    uint16_t fHasSEH : 1;
    uint16_t fNaked : 1;
    uint16_t fSecurityChecks : 1;
    uint16_t fAsyncEH : 1;
    uint16_t fGSNoStackOrdering : 1;
    uint16_t fWasInlined : 1;
    uint16_t reserved : 4;
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(FrameProcSymFlags, 2);

#pragma pack(pop)

#endif  // SYZYGY_PE_CVINFO_EXT_H_
