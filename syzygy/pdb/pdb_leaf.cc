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

#include "syzygy/pdb/pdb_leaf.h"

#include "base/stringprintf.h"
#include "syzygy/pdb/cvinfo_ext.h"
#include "syzygy/pdb/pdb_dump_util.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

namespace {

// Return the string value associated with a type info leaf.
const char* LeafName(uint16 leaf_type) {
  switch (leaf_type) {
// Just return the name of the enum.
#define LEAF_TYPE_NAME(record_type, unused) \
    case cci::record_type: { \
      return #record_type; \
    }
    LEAF_CASE_TABLE(LEAF_TYPE_NAME);
#undef LEAF_TYPE_NAME
    default :
      return NULL;
  }
}

// Return the string value associated with a special type.
const char* SpecialTypeName(uint16 special_type) {
  switch (special_type) {
// Just return the name of the enum.
#define SPECIAL_TYPE_NAME(record_type) \
    case cci::record_type: { \
      return #record_type; \
    }
    SPECIAL_TYPE_CASE_TABLE(SPECIAL_TYPE_NAME);
#undef SPECIAL_TYPE_NAME
    default :
      return NULL;
  }
}

// Dump the name associated with a index type field in a leaf.
bool DumpTypeIndexName(uint16 type_value,
                       const TypeInfoRecordMap& type_map,
                       FILE* out,
                       uint8 level_of_indent) {
  const char* special_type_name = SpecialTypeName(type_value);
  if (special_type_name != NULL) {
    ::fprintf(out, "%s.\n", special_type_name);
  } else {
    // If the special type name is null it means that we refer to another type
    // info record.
    if (type_value >= cci::CV_PRIMITIVE_TYPE::CV_FIRST_NONPRIM &&
        type_map.find(type_value) != type_map.end()) {
      ::fprintf(out, "Reference to another type info.\n");
    } else {
      LOG(ERROR) << "Reference to an unknown type index: "
                 << StringPrintf("0x%04X.", type_value) << ".\n";
      return false;
    }
  }
  return true;
}

bool DumpLeafVTShape(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafCobol1(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafLabel(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEndPreComp(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len,
                        uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafList(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafRefSym(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafModifier(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 level_of_indent) {
  cci::LeafModifier type_info = {};
  uint16 modifier_attributes;
  // We need to read the attribute field separately because if we read it
  // directly (by reading the struct) we'll read it as a 32-bit field (it's an
  // enum) but it's in fact a 16-bits value and the following data is just
  // padding.
  size_t to_read = offsetof(cci::LeafModifier, attr);
  size_t bytes_read = 0;
  if (!stream->ReadBytes(&type_info, to_read, &bytes_read) ||
      !stream->Read(&modifier_attributes, 1) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpTabs(out, level_of_indent);
  ::fprintf(out, "Modifier type index : 0x%08X, ", type_info.type);
  if (!DumpTypeIndexName(type_info.type, type_map, out, level_of_indent))
    return false;
  DumpTabs(out, level_of_indent);
  switch (modifier_attributes) {
    case cci::MOD_const:
      ::fprintf(out, "Modifier attribute: const\n");
      break;
    case cci::MOD_volatile:
      ::fprintf(out, "Modifier attribute: volatile\n");
      break;
    case cci::MOD_unaligned:
      ::fprintf(out, "Modifier attribute: unaligned\n");
      break;
    default:
      ::fprintf(out, "Undefined modifier attribute: 0x%04X\n",
                modifier_attributes);
      break;
  }
  return true;
}

bool DumpLeafPointer(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMFunc(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafCobol0(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBArray(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFTPath(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOEM(const TypeInfoRecordMap& type_map,
                 FILE* out,
                 PdbStream* stream,
                 uint16 len,
                 uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOEM2(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafSkip(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafArgList(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafFieldList(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 level_of_indent) {
  size_t leaf_end = stream->pos() + len;
  while (stream->pos() < leaf_end) {
    uint16 leaf_type = 0;
    if (!stream->Read(&leaf_type, 1)) {
      LOG(ERROR) << "Unable to read the type of a list field.";
      return false;
    }
    if (!DumpLeaf(type_map,
                  leaf_type,
                  out,
                  stream,
                  leaf_end - stream->pos(),
                  level_of_indent)) {
      return false;
    }
  }

  return true;
}

bool DumpLeafDerived(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBitfield(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMethodList(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len,
                        uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDimCon(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDimVar(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBClass(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVBClass(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafIndex(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFuncTab(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFuncOff(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafTypeServer(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len,
                        uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEnumerate(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 level_of_indent) {
  cci::LeafEnumerate type_info = {};
  if (!stream->Read(&type_info.attr, 1)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpTabs(out, level_of_indent);
  ::fprintf(out, "Attribute : 0x%04X\n", type_info.attr);
  uint16 enum_data_type = 0;
  if (!stream->Read(&enum_data_type, 1)) {
    LOG(ERROR) << "Unable to read the type of the data of an enum leaf.";
    return false;
  }
  // If the value of the data type is less than LF_NUMERIC, then the value data
  // is just the value of that type.
  if (enum_data_type < cci::CV_PRIMITIVE_TYPE::CV_FIRST_NONPRIM) {
    DumpTabs(out, level_of_indent);
    ::fprintf(out, "Value: %d\n", enum_data_type);
  } else {
    const char* value_type_name = NumericLeafName(enum_data_type);
    DumpTabs(out, level_of_indent);
    ::fprintf(out, "Value: type=%s, value=", value_type_name);
    DumpNumericLeaf(out, enum_data_type, stream);
    ::fprintf(out, "\n");
  }
  std::string leaf_name;
  if (!ReadString(stream, &leaf_name)) {
    LOG(ERROR) << "Unable to read the name of an enum leaf.";
    return false;
  }
  DumpTabs(out, level_of_indent);
  ::fprintf(out, "Name : %s\n", leaf_name.c_str());
  return true;
}

bool DumpLeafArray(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafClass(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafUnion(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEnum(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDimArray(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafPreComp(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafAlias(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDefArg(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafFriendFcn(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMember(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafSTMember(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMethod(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafNestType(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOneMethod(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafNestTypeEx(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len,
                        uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMemberModify(const TypeInfoRecordMap& type_map,
                          FILE* out,
                          PdbStream* stream,
                          uint16 len,
                          uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafManaged(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafTypeServer2(const TypeInfoRecordMap& type_map,
                         FILE* out,
                         PdbStream* stream,
                         uint16 len,
                         uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVarString(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 level_of_indent) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafProc(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 level_of_indent) {
  cci::LeafProc type_info = {};
  if (!stream->Read(&type_info, 1)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpTabs(out, level_of_indent);
  ::fprintf(out, "Return value type index : 0x%08X, ", type_info.rvtype);
  if (!DumpTypeIndexName(type_info.rvtype, type_map, out, level_of_indent))
    return false;
  DumpTabs(out, level_of_indent);
  ::fprintf(out, "Calling convention: %d\n", type_info.calltype);
  DumpTabs(out, level_of_indent);
  ::fprintf(out, "Number of parameters: %d\n", type_info.parmcount);
  DumpTabs(out, level_of_indent);
  ::fprintf(out, "Argument list type index: 0x%08X, ", type_info.arglist);
  if (!DumpTypeIndexName(type_info.arglist, type_map, out, level_of_indent))
    return false;
  return true;
}

// These function allows to display a particular kind of numeric value in the
// out stream.

void DumpFLOAT10(FILE* out, cci::FLOAT10 float10) {
  fprintf(out, "%d", float10.Data_0);
  fprintf(out, "%d", float10.Data_1);
  fprintf(out, "%d", float10.Data_2);
  fprintf(out, "%d", float10.Data_3);
  fprintf(out, "%d", float10.Data_4);
  fprintf(out, "%d", float10.Data_5);
  fprintf(out, "%d", float10.Data_6);
  fprintf(out, "%d", float10.Data_7);
  fprintf(out, "%d", float10.Data_8);
  fprintf(out, "%d", float10.Data_9);
}

void DumpLeafChar(FILE* out, PdbStream* stream) {
  cci::LeafChar numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafShort(FILE* out, PdbStream* stream) {
  cci::LeafShort numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafUShort(FILE* out, PdbStream* stream) {
  cci::LeafUShort numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafLong(FILE* out, PdbStream* stream) {
  cci::LeafLong numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafULong(FILE* out, PdbStream* stream) {
  cci::LeafULong numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

// In the tests used to validate these function I've added a const double to my
// test program to make sure that it is saved as a LeafReal64 in the PDB (I've
// initialized it to Pi to make sure it is not implicitly converted to an
// integer) but the type associated with its value is LF_ULONG. I've verified in
// the PDB to make sure this is not an error in my code and this is really the
// type present for this value (0x8004). This is also the case for the float
// type. It may be related to the type index. For each symbol there is a field
// for the value (and the type associated with it if it's a numeric type) and a
// field called "type index" which seems to refer to a type present in the type
// info stream. An error is logged if we encounter a LeafReal type for one
// symbol.

const char* unexpected_real_type = "This type is unexpected.";

void DumpLeafReal32(FILE* out, PdbStream* stream) {
  LOG(WARNING) << unexpected_real_type;
  cci::LeafReal32 numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%f", numeric_value.val);
}

void DumpLeafReal64(FILE* out, PdbStream* stream) {
  LOG(WARNING) << unexpected_real_type;
  cci::LeafReal64 numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%f", numeric_value.val);
}

void DumpLeafReal80(FILE* out, PdbStream* stream) {
  LOG(WARNING) << unexpected_real_type;
  cci::LeafReal80 numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  DumpFLOAT10(out, numeric_value.val);
}

void DumpLeafReal128(FILE* out, PdbStream* stream) {
  LOG(WARNING) << unexpected_real_type;
  cci::LeafReal128 numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d%d", numeric_value.val0, numeric_value.val1);
}

void DumpLeafQuad(FILE* out, PdbStream* stream) {
  cci::LeafQuad numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafUQuad(FILE* out, PdbStream* stream) {
  cci::LeafUQuad numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafCmplx32(FILE* out, PdbStream* stream) {
  cci::LeafCmplx32 numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "real: %f, imaginary: %f", numeric_value.val_real,
            numeric_value.val_imag);
}

void DumpLeafCmplx64(FILE* out, PdbStream* stream) {
  cci::LeafCmplx64 numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "real: %f, imaginary: %f", numeric_value.val_real,
            numeric_value.val_imag);
}

void DumpLeafCmplx80(FILE* out, PdbStream* stream) {
  cci::LeafCmplx80 numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "real: ");
  DumpFLOAT10(out, numeric_value.val_real);
  ::fprintf(out, ", imaginary: ");
  DumpFLOAT10(out, numeric_value.val_imag);
}

void DumpLeafCmplx128(FILE* out, PdbStream* stream) {
  cci::LeafCmplx128 numeric_value = {};
  if (!stream->Read(&numeric_value, 1)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "real: %f, imaginary: %f",
            numeric_value.val0_real,
            numeric_value.val1_real,
            numeric_value.val0_imag,
            numeric_value.val0_imag);
}

}  // namespace

bool DumpUnknownLeaf(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 level_of_indent) {
  DumpTabs(out, level_of_indent);
  ::fprintf(out, "Unsupported type info. Data:\n");
  return DumpUnknownBlock(out, stream, len, level_of_indent);
}

size_t NumericLeafSize(uint16 symbol_type) {
  switch (symbol_type) {
#define LEAF_TYPE_SIZE(sym_type, struct_type) \
    case cci::sym_type: { \
      return sizeof(cci::struct_type); \
    }
    NUMERIC_LEAVES_CASE_TABLE(LEAF_TYPE_SIZE);
#undef LEAF_TYPE_SIZE
    default:
      return 0;
  }
}

const char* NumericLeafName(uint16 leaf_type) {
  switch (leaf_type) {
// Just return the name of the leaf type.
#define LEAF_TYPE_NAME(leaf_type, unused) \
    case cci::leaf_type: { \
      return #leaf_type; \
    }
    NUMERIC_LEAVES_CASE_TABLE(LEAF_TYPE_NAME);
#undef LEAF_TYPE_NAME
    default:
      return NULL;
  }
}

void DumpNumericLeaf(FILE* out, uint16 leaf_type, PdbStream* stream) {
  switch (leaf_type) {
// Call a function to dump a specific (value_type) kind of numeric value.
#define NUMERIC_LEAF_TYPE_DUMP(leaf_type, struct_type) \
    case cci::leaf_type: { \
      Dump ## struct_type(out, stream); \
      break; \
    }
      NUMERIC_LEAVES_CASE_TABLE(NUMERIC_LEAF_TYPE_DUMP);
#undef NUMERIC_LEAF_TYPE_DUMP
  }
}

// Call the specific function to dump a kind of leaf.
bool DumpLeaf(const TypeInfoRecordMap& type_map,
              uint16 type_value,
              FILE* out,
              PdbStream* stream,
              uint16 len,
              uint8 level_of_indent) {
  DCHECK(out != NULL);
  DCHECK(stream != NULL);
  const char* leaf_type_text = LeafName(type_value);
  DumpTabs(out, level_of_indent);
  if (leaf_type_text != NULL) {
    ::fprintf(out, "Leaf type: 0x%04X %s\n",
              type_value,
              leaf_type_text);
  } else {
    ::fprintf(out, "Unknown leaf type: 0x%04X\n",
              type_value);
  }
  switch (type_value) {
// Call a function to dump a specific (struct_type) kind of structure.
#define LEAF_TYPE_DUMP(type_value, struct_type) \
    case cci::type_value: { \
      return Dump ## struct_type(type_map, \
                                 out, \
                                 stream, \
                                 len, \
                                 level_of_indent + 1); \
      break; \
    }
      LEAF_CASE_TABLE(LEAF_TYPE_DUMP);
#undef LEAF_TYPE_DUMP
    default:
      return false;
  }
}

// Get the name and the size associated with a numeric leaf.
// Return NULL if the leaf is not of a numeric type.
const char* GetNumericLeafNameAndSize(uint16 leaf_type, size_t* leaf_size) {
  const char* leaf_name = NULL;
  if (leaf_type >= cci::LF_NUMERIC) {
    leaf_name = NumericLeafName(leaf_type);
    if (leaf_name == NULL) {
      LOG(ERROR) << "Unsupported leaf type " << StringPrintf("0x%04X.",
                                                             leaf_type);
      return false;
    }
    *leaf_size = NumericLeafSize(leaf_type);
  }
  return leaf_name;
}

}  // namespace pdb
