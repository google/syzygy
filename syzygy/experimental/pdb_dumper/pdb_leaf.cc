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

#include "syzygy/experimental/pdb_dumper/pdb_leaf.h"

#include <string>

#include "base/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/cvinfo_ext.h"

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
    LEAF_CASE_TABLE(LEAF_TYPE_NAME)
#undef LEAF_TYPE_NAME
    default :
      return NULL;
  }
}

// Return the string value associated with a special type.
const char* SpecialTypeName(uint32 special_type) {
  switch (special_type) {
// Just return the name of the enum.
#define SPECIAL_TYPE_NAME(record_type) \
    case cci::record_type: { \
      return #record_type; \
    }
    SPECIAL_TYPE_CASE_TABLE(SPECIAL_TYPE_NAME)
#undef SPECIAL_TYPE_NAME
    default :
      return NULL;
  }
}

// Dump the name associated with an index type field in a leaf.
bool DumpTypeIndexName(uint32 type_value,
                       const TypeInfoRecordMap& type_map,
                       FILE* out,
                       uint8 indent_level) {
  const char* special_type_name = SpecialTypeName(type_value);
  if (special_type_name != NULL) {
    ::fprintf(out, "%s\n", special_type_name);
  } else {
    // If the special type name is null it means that we refer to another type
    // info record.
    if (type_value >= cci::CV_PRIMITIVE_TYPE::CV_FIRST_NONPRIM &&
        type_map.find(type_value) != type_map.end()) {
      ::fprintf(out, "reference to another type info.\n");
    } else {
      LOG(ERROR) << "reference to an unknown type index: "
                 << base::StringPrintf("0x%08X.", type_value);
      return false;
    }
  }
  return true;
}

// Dump a reference to another type index.
bool DumpTypeIndexField(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        const char* field_name,
                        uint32 field_value,
                        uint8 indent_level) {
  DumpIndentedText(out, indent_level, "%s: 0x%08X, ", field_name, field_value);
  return DumpTypeIndexName(field_value, type_map, out, indent_level);
}

// Dump the "byte data[1]" field present in different leaf structures. The first
// word of this field indicate its structure.
bool DumpLeafDataField(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint8 indent_level) {
  uint16 enum_data_type = 0;
  if (!stream->Read(&enum_data_type, 1)) {
    LOG(ERROR) << "Unable to read the type of the data of an enum leaf.";
    return false;
  }
  // If the value of the data type is less than LF_NUMERIC , then the value data
  // is just the value of that type.
  if (enum_data_type < cci::LF_NUMERIC) {
    DumpIndentedText(out, indent_level, "Value: %d\n", enum_data_type);
    return true;
  }
  const char* value_type_name = NumericLeafName(enum_data_type);
  if (value_type_name == NULL) {
    if (type_map.find(enum_data_type) != type_map.end()) {
      DumpIndentedText(out, indent_level, "Reference to another type info.\n");
    } else {
      LOG(ERROR) << "Invalid leaf type reference: " << enum_data_type;
      return false;
    }
  } else {
    DumpIndentedText(out, indent_level, "Value type: %s, value: ",
                     value_type_name);
    DumpNumericLeaf(out, enum_data_type, stream);
    ::fprintf(out, "\n");
  }
  return true;
}

// Dump a member attribute field.
void DumpMemberAttributeField(FILE* out,
                              LeafMemberAttributeField attribute,
                              uint8 indent_level) {
  // Dump the access attributes.
  DumpIndentedText(out, indent_level, "Access attribute:\n");
  switch (attribute.access) {
    case LeafMemberAttributeField::no_access_protection:
      DumpIndentedText(out, indent_level + 1, "no access protection\n");
      break;
    case LeafMemberAttributeField::private_access:
      DumpIndentedText(out, indent_level + 1, "private\n");
      break;
    case LeafMemberAttributeField::protected_access:
      DumpIndentedText(out, indent_level + 1, "protected\n");
      break;
    case LeafMemberAttributeField::public_access:
      DumpIndentedText(out, indent_level + 1, "public\n");
      break;
    default:
      LOG(ERROR) << "Unexpected member attribute access protection for a leaf ("
                 << attribute.access << ").";
      return;
  }

  // Dump the properties attributes.
  DumpIndentedText(out, indent_level, "Property attributes:\n");
  switch (attribute.mprop) {
    case cci::CV_MTvanilla:
      DumpIndentedText(out, indent_level + 1, "vanilla method\n");
      break;
    case cci::CV_MTvirtual:
      DumpIndentedText(out, indent_level + 1, "virtual method\n");
      break;
    case cci::CV_MTstatic:
      DumpIndentedText(out, indent_level + 1, "static method\n");
      break;
    case cci::CV_MTfriend:
      DumpIndentedText(out, indent_level + 1, "friend method\n");
      break;
    case cci::CV_MTintro:
      DumpIndentedText(out, indent_level + 1, "Introducing virtual method\n");
      break;
    case cci::CV_MTpurevirt:
      DumpIndentedText(out, indent_level + 1, "pure virtual method\n");
      break;
    case cci::CV_MTpureintro:
      DumpIndentedText(out, indent_level + 1,
                       "Pure introducing virtual method\n");
      break;
    default:
      LOG(ERROR) << "Unexpected member attribute property for a leaf ("
                 << attribute.mprop << ").";
      return;
  }

  // Dump the other attributes.
  if (attribute.pseudo != 0) {
    DumpIndentedText(out, indent_level,
                     "Compiler generated function and does not exist.\n");
  }
  if (attribute.noinherit != 0) {
    DumpIndentedText(out, indent_level, "Class cannot be inherited.\n");
  }
  if (attribute.noconstruct != 0) {
    DumpIndentedText(out, indent_level, "Class cannot be constructed.\n");
  }
  if (attribute.compgenx != 0) {
    DumpIndentedText(out, indent_level,
                     "Compiler generated function and does exist.\n");
  }
}

// Dump a field property (matching a cci::CV_prop enum value).
void DumpFieldProperty(FILE* out,
                       LeafPropertyField field_property,
                       uint8 indent_level) {
  if (field_property.raw == 0)
    return;
  DumpIndentedText(out, indent_level, "Property:\n");
  if (field_property.packed != 0) {
    DumpIndentedText(out, indent_level + 1, "Packed.\n");
  }
  if (field_property.ctor != 0) {
    DumpIndentedText(out, indent_level + 1,
                     "Constructors or destructors present.\n");
  }
  if (field_property.ovlops != 0) {
    DumpIndentedText(out, indent_level + 1, "Overloaded operators present.\n");
  }
  if (field_property.isnested != 0) {
    DumpIndentedText(out, indent_level + 1, "This is a nested class.\n");
  }
  if (field_property.cnested != 0) {
    DumpIndentedText(out, indent_level + 1,
                     "This class contains nested types.\n");
  }
  if (field_property.opassign != 0) {
    DumpIndentedText(out, indent_level + 1, "Overloaded assignment (=).\n");
  }
  if (field_property.opcast != 0) {
    DumpIndentedText(out, indent_level + 1, "Casting methods.\n");
  }
  if (field_property.fwdref != 0) {
    DumpIndentedText(out, indent_level + 1, "Forward reference.\n");
  }
  if (field_property.scoped != 0) {
    DumpIndentedText(out, indent_level + 1, "Scoped definition.\n");
  }
  if (field_property.reserved != 0) {
    // There are some bits in the reserved section which are sometimes set to 1
    // and sometimes set to 0. If we modify these bits and try to dump the flags
    // for a symbol in the DIA dumper nothing changes. We should keep an eye on
    // those flags to make sure that they're useless.
    DumpIndentedText(out, indent_level + 1, "Unknown property field: 0x%02X\n",
                     field_property.reserved);
  }
}

// Dump a field property (matching a cci::CV_prop enum value).
void DumpModifierAttribute(FILE* out,
                           LeafModifierAttribute attribute,
                           uint8 indent_level) {
  if (attribute.raw == 0)
    return;
  DumpIndentedText(out, indent_level, "Modifier attribute:\n");
  if (attribute.mod_const) {
    DumpIndentedText(out, indent_level + 1, "const\n");
  }
  if (attribute.mod_volatile) {
    DumpIndentedText(out, indent_level + 1, "volatile\n");
  }
  if (attribute.mod_unaligned) {
    DumpIndentedText(out, indent_level + 1, "unaligned\n");
  }
}

bool DumpLeafVTShape(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafCobol1(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafLabel(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEndPreComp(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len,
                        uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafList(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafRefSym(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafModifier(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  cci::LeafModifier type_info = {};
  LeafModifierAttribute modifier_attributes = {};
  size_t to_read = offsetof(cci::LeafModifier, attr);
  size_t bytes_read = 0;
  if (!stream->ReadBytes(&type_info, to_read, &bytes_read) ||
      !stream->Read(&modifier_attributes, 1) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Modifier type index", type_info.type,
                          indent_level)) {
    return false;
  }
  DumpModifierAttribute(out, modifier_attributes, indent_level);
  return true;
}

bool DumpLeafPointer(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMFunc(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  cci::LeafMFunc type_info = {};
  if (!stream->Read(&type_info, 1)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpTypeIndexField(type_map, out, "Type index of return value",
                     type_info.rvtype, indent_level);
  DumpTypeIndexField(type_map, out, "Type index of containing class",
                     type_info.classtype, indent_level);
  DumpTypeIndexField(type_map, out, "Type index of this pointer",
                     type_info.thisadjust, indent_level);
  DumpIndentedText(out, indent_level, "Calling convention: 0x%02X\n",
                   type_info.calltype);
  DumpIndentedText(out, indent_level, "Number of parameters: %d\n",
                   type_info.parmcount);
  DumpTypeIndexField(type_map, out, "Type index of argument list",
                     type_info.arglist, indent_level);
  DumpIndentedText(out, indent_level, "Adjuster: %d\n", type_info.thisadjust);
  return true;
}

bool DumpLeafCobol0(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBArray(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFTPath(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOEM(const TypeInfoRecordMap& type_map,
                 FILE* out,
                 PdbStream* stream,
                 uint16 len,
                 uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOEM2(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafSkip(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafArgList(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  return false;
}

bool DumpLeafFieldList(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 indent_level) {
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
                  indent_level)) {
      return false;
    }
    stream->Seek(common::AlignUp(stream->pos(), 4));
  }

  return true;
}

bool DumpLeafDerived(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBitfield(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMethodList(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len,
                        uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDimCon(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDimVar(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBClass(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVBClass(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafIndex(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFuncTab(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFuncOff(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafTypeServer(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len,
                        uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEnumerate(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 indent_level) {
  cci::LeafEnumerate type_info = {};
  if (!stream->Read(&type_info.attr, 1)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  LeafMemberAttributeField member_attributes = { type_info.attr };
  DumpMemberAttributeField(out, member_attributes, indent_level);
  DumpLeafDataField(type_map, out, stream, indent_level);
  std::string leaf_name;
  if (!ReadString(stream, &leaf_name)) {
    LOG(ERROR) << "Unable to read the name of an enum leaf.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Name: %s\n", leaf_name.c_str());
  return true;
}

bool DumpLeafArray(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafClass(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  cci::LeafClass type_info = {};
  size_t to_read = offsetof(cci::LeafClass, data);
  size_t bytes_read = 0;
  if (!stream->ReadBytes(&type_info, to_read, &bytes_read) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Number of elements in class: %d\n",
                   type_info.count);
  LeafPropertyField property_field = {type_info.property};
  DumpFieldProperty(out, property_field, indent_level);
  if (!DumpTypeIndexField(type_map, out, "Type index of field descriptor",
      type_info.field, indent_level)) {
    return false;
  }
  if (type_info.derived != 0 &&
      !DumpTypeIndexField(type_map, out,
                          "Type index of derived from",
                          type_info.derived, indent_level)) {
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of vshape table",
      type_info.vshape, indent_level)) {
    return false;
  }
  DumpLeafDataField(type_map, out, stream, indent_level);
  std::string leaf_name;
  if (!ReadString(stream, &leaf_name)) {
    LOG(ERROR) << "Unable to read the name of a class leaf.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Name: %s\n", leaf_name.c_str());
  if (property_field.decorated_name_present != 0) {
    std::string leaf_name_decorated;
    if (!ReadString(stream, &leaf_name_decorated)) {
      LOG(ERROR) << "Unable to read the decorated name of a class leaf ("
                 << "undecorated name: " << leaf_name.c_str() << ").";
      return false;
    }
    DumpIndentedText(out, indent_level, "Decorated name: %s\n",
                     leaf_name_decorated.c_str());
  }
  return true;
}

bool DumpLeafUnion(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEnum(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 indent_level) {
  cci::LeafEnum type_info = {};
  size_t to_read = offsetof(cci::LeafEnum, name);
  size_t bytes_read = 0;
  std::string enum_name;
  if (!stream->ReadBytes(&type_info, to_read, &bytes_read) ||
      !ReadString(stream, &enum_name) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Number of elements in class: %d\n",
                   type_info.count);
  LeafPropertyField property_field = {type_info.property};
  DumpFieldProperty(out, property_field, indent_level);
  if (!DumpTypeIndexField(type_map, out, "Underlying type",
      type_info.utype, indent_level)) {
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of field descriptor",
      type_info.field, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Enum name: %s\n", enum_name.c_str());

  if (property_field.decorated_name_present != 0) {
    std::string enum_name_decorated;
    if (!ReadString(stream, &enum_name_decorated)) {
      LOG(ERROR) << "Unable to read the decorated name of an enum (undecorated "
                 << "name: " << enum_name.c_str() << ").";
      return false;
    }
    DumpIndentedText(out, indent_level, "Enum name decorated: %s\n",
                     enum_name_decorated.c_str());
  }
  return true;
}

bool DumpLeafDimArray(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafPreComp(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafAlias(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDefArg(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafFriendFcn(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMember(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  cci::LeafMember type_info = {};
  size_t to_read = offsetof(cci::LeafMember, offset);
  size_t bytes_read = 0;
  if (!stream->ReadBytes(&type_info, to_read, &bytes_read) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  LeafMemberAttributeField member_attributes = { type_info.attr };
  DumpMemberAttributeField(out, member_attributes, indent_level);
  if (!DumpTypeIndexField(type_map, out, "Index of type record for field",
                          type_info.index, indent_level)) {
    return false;
  }
  DumpLeafDataField(type_map, out, stream, indent_level);
  std::string leaf_name;
  if (!ReadString(stream, &leaf_name)) {
    LOG(ERROR) << "Unable to read the name of an enum leaf.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Name: %s\n", leaf_name.c_str());
  return true;
}

bool DumpLeafSTMember(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMethod(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  cci::LeafMethod type_info;
  size_t to_read = offsetof(cci::LeafMember, name);
  size_t bytes_read = 0;
  if (!stream->ReadBytes(&type_info, to_read, &bytes_read) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Number of occurrences", "%d.\n",
                   type_info.count);
  DumpTypeIndexField(type_map, out, "Index to LF_METHODLIST record",
                     type_info.mList, indent_level);
  std::string leaf_name;
  if (!ReadString(stream, &leaf_name)) {
    LOG(ERROR) << "Unable to read the name of a method leaf.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Name: %s\n", leaf_name.c_str());
  return true;
}

bool DumpLeafNestType(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOneMethod(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafNestTypeEx(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        PdbStream* stream,
                        uint16 len,
                        uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMemberModify(const TypeInfoRecordMap& type_map,
                          FILE* out,
                          PdbStream* stream,
                          uint16 len,
                          uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafManaged(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafTypeServer2(const TypeInfoRecordMap& type_map,
                         FILE* out,
                         PdbStream* stream,
                         uint16 len,
                         uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVarString(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafProc(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 indent_level) {
  cci::LeafProc type_info = {};
  if (!stream->Read(&type_info, 1)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Return value type index",
                          type_info.rvtype, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Calling convention: %d\n",
                   type_info.calltype);
  DumpIndentedText(out, indent_level, "Number of parameters: %d\n",
                   type_info.parmcount);
  if (!DumpTypeIndexField(type_map, out, "Argument list type index",
                          type_info.arglist, indent_level)) {
    return false;
  }
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
  // TODO(sebmarchand): Fix the output of this structure.
  ::fprintf(out, "reals: %f-%f, imaginaries: %f-%f",
            numeric_value.val0_real,
            numeric_value.val1_real,
            numeric_value.val0_imag,
            numeric_value.val1_imag);
}

}  // namespace

bool DumpUnknownLeaf(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  DumpIndentedText(out, indent_level, "Unsupported type info. Data:\n");
  return DumpUnknownBlock(out, stream, len, indent_level);
}

size_t NumericLeafSize(uint16 symbol_type) {
  switch (symbol_type) {
#define LEAF_TYPE_SIZE(sym_type, struct_type) \
    case cci::sym_type: { \
      return sizeof(cci::struct_type); \
    }
    NUMERIC_LEAVES_CASE_TABLE(LEAF_TYPE_SIZE)
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
    NUMERIC_LEAVES_CASE_TABLE(LEAF_TYPE_NAME)
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
      NUMERIC_LEAVES_CASE_TABLE(NUMERIC_LEAF_TYPE_DUMP)
#undef NUMERIC_LEAF_TYPE_DUMP
  }
}

// Call the specific function to dump a kind of leaf.
bool DumpLeaf(const TypeInfoRecordMap& type_map,
              uint16 type_value,
              FILE* out,
              PdbStream* stream,
              uint16 len,
              uint8 indent_level) {
  DCHECK(out != NULL);
  DCHECK(stream != NULL);
  const char* leaf_type_text = LeafName(type_value);
  DumpTabs(out, indent_level);
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
                                 indent_level + 1); \
    }
      LEAF_CASE_TABLE(LEAF_TYPE_DUMP)
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
      LOG(ERROR) << "Unsupported leaf type "
                 << base::StringPrintf("0x%04X.", leaf_type);
      return NULL;
    }
    *leaf_size = NumericLeafSize(leaf_type);
  }
  return leaf_name;
}

}  // namespace pdb
