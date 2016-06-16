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

#include "base/strings/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/common/buffer_parser.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/pdb/gen/pdb_type_info_records.h"
#include "syzygy/pdb/pdb_stream.h"
#include "syzygy/pdb/pdb_stream_reader.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/cvinfo_ext.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

namespace {

// Return the string value associated with a type info leaf.
const char* LeafName(uint16_t leaf_type) {
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
const char* SpecialTypeName(uint32_t special_type) {
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
bool DumpTypeIndexName(uint32_t type_value,
                       const TypeInfoRecordMap& type_map,
                       FILE* out,
                       uint8_t indent_level) {
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
                 << base::StringPrintf("0x%04X.", type_value);
      return false;
    }
  }
  return true;
}

// Dump a reference to another type index.
bool DumpTypeIndexField(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        const char* field_name,
                        uint32_t field_value,
                        uint8_t indent_level) {
  DumpIndentedText(out, indent_level, "%s: 0x%04X, ", field_name, field_value);
  return DumpTypeIndexName(field_value, type_map, out, indent_level);
}

// Dump a member attribute field.
void DumpMemberAttributeField(FILE* out,
                              LeafMemberAttributeField attribute,
                              uint8_t indent_level) {
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
                       uint8_t indent_level) {
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
                           uint8_t indent_level) {
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
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level) {
  LeafVTShape type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Number of descriptors: %d\n",
                   type_info.body().count);
  uint8_t current_byte = 0;
  const uint8_t kOddMask = 0x0F;
  const uint8_t kEvenMask = 0xF0;
  for (size_t i = 0; i < type_info.body().count; i++) {
    uint8_t vts_desc = 0;

    // VTShape descriptors are only 4 bits long so we read next byte only on an
    // even descriptor.
    if (i % 2 == 0) {
      if (!ReadBasicType(parser, &current_byte))
        return false;
      vts_desc = (current_byte & kEvenMask) >> 4;
    } else {
      vts_desc = current_byte & kOddMask;
    }

    switch (vts_desc) {
      case cci::CV_VTS_near: {
        DumpIndentedText(out, indent_level + 1, "CV_VTS_near\n");
        break;
      }
      case cci::CV_VTS_far: {
        DumpIndentedText(out, indent_level + 1, "CV_VTS_far\n");
        break;
      }
      case cci::CV_VTS_thin: {
        DumpIndentedText(out, indent_level + 1, "CV_VTS_thin\n");
        break;
      }
      case cci::CV_VTS_outer: {
        DumpIndentedText(out, indent_level + 1, "CV_VTS_outer\n");
        break;
      }
      case cci::CV_VTS_meta: {
        DumpIndentedText(out, indent_level + 1, "CV_VTS_meta\n");
        break;
      }
      case cci::CV_VTS_near32: {
        DumpIndentedText(out, indent_level + 1, "CV_VTS_near32\n");
        break;
      }
      case cci::CV_VTS_far32: {
        DumpIndentedText(out, indent_level + 1, "CV_VTS_far32\n");
        break;
      }
      case cci::CV_VTS_unused: {
        DumpIndentedText(out, indent_level + 1, "CV_VTS_unused\n");
        break;
      }
    }
  }
  return true;
}

bool DumpLeafCobol1(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafLabel(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   common::BinaryStreamParser* parser,
                   uint16_t len,
                   uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEndPreComp(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        common::BinaryStreamParser* parser,
                        uint16_t len,
                        uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafList(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  common::BinaryStreamParser* parser,
                  uint16_t len,
                  uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafRefSym(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafModifier(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      common::BinaryStreamParser* parser,
                      uint16_t len,
                      uint8_t indent_level) {
  LeafModifier type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Modifier type index",
                          type_info.body().type, indent_level)) {
    return false;
  }
  DumpModifierAttribute(out, type_info.attr(), indent_level);
  return true;
}

bool DumpLeafPointer(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level) {
  LeafPointer type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }

  DumpTypeIndexField(type_map, out, "Type index of pointer value",
                     type_info.body().utype, indent_level);
  DumpIndentedText(out, indent_level, "Pointer attributes:\n");
  switch (type_info.attr().ptrtype) {
    case cci::CV_PTR_BASE_SEG:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_BASE_SEG\n");
      break;
    case cci::CV_PTR_BASE_VAL:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_BASE_VAL\n");
      break;
    case cci::CV_PTR_BASE_SEGVAL:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_BASE_SEGVAL\n");
      break;
    case cci::CV_PTR_BASE_ADDR:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_BASE_ADDR\n");
      break;
    case cci::CV_PTR_BASE_SEGADDR:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_BASE_SEGADDR\n");
      break;
    case cci::CV_PTR_BASE_TYPE:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_BASE_TYPE\n");
      break;
    case cci::CV_PTR_BASE_SELF:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_BASE_SELF\n");
      break;
    case cci::CV_PTR_NEAR32:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_NEAR32\n");
      break;
    case cci::CV_PTR_64:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_64\n");
      break;
    case cci::CV_PTR_UNUSEDPTR:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_UNUSEDPTR\n");
      break;
  }

  switch (type_info.attr().ptrmode) {
    case cci::CV_PTR_MODE_PTR:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_MODE_PTR\n");
      break;
    case cci::CV_PTR_MODE_REF:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_MODE_REF\n");
      break;
    case cci::CV_PTR_MODE_PMEM:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_MODE_PMEM\n");
      break;
    case cci::CV_PTR_MODE_PMFUNC:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_MODE_PMFUNC\n");
      break;
    case cci::CV_PTR_MODE_RESERVED:
      DumpIndentedText(out, indent_level + 1, "CV_PTR_MODE_RESERVED\n");
      break;
  }

  if (type_info.attr().isflat32)
    DumpIndentedText(out, indent_level + 1, "isflat32\n");
  if (type_info.attr().isvolatile)
    DumpIndentedText(out, indent_level + 1, "isvolatile\n");
  if (type_info.attr().isconst)
    DumpIndentedText(out, indent_level + 1, "isconst\n");
  if (type_info.attr().isunaligned)
    DumpIndentedText(out, indent_level + 1, "isunaligned\n");
  if (type_info.attr().isrestrict)
    DumpIndentedText(out, indent_level + 1, "isrestrict\n");

  if (type_info.has_pmtype()) {
    switch (type_info.pmtype()) {
      case cci::CV_PMTYPE_Undef:
        DumpIndentedText(out, indent_level + 1, "CV_PMTYPE_Undef\n");
        break;
      case cci::CV_PMTYPE_D_Single:
        DumpIndentedText(out, indent_level + 1, "CV_PMTYPE_D_Single\n");
        break;
      case cci::CV_PMTYPE_D_Multiple:
        DumpIndentedText(out, indent_level + 1, "CV_PMTYPE_D_Multiple\n");
        break;
      case cci::CV_PMTYPE_D_Virtual:
        DumpIndentedText(out, indent_level + 1, "CV_PMTYPE_D_Virtual\n");
        break;
      case cci::CV_PMTYPE_D_General:
        DumpIndentedText(out, indent_level + 1, "CV_PMTYPE_D_General\n");
        break;
      case cci::CV_PMTYPE_F_Single:
        DumpIndentedText(out, indent_level + 1, "CV_PMTYPE_F_Single\n");
        break;
      case cci::CV_PMTYPE_F_Multiple:
        DumpIndentedText(out, indent_level + 1, "CV_PMTYPE_F_Multiple\n");
        break;
      case cci::CV_PMTYPE_F_Virtual:
        DumpIndentedText(out, indent_level + 1, "CV_PMTYPE_F_Virtual\n");
        break;
      case cci::CV_PMTYPE_F_General:
        DumpIndentedText(out, indent_level + 1, "CV_PMTYPE_F_General\n");
        break;
    }
  }

  if (type_info.has_containing_class()) {
    DumpTypeIndexField(type_map, out, "Type index of the containing class",
                       type_info.containing_class(), indent_level);
  }

  return true;
}

bool DumpLeafMFunc(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   common::BinaryStreamParser* parser,
                   uint16_t len,
                   uint8_t indent_level) {
  LeafMFunction type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpTypeIndexField(type_map, out, "Type index of return value",
                     type_info.body().rvtype, indent_level);
  DumpTypeIndexField(type_map, out, "Type index of containing class",
                     type_info.body().classtype, indent_level);
  DumpTypeIndexField(type_map, out, "Type index of this pointer",
                     type_info.body().thistype, indent_level);
  DumpIndentedText(out, indent_level, "Calling convention: 0x%02X\n",
                   type_info.body().calltype);
  DumpIndentedText(out, indent_level, "Number of parameters: %d\n",
                   type_info.body().parmcount);
  DumpTypeIndexField(type_map, out, "Type index of argument list",
                     type_info.body().arglist, indent_level);
  DumpIndentedText(out, indent_level, "Adjuster: %d\n",
                   type_info.body().thisadjust);
  return true;
}

bool DumpLeafCobol0(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBArray(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVFTPath(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOEM(const TypeInfoRecordMap& type_map,
                 FILE* out,
                 common::BinaryStreamParser* parser,
                 uint16_t len,
                 uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafOEM2(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  common::BinaryStreamParser* parser,
                  uint16_t len,
                  uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafSkip(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  common::BinaryStreamParser* parser,
                  uint16_t len,
                  uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafArgList(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level) {
  LeafArgList type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Number of arguments: %d\n",
                   type_info.body().count);
  DumpIndentedText(out, indent_level, "Arguments:\n");

  uint32_t arg_type_index = 0;
  while (ReadBasicType(parser, &arg_type_index)) {
    DumpTypeIndexField(type_map, out, "Type index", arg_type_index,
                       indent_level + 1);
  }
  return true;
}

bool DumpLeafFieldList(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       common::BinaryStreamParser* parser,
                       uint16_t len,
                       uint8_t indent_level) {
  common::BinaryStreamReader* reader = parser->stream_reader();
  size_t leaf_end = reader->Position() + len;
  while (reader->Position() < leaf_end) {
    uint16_t leaf_type = 0;
    if (!ReadBasicType(parser, &leaf_type)) {
      LOG(ERROR) << "Unable to read the type of a list field.";
      return false;
    }
    if (!DumpLeaf(type_map, leaf_type, out, parser,
                  leaf_end - reader->Position(), indent_level)) {
      return false;
    }

    // Align the reader to the next 4 byte boundary.
    size_t pos = reader->Position();
    size_t to_discard = common::AlignUp(pos, 4) - pos;
    uint8_t buf[3];
    DCHECK_LE(to_discard, sizeof(buf));
    reader->Read(to_discard, buf);
  }

  return true;
}

bool DumpLeafDerived(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBitfield(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      common::BinaryStreamParser* parser,
                      uint16_t len,
                      uint8_t indent_level) {
  LeafBitfield type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of bitfield",
                          type_info.body().type, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Length in bits: %u\n",
                   type_info.body().length);
  DumpIndentedText(out, indent_level,
                   "Starting position of the object in the word: %u\n",
                   type_info.body().position);
  return true;
}

bool DumpLeafMethodList(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        common::BinaryStreamParser* parser,
                        uint16_t len,
                        uint8_t indent_level) {
  common::BinaryStreamReader* reader = parser->stream_reader();
  size_t leaf_end = reader->Position() + len;
  for (uint16_t count = 1; reader->Position() < leaf_end; count++) {
    MethodListRecord method_record;
    if (!method_record.Initialize(parser)) {
      LOG(ERROR) << "Unable to read type info record.";
      return false;
    }
    DumpIndentedText(out, indent_level, "Method %u:\n", count);
    DumpMemberAttributeField(out, method_record.attr(), indent_level + 1);
    if (!DumpTypeIndexField(type_map, out, "Type index of the function type",
                            method_record.body().index, indent_level + 1)) {
      return false;
    }
    if (method_record.has_vbaseoff()) {
      DumpIndentedText(out, indent_level + 1,
                       "Starting position of the object in the word: %ull\n",
                       method_record.vbaseoff());
    }
  }

  return true;
}

bool DumpLeafDimCon(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDimVar(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafBClass(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  LeafBClass type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpMemberAttributeField(out, type_info.attr(), indent_level);
  if (!DumpTypeIndexField(type_map, out, "Type index of base class",
                          type_info.body().index, indent_level)) {
    return false;
  }

  DumpIndentedText(out, indent_level, "Offset of base: %llu\n",
                   type_info.offset());
  return true;
}

bool DumpLeafVBClass(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level) {
  LeafVBClass type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpMemberAttributeField(out, type_info.attr(), indent_level);
  if (!DumpTypeIndexField(type_map, out, "Type index of virtual base class",
                          type_info.body().index, indent_level)) {
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of virtual base pointer",
                          type_info.body().vbptr, indent_level)) {
    return false;
  }

  DumpIndentedText(out, indent_level, "Virtual base pointer offset: %llu\n",
                   type_info.vbpoff());
  DumpIndentedText(out, indent_level,
                   "Virtual base offset from vbtable: %llu\n",
                   type_info.vboff());
  return true;
}

bool DumpLeafIndex(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   common::BinaryStreamParser* parser,
                   uint16_t len,
                   uint8_t indent_level) {
  LeafIndex type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of fieldlist continuation",
                          type_info.body().index, indent_level)) {
    return false;
  }
  return true;
}

bool DumpLeafVFuncTab(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      common::BinaryStreamParser* parser,
                      uint16_t len,
                      uint8_t indent_level) {
  LeafVFuncTab type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of virtual table pointer",
                          type_info.body().type, indent_level)) {
    return false;
  }
  return true;
}

bool DumpLeafVFuncOff(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      common::BinaryStreamParser* parser,
                      uint16_t len,
                      uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafTypeServer(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        common::BinaryStreamParser* parser,
                        uint16_t len,
                        uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafEnumerate(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       common::BinaryStreamParser* parser,
                       uint16_t len,
                       uint8_t indent_level) {
  LeafEnumerate type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpMemberAttributeField(out, type_info.attr(), indent_level);
  switch (type_info.value().kind()) {
    case NumericConstant::CONSTANT_SIGNED: {
      DumpIndentedText(out, indent_level, "Value: %lld\n",
                       type_info.value().signed_value());
      break;
    }
    case NumericConstant::CONSTANT_UNSIGNED: {
      DumpIndentedText(out, indent_level, "Value: %lld\n",
                       type_info.value().signed_value());
      break;
    }
  }
  DumpIndentedText(out, indent_level, "Name: %ls\n", type_info.name().c_str());
  return true;
}

bool DumpLeafArray(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   common::BinaryStreamParser* parser,
                   uint16_t len,
                   uint8_t indent_level) {
  LeafArray type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of element type",
                          type_info.body().elemtype, indent_level)) {
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of indexing type",
                          type_info.body().idxtype, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Length in bytes: %llu\n",
                   type_info.size());
  return true;
}

bool DumpLeafClass(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   common::BinaryStreamParser* parser,
                   uint16_t len,
                   uint8_t indent_level) {
  LeafClass type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Number of elements in class: %d\n",
                   type_info.body().count);
  DumpFieldProperty(out, type_info.property(), indent_level);
  if (!DumpTypeIndexField(type_map, out, "Type index of field descriptor",
                          type_info.body().field, indent_level)) {
    return false;
  }
  if (type_info.body().derived != 0 &&
      !DumpTypeIndexField(type_map, out, "Type index of derived from",
                          type_info.body().derived, indent_level)) {
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of vshape table",
                          type_info.body().vshape, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Size: %llu\n", type_info.size());
  DumpIndentedText(out, indent_level, "Name: %ls\n", type_info.name().c_str());
  if (type_info.property().decorated_name_present != 0) {
    DumpIndentedText(out, indent_level, "Decorated name: %ls\n",
                     type_info.decorated_name().c_str());
  }
  return true;
}

bool DumpLeafUnion(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   common::BinaryStreamParser* parser,
                   uint16_t len,
                   uint8_t indent_level) {
  LeafUnion type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Number of elements in union: %d\n",
                   type_info.body().count);
  DumpFieldProperty(out, type_info.property(), indent_level);
  if (!DumpTypeIndexField(type_map, out, "Type index of field descriptor",
                          type_info.body().field, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Size: %llu\n", type_info.size());
  DumpIndentedText(out, indent_level, "Name: %ls\n", type_info.name().c_str());
  if (type_info.property().decorated_name_present != 0) {
    DumpIndentedText(out, indent_level, "Decorated name: %ls\n",
                     type_info.decorated_name().c_str());
  }
  return true;
}

bool DumpLeafEnum(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  common::BinaryStreamParser* parser,
                  uint16_t len,
                  uint8_t indent_level) {
  LeafEnum type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Number of elements in class: %d\n",
                   type_info.body().count);
  DumpFieldProperty(out, type_info.property(), indent_level);
  if (!DumpTypeIndexField(type_map, out, "Underlying type",
                          type_info.body().utype, indent_level)) {
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of field descriptor",
                          type_info.body().field, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Enum name: %ls\n",
                   type_info.name().c_str());

  if (type_info.has_decorated_name()) {
    DumpIndentedText(out, indent_level, "Enum name decorated: %sS\n",
                     type_info.decorated_name().c_str());
  }
  return true;
}

bool DumpLeafDimArray(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      common::BinaryStreamParser* parser,
                      uint16_t len,
                      uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafPreComp(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafAlias(const TypeInfoRecordMap& type_map,
                   FILE* out,
                   common::BinaryStreamParser* parser,
                   uint16_t len,
                   uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafDefArg(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafFriendFcn(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       common::BinaryStreamParser* parser,
                       uint16_t len,
                       uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMember(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  LeafMember type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpMemberAttributeField(out, type_info.attr(), indent_level);
  if (!DumpTypeIndexField(type_map, out, "Index of type record for field",
                          type_info.body().index, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Offset of field: %llu\n",
                   type_info.offset());
  DumpIndentedText(out, indent_level, "Name: %ls\n", type_info.name().c_str());
  return true;
}

bool DumpLeafSTMember(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      common::BinaryStreamParser* parser,
                      uint16_t len,
                      uint8_t indent_level) {
  LeafSTMember type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpMemberAttributeField(out, type_info.attr(), indent_level);
  DumpIndentedText(out, indent_level, "Name: %ls\n", type_info.name().c_str());
  return true;
}

bool DumpLeafMethod(const TypeInfoRecordMap& type_map,
                    FILE* out,
                    common::BinaryStreamParser* parser,
                    uint16_t len,
                    uint8_t indent_level) {
  LeafMethod type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Number of occurrences: %d\n",
                   type_info.body().count);
  DumpTypeIndexField(type_map, out, "Index to LF_METHODLIST record",
                     type_info.body().mList, indent_level);
  DumpIndentedText(out, indent_level, "Name: %ls\n", type_info.name().c_str());
  return true;
}

bool DumpLeafNestType(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      common::BinaryStreamParser* parser,
                      uint16_t len,
                      uint8_t indent_level) {
  LeafNestType type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpMemberAttributeField(out, type_info.attr(), indent_level);
  if (!DumpTypeIndexField(type_map, out, "Nested type index",
                          type_info.body().index, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Name: %ls\n", type_info.name().c_str());

  return true;
}

bool DumpLeafOneMethod(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       common::BinaryStreamParser* parser,
                       uint16_t len,
                       uint8_t indent_level) {
  LeafOneMethod type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  DumpMemberAttributeField(out, type_info.attr(), indent_level);
  DumpTypeIndexField(type_map, out, "Type index of function type",
                     type_info.body().index, indent_level);
  if (type_info.has_vbaseoff()) {
    DumpIndentedText(out, indent_level, "Virtual base offset: %llu\n",
                     type_info.vbaseoff());
  }
  DumpIndentedText(out, indent_level, "Name: %ls\n", type_info.name().c_str());
  return true;
}

bool DumpLeafNestTypeEx(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        common::BinaryStreamParser* parser,
                        uint16_t len,
                        uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafMemberModify(const TypeInfoRecordMap& type_map,
                          FILE* out,
                          common::BinaryStreamParser* parser,
                          uint16_t len,
                          uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafManaged(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafTypeServer2(const TypeInfoRecordMap& type_map,
                         FILE* out,
                         common::BinaryStreamParser* parser,
                         uint16_t len,
                         uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafVarString(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       common::BinaryStreamParser* parser,
                       uint16_t len,
                       uint8_t indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this leaf.
  return false;
}

bool DumpLeafProc(const TypeInfoRecordMap& type_map,
                  FILE* out,
                  common::BinaryStreamParser* parser,
                  uint16_t len,
                  uint8_t indent_level) {
  LeafProcedure type_info;
  if (!type_info.Initialize(parser)) {
    LOG(ERROR) << "Unable to read type info record.";
    return false;
  }
  if (!DumpTypeIndexField(type_map, out, "Type index of the return value",
                          type_info.body().rvtype, indent_level)) {
    return false;
  }
  DumpIndentedText(out, indent_level, "Calling convention: %d\n",
                   type_info.body().calltype);
  DumpIndentedText(out, indent_level, "Number of parameters: %d\n",
                   type_info.body().parmcount);
  if (!DumpTypeIndexField(type_map, out, "Argument list type index",
                          type_info.body().arglist, indent_level)) {
    return false;
  }
  return true;
}

// These function allows to display a particular kind of numeric value in the
// out parser.

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

void DumpLeafChar(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafChar numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafShort(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafShort numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafUShort(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafUShort numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafLong(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafLong numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%d", numeric_value.val);
}

void DumpLeafULong(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafULong numeric_value = {};
  if (!parser->Read(&numeric_value)) {
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
// info parser. An error is logged if we encounter a LeafReal type for one
// symbol.

const char* unexpected_real_type = "This type is unexpected.";

void DumpLeafReal32(FILE* out, common::BinaryStreamParser* parser) {
  LOG(WARNING) << unexpected_real_type;
  cci::LeafReal32 numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%f", numeric_value.val);
}

void DumpLeafReal64(FILE* out, common::BinaryStreamParser* parser) {
  LOG(WARNING) << unexpected_real_type;
  cci::LeafReal64 numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%f", numeric_value.val);
}

void DumpLeafReal80(FILE* out, common::BinaryStreamParser* parser) {
  LOG(WARNING) << unexpected_real_type;
  cci::LeafReal80 numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  DumpFLOAT10(out, numeric_value.val);
}

void DumpLeafReal128(FILE* out, common::BinaryStreamParser* parser) {
  LOG(WARNING) << unexpected_real_type;
  cci::LeafReal128 numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%llu%llu", numeric_value.val0, numeric_value.val1);
}

void DumpLeafQuad(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafQuad numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%llu", numeric_value.val);
}

void DumpLeafUQuad(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafUQuad numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "%llu", numeric_value.val);
}

void DumpLeafCmplx32(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafCmplx32 numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "real: %f, imaginary: %f", numeric_value.val_real,
            numeric_value.val_imag);
}

void DumpLeafCmplx64(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafCmplx64 numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "real: %f, imaginary: %f", numeric_value.val_real,
            numeric_value.val_imag);
}

void DumpLeafCmplx80(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafCmplx80 numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  ::fprintf(out, "real: ");
  DumpFLOAT10(out, numeric_value.val_real);
  ::fprintf(out, ", imaginary: ");
  DumpFLOAT10(out, numeric_value.val_imag);
}

void DumpLeafCmplx128(FILE* out, common::BinaryStreamParser* parser) {
  cci::LeafCmplx128 numeric_value = {};
  if (!parser->Read(&numeric_value)) {
    LOG(ERROR) << "Unable to read numeric value.";
    return;
  }
  // TODO(sebmarchand): Fix the output of this structure.
  ::fprintf(out, "reals: %llu-%llu, imaginaries: %llu-%llu",
            numeric_value.val0_real, numeric_value.val1_real,
            numeric_value.val0_imag, numeric_value.val1_imag);
}

// ID parser leaf types.

bool DumpLeafFunctionId(const TypeInfoRecordMap& type_map,
                        FILE* out,
                        common::BinaryStreamParser* parser,
                        uint16_t len,
                        uint8_t indent_level) {
  LeafFunctionId func_id = {};
  if (!parser->ReadBytes(offsetof(LeafFunctionId, name), &func_id))
    return false;
  std::string name;
  if (!parser->ReadString(&name))
    return false;
  DumpIndentedText(out, indent_level, "scopeId: 0x%08x\n", func_id.scopeId);
  DumpIndentedText(out, indent_level, "type: 0x%08x\n", func_id.type);
  DumpIndentedText(out, indent_level, "name: %s\n", name.c_str());
  return true;
}

bool DumpLeafMemberFunctionId(const TypeInfoRecordMap& type_map,
                              FILE* out,
                              common::BinaryStreamParser* parser,
                              uint16_t len,
                              uint8_t indent_level) {
  LeafMemberFunctionId mfunc_id = {};
  if (!parser->ReadBytes(offsetof(LeafMemberFunctionId, name), &mfunc_id))
    return false;
  std::string name;
  if (!parser->ReadString(&name))
    return false;
  DumpIndentedText(out, indent_level, "parentType: 0x%08x\n",
                   mfunc_id.parentType);
  DumpIndentedText(out, indent_level, "type: 0x%08x\n", mfunc_id.type);
  DumpIndentedText(out, indent_level, "name: %s\n", name.c_str());
  return true;
}

bool DumpLeafStringId(const TypeInfoRecordMap& type_map,
                      FILE* out,
                      common::BinaryStreamParser* parser,
                      uint16_t len,
                      uint8_t indent_level) {
  LeafStringId str_id = {};
  if (!parser->ReadBytes(offsetof(LeafStringId, name), &str_id))
    return false;
  std::string name;
  if (!parser->ReadString(&name))
    return false;
  DumpIndentedText(out, indent_level, "id: 0x%08x\n", str_id.id);
  DumpIndentedText(out, indent_level, "name: %s\n", name.c_str());
  return true;
}

bool DumpLeafUdtSourceLine(const TypeInfoRecordMap& type_map,
                           FILE* out,
                           common::BinaryStreamParser* parser,
                           uint16_t len,
                           uint8_t indent_level) {
  LeafUdtSourceLine src_line = {};
  if (!parser->Read(&src_line))
    return false;
  DumpIndentedText(out, indent_level, "type: 0x%08x\n", src_line.type);
  DumpIndentedText(out, indent_level, "src: 0x%08x\n", src_line.src);
  DumpIndentedText(out, indent_level, "line: 0x%08x\n", src_line.line);
  return true;
}

bool DumpLeafUdtModuleSourceLine(const TypeInfoRecordMap& type_map,
                                 FILE* out,
                                 common::BinaryStreamParser* parser,
                                 uint16_t len,
                                 uint8_t indent_level) {
  LeafUdtModuleSourceLine mod_src_line = {};
  if (!parser->Read(&mod_src_line))
    return false;
  DumpIndentedText(out, indent_level, "type: 0x%08x\n", mod_src_line.type);
  DumpIndentedText(out, indent_level, "src: 0x%08x\n", mod_src_line.src);
  DumpIndentedText(out, indent_level, "line: 0x%08x\n", mod_src_line.line);
  DumpIndentedText(out, indent_level, "imod: 0x%04x\n", mod_src_line.imod);
  return true;
}

bool DumpLeafBuildInfo(const TypeInfoRecordMap& type_map,
                       FILE* out,
                       common::BinaryStreamParser* parser,
                       uint16_t len,
                       uint8_t indent_level) {
  static const char* kFieldNames[] = { "CurrentDirectory", "BuildTool",
      "SourceFile", "ProgramDatabaseFile"};
  uint16_t count = 0;
  if (!parser->Read(&count))
    return false;
  for (size_t i = 0; i < count; ++i) {
    uint32_t id = 0;
    if (!parser->Read(&id))
      return false;
    size_t j = std::min(arraysize(kFieldNames) - 1, i);
    if (i == j) {
      DumpIndentedText(out, indent_level, "%s: 0x%08x\n", kFieldNames[i], id);
    } else {
      DumpIndentedText(out, indent_level, "Argument[%d]: 0x%08x\n", i - j, id);
    }
  }
  return true;
}

}  // namespace

bool DumpUnknownLeaf(const TypeInfoRecordMap& type_map,
                     FILE* out,
                     common::BinaryStreamParser* parser,
                     uint16_t len,
                     uint8_t indent_level) {
  DumpIndentedText(out, indent_level, "Unsupported type info. Data:\n");
  return DumpUnknownBlock(out, parser, len, indent_level);
}

size_t NumericLeafSize(uint16_t symbol_type) {
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

const char* NumericLeafName(uint16_t leaf_type) {
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

void DumpNumericLeaf(FILE* out,
                     uint16_t leaf_type,
                     common::BinaryStreamParser* parser) {
  switch (leaf_type) {
// Call a function to dump a specific (value_type) kind of numeric value.
#define NUMERIC_LEAF_TYPE_DUMP(leaf_type, struct_type) \
  case cci::leaf_type: {                               \
    Dump##struct_type(out, parser);                    \
    break;                                             \
  }
      NUMERIC_LEAVES_CASE_TABLE(NUMERIC_LEAF_TYPE_DUMP)
#undef NUMERIC_LEAF_TYPE_DUMP
  }
}

// Call the specific function to dump a kind of leaf.
bool DumpLeaf(const TypeInfoRecordMap& type_map,
              uint16_t type_value,
              FILE* out,
              common::BinaryStreamParser* parser,
              size_t len,
              uint8_t indent_level) {
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
#define LEAF_TYPE_DUMP(type_value, struct_type)                             \
  case cci::type_value: {                                                   \
    return Dump##struct_type(type_map, out, parser,                         \
                             static_cast<uint16_t>(len), indent_level + 1); \
  }
      LEAF_CASE_TABLE(LEAF_TYPE_DUMP)
#undef LEAF_TYPE_DUMP

    default:
      return false;
  }
}

// Get the name and the size associated with a numeric leaf.
// Return NULL if the leaf is not of a numeric type.
const char* GetNumericLeafNameAndSize(uint16_t leaf_type, size_t* leaf_size) {
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
