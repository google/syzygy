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

#include "syzygy/pdb/pdb_symbol_record.h"

#include <string>

#include "base/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/experimental/pdb_dumper/cvinfo_ext.h"
#include "syzygy/experimental/pdb_dumper/pdb_dump_util.h"
#include "syzygy/experimental/pdb_dumper/pdb_leaf.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

namespace {

template <typename SymbolType>
bool ReadSymbolAndName(PdbStream* stream,
                       uint16 len,
                       SymbolType* symbol_out,
                       std::string* name_out) {
  DCHECK(stream != NULL);
  DCHECK(len > 0);
  DCHECK(symbol_out != NULL);
  DCHECK(name_out != NULL);

  // Note the zero-terminated name field must be the trailing field
  // of the symbol.
  size_t to_read = offsetof(SymbolType, name);
  size_t bytes_read = 0;
  if (!stream->ReadBytes(symbol_out, to_read, &bytes_read) ||
      !ReadString(stream, name_out) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read symbol record.";
    return false;
  }

  return true;
}

// Return the string value associated with a symbol type.
const char* SymbolTypeName(uint16 symbol_type) {
  switch (symbol_type) {
// Just return the name of the enum.
#define SYM_TYPE_NAME(sym_type, unused) \
    case cci::sym_type: { \
      return #sym_type; \
    }
    SYM_TYPE_CASE_TABLE(SYM_TYPE_NAME)
#undef SYM_TYPE_NAME
    default :
      return NULL;
  }
}

// Dump a symbol record using RefSym2 struct to out.
bool DumpRefSym2(FILE* out, PdbStream* stream, uint16 len, uint8 indent_level) {
  cci::RefSym2 symbol_info = {};
  std::string symbol_name;
  if (!ReadSymbolAndName(stream, len, &symbol_info, &symbol_name))
    return false;

  DumpIndentedText(out, indent_level, "Name: %s\n", symbol_name.c_str());
  DumpIndentedText(out, indent_level, "SUC: %d\n", symbol_info.sumName);
  DumpIndentedText(out, indent_level, "Offset: 0x%08X\n", symbol_info.ibSym);
  DumpIndentedText(out, indent_level, "Module: %d\n", symbol_info.imod);

  return true;
}

// Dump a symbol record using DatasSym32 struct to out.
bool DumpDatasSym32(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  cci::DatasSym32 symbol_info = {};
  std::string symbol_name;
  if (!ReadSymbolAndName(stream, len, &symbol_info, &symbol_name))
    return false;

  DumpIndentedText(out, indent_level, "Name: %s\n", symbol_name.c_str());
  DumpIndentedText(out, indent_level, "Type index: %d\n", symbol_info.typind);
  DumpIndentedText(out, indent_level, "Offset: 0x%08X\n", symbol_info.off);
  DumpIndentedText(out, indent_level, "Segment: 0x%04X\n", symbol_info.seg);
  return true;
}

bool DumpOemSymbol(FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpVpathSym32(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpFrameProcSym(FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAnnotationSym(FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 indent_level) {
  cci::AnnotationSym symbol_info = {};

  size_t to_read = offsetof(cci::AnnotationSym, rgsz);
  size_t bytes_read = 0;
  if (!stream->ReadBytes(&symbol_info, to_read, &bytes_read) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read symbol record.";
    return false;
  }

  DumpIndentedText(out, indent_level, "Offset: 0x%08X\n", symbol_info.off);
  DumpIndentedText(out, indent_level, "Segment: 0x%04X\n", symbol_info.seg);
  DumpIndentedText(out, indent_level, "Number of strings: %d\n",
      symbol_info.csz);

  for (int i = 0; i < symbol_info.csz; ++i) {
    std::string annotation;
    if (!ReadString(stream, &annotation)) {
      LOG(ERROR) << "Unable to read an annotation.";
      return false;
    }
    DumpIndentedText(out, indent_level + 1, "%d: %s\n", i, annotation.c_str());
  }

  return true;
}

bool DumpManyTypRef(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpObjNameSym(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpThunkSym32(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpBlockSym32(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpWithSym32(FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpLabelSym32(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpRegSym(FILE* out, PdbStream* stream, uint16 len, uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpConstSym(FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 indent_level) {
  size_t to_read = offsetof(cci::ConstSym, name);
  size_t bytes_read = 0;
  cci::ConstSym symbol_info = {};
  if (!stream->ReadBytes(&symbol_info, to_read, &bytes_read) ||
      bytes_read != to_read) {
    LOG(ERROR) << "Unable to read symbol record.";
    return false;
  }

  // If the value field is less than LF_NUMERIC then the value data is the value
  // of that symbol. Otherwise it refers to the value data and the actual value
  // is located after this field.
  size_t name_start_offset = 0;
  const char* value_type = GetNumericLeafNameAndSize(symbol_info.value,
                                                     &name_start_offset);

  if (value_type == NULL) {
    DumpIndentedText(out, indent_level, "Value: 0x%04X\n", symbol_info.value);
  } else {
    DumpIndentedText(out, indent_level, "Value: type=%s, value=", value_type);
    DumpNumericLeaf(out, symbol_info.value, stream);
    ::fprintf(out, "\n");
  }
  std::string symbol_name;
  if (!ReadString(stream, &symbol_name)) {
    LOG(ERROR) << "Unable to read the name of a symbol record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Name: %s\n", symbol_name.c_str());
  DumpIndentedText(out, indent_level, "Type index: 0x%08X\n",
      symbol_info.typind);

  return true;
}

bool DumpUdtSym(FILE* out, PdbStream* stream, uint16 len, uint8 indent_level) {
  cci::UdtSym symbol_info = {};
  std::string symbol_name;
  if (!ReadSymbolAndName(stream, len, &symbol_info, &symbol_name))
    return false;

  DumpIndentedText(out, indent_level, "Name: %s\n", symbol_name.c_str());
  DumpIndentedText(out, indent_level, "Type index: %d\n", symbol_info.typind);
  return true;
}

bool DumpManyRegSym(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpBpRelSym32(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpProcSym32(FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpRegRel32(FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpThreadSym32(FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  cci::ThreadSym32 symbol_info = {};
  std::string symbol_name;
  if (!ReadSymbolAndName(stream, len, &symbol_info, &symbol_name))
    return false;

  DumpIndentedText(out, indent_level, "Name: %s\n", symbol_name.c_str());
  DumpIndentedText(out, indent_level, "Offset: %d\n", symbol_info.off);
  DumpIndentedText(out, indent_level, "Segment: %d\n", symbol_info.seg);
  DumpIndentedText(out, indent_level, "Type index: %d\n", symbol_info.typind);
  return true;
}

bool DumpProcSymMips(FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}
bool DumpCompileSym(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpManyRegSym2(FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpProcSymIa64(FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpSlotSym32(FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpFrameRelSym(FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrRegSym(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrSlotSym(FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrManyRegSym(FILE* out,
                        PdbStream* stream,
                        uint16 len,
                        uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrRegRel(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrManyRegSym2(FILE* out,
                         PdbStream* stream,
                         uint16 len,
                         uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpUnamespaceSym(FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpManProcSym(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpTrampolineSym(FILE* out,
                       PdbStream* stream,
                       uint16 len,
                       uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpSepCodSym(FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpLocalSym(FILE* out,
                  PdbStream* stream,
                  uint16 len,
                  uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpDefRangeSym(FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpDefRangeSym2(FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpSectionSym(FILE* out,
                    PdbStream* stream,
                    uint16 len,
                    uint8 indent_level) {
  cci::SectionSym section = {};
  std::string section_name;
  if (!ReadSymbolAndName(stream, len, &section, &section_name))
    return false;

  DumpIndentedText(out, indent_level, "isec: %d\n", section.isec);
  DumpIndentedText(out, indent_level, "align: %d\n", section.align);
  DumpIndentedText(out, indent_level, "bReserved: %d\n", section.bReserved);
  DumpIndentedText(out, indent_level, "rva: 0x%08X\n", section.rva);
  DumpIndentedText(out, indent_level, "cb: %d\n", section.cb);
  DumpIndentedText(out, indent_level, "characteristics: 0x%08X\n",
                   section.characteristics);
  DumpIndentedText(out, indent_level, "name: %s\n", section_name.c_str());

  return true;
}

bool DumpCoffGroupSym(FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  cci::CoffGroupSym coff_group = {};
  std::string coff_group_name;
  if (!ReadSymbolAndName(stream, len, &coff_group, &coff_group_name))
    return false;

  DumpIndentedText(out, indent_level, "cb: %d\n", coff_group.cb);
  DumpIndentedText(out, indent_level, "characteristics: 0x%08X\n",
                   coff_group.characteristics);
  DumpIndentedText(out, indent_level, "off: %d\n", coff_group.off);
  DumpIndentedText(out, indent_level, "seg: %d\n", coff_group.seg);
  DumpIndentedText(out, indent_level, "name: %s\n", coff_group_name.c_str());

  return true;
}

bool DumpExportSym(FILE* out,
                   PdbStream* stream,
                   uint16 len,
                   uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpCallsiteInfo(FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  cci::CallsiteInfo symbol_info = {};
  if (!stream->Read(&symbol_info, 1)) {
    LOG(ERROR) << "Unable to read symbol record.";
    return false;
  }
  DumpIndentedText(out, indent_level, "Offset: 0x%08X\n", symbol_info.off);
  DumpIndentedText(out, indent_level, "Section index: 0x%04X\n",
      symbol_info.ect);
  DumpIndentedText(out, indent_level,
      "Type index describing function signature: 0x%08X\n", symbol_info.typind);
  return true;
}

bool DumpFrameCookie(FILE* out,
                     PdbStream* stream,
                     uint16 len,
                     uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpDiscardedSym(FILE* out,
                      PdbStream* stream,
                      uint16 len,
                      uint8 indent_level) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

// Hexdump the data of the undeciphered symbol records.
bool DumpUnknown(FILE* out, PdbStream* stream, uint16 len, uint8 indent_level) {
  if (len == 0)
    return true;
  DumpIndentedText(out, indent_level, "Unsupported symbol type. Data:\n");
  return DumpUnknownBlock(out, stream, len, indent_level + 1);
}

}  //  namespace

void DumpSymbolRecords(FILE* out,
                       PdbStream* stream,
                       const SymbolRecordVector& sym_record_vector,
                       uint8 indent_level) {
  DCHECK(stream != NULL);

  SymbolRecordVector::const_iterator symbol_iter =
    sym_record_vector.begin();
  // Dump each symbol contained in the vector.
  for (; symbol_iter != sym_record_vector.end(); ++symbol_iter) {
    if (!stream->Seek(symbol_iter->start_position)) {
      LOG(ERROR) << "Unable to seek to symbol record at position "
                 << base::StringPrintf("0x%08X.", symbol_iter->start_position);
      return;
    }
    const char* symbol_type_text = SymbolTypeName(symbol_iter->type);
    if (symbol_type_text != NULL) {
      DumpIndentedText(out,
                       indent_level,
                       "Symbol Type: 0x%04X %s\n",
                       symbol_iter->type,
                       symbol_type_text);
    } else {
      DumpIndentedText(out,
                       indent_level,
                       "Unknown symbol Type: 0x%04X\n",
                       symbol_iter->type);
    }
    bool success = false;
    switch (symbol_iter->type) {
// Call a function to dump a specific (struct_type) kind of structure.
#define SYM_TYPE_DUMP(sym_type, struct_type) \
    case cci::sym_type: { \
      success = Dump ## struct_type(out, \
                                    stream, \
                                    symbol_iter->len, \
                                    indent_level + 1); \
      break; \
    }
      SYM_TYPE_CASE_TABLE(SYM_TYPE_DUMP)
#undef SYM_TYPE_DUMP
    }

    if (!success) {
      // In case of failure we just dump the hex data of this symbol.
      if (!stream->Seek(symbol_iter->start_position)) {
        LOG(ERROR) << "Unable to seek to symbol record at position "
                   << base::StringPrintf("0x%08X.",
                                         symbol_iter->start_position);
        return;
      }
      DumpUnknown(out, stream, symbol_iter->len, indent_level + 1);
    }
    stream->Seek(common::AlignUp(stream->pos(), 4));
    if (stream->pos() != symbol_iter->start_position + symbol_iter->len) {
      LOG(ERROR) << "Symbol record stream is not valid.";
      return;
    }
  }
}

}  // namespace pdb
