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

#include "syzygy/pdb/pdb_dump_symbols.h"

#include <string>

#include "base/stringprintf.h"
#include "syzygy/common/align.h"
#include "syzygy/pdb/pdb_dump.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_util.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

namespace {

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

// Return the string value associated with a symbol type.
const char* SymbolTypeName(uint16 symbol_type) {
  switch (symbol_type) {
// Just print the name of the enum.
#define SYM_TYPE_NAME(sym_type, unused) \
    case cci::sym_type: { \
      return #sym_type; \
    }
    SYM_TYPE_CASE_TABLE(SYM_TYPE_NAME);
#undef SYM_TYPE_NAME
    default :
      return NULL;
  }
}

// Returns the size of the struct associated with a numeric leaf type.
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

// Returns the name associated with a numeric leaf type.
const char* NumericLeafName(uint16 leaf_type) {
  switch (leaf_type) {
// Just print the name of the leaf type.
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

// Dump a symbol record using RefSym2 struct to out.
bool DumpRefSym2(FILE* out, PdbStream* stream, uint16 len) {
  cci::RefSym2 symbol_info = {};
  size_t to_read = offsetof(cci::RefSym2, name);
  size_t bytes_read = 0;
  std::string symbol_name;
  if (!stream->ReadBytes(&symbol_info, to_read, &bytes_read) ||
      !ReadString(stream, &symbol_name) ||
      to_read != bytes_read) {
    LOG(ERROR) << "Unable to read symbol record.";
    return false;
  }
  ::fprintf(out, "\t\tName: %s\n", symbol_name.c_str());
  ::fprintf(out, "\t\tSUC: %d\n", symbol_info.sumName);
  ::fprintf(out, "\t\tOffset: 0x%08X\n", symbol_info.ibSym);
  ::fprintf(out, "\t\tModule: %d\n", symbol_info.imod);

  return true;
}

// Dump a symbol record using DatasSym32 struct to out.
bool DumpDatasSym32(FILE* out, PdbStream* stream, uint16 len) {
  size_t to_read = offsetof(cci::DatasSym32, name);
  size_t bytes_read = 0;
  cci::DatasSym32 symbol_info = {};
  std::string symbol_name;
  if (!stream->ReadBytes(&symbol_info, to_read, &bytes_read) ||
      !ReadString(stream, &symbol_name) ||
      to_read != bytes_read) {
    LOG(ERROR) << "Unable to read symbol record.";
    return false;
  }
  ::fprintf(out, "\t\tName: %s\n", symbol_name.c_str());
  ::fprintf(out, "\t\tType index: %d\n", symbol_info.typind);
  ::fprintf(out, "\t\tOffset: 0x%08X\n", symbol_info.off);
  ::fprintf(out, "\t\tSegment: 0x%04X\n", symbol_info.seg);
  return true;
}

bool DumpOemSymbol(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpVpathSym32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpFrameProcSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAnnotationSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpManyTypRef(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpObjNameSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpThunkSym32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpBlockSym32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpWithSym32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpLabelSym32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpRegSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpConstSym(FILE* out, PdbStream* stream, uint16 len) {
  size_t to_read = offsetof(cci::ConstSym, name);
  size_t bytes_read = 0;
  cci::ConstSym symbol_info = {};
  if (!stream->ReadBytes(&symbol_info, to_read, &bytes_read) ||
      to_read != bytes_read) {
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
    ::fprintf(out, "\t\tValue: 0x%04X\n", symbol_info.value);
  } else {
    ::fprintf(out, "\t\tValue: type=%s, value=", value_type);
    switch (symbol_info.value) {
// Call a function to dump a specific (value_type) kind of numeric value.
#define LEAF_TYPE_DUMP(sym_type, struct_type) \
    case cci::sym_type: { \
      Dump ## struct_type(out, stream); \
      break; \
    }
      NUMERIC_LEAVES_CASE_TABLE(LEAF_TYPE_DUMP);
#undef function
    }
    ::fprintf(out, "\n");
  }
  std::string symbol_name;
  if (!ReadString(stream, &symbol_name)) {
    LOG(ERROR) << "Unable to read the name of a symbol record.";
    return false;
  }
  ::fprintf(out, "\t\tName: %s\n", symbol_name.c_str());
  ::fprintf(out, "\t\tType index: 0x%08X\n", symbol_info.typind);

  return true;
}

bool DumpUdtSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpManyRegSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpBpRelSym32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpProcSym32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpRegRel32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpThreadSym32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpProcSymMips(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}
bool DumpCompileSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpManyRegSym2(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpProcSymIa64(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpSlotSym32(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpFrameRelSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrRegSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrSlotSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrManyRegSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrRegRel(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpAttrManyRegSym2(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpUnamespaceSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpManProcSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpTrampolineSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpSepCodSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpLocalSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpDefRangeSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpDefRangeSym2(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpSectionSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpCoffGroupSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpExportSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpCallsiteInfo(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpFrameCookie(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

bool DumpDiscardedSym(FILE* out, PdbStream* stream, uint16 len) {
  // TODO(sebmarchand): Implement this function if we encounter this symbol.
  return false;
}

// Hexdump the data of the undeciphered symbol records.
bool DumpUnknown(FILE* out, PdbStream* stream, uint16 len) {
  ::fprintf(out, "\t\tUnsupported symbol type. Data:\n");
  uint8 buffer[32];
  size_t bytes_read = 0;
  while (bytes_read < len) {
    size_t bytes_to_read = len - bytes_read;
    if (bytes_to_read > sizeof(buffer))
      bytes_to_read = sizeof(buffer);
    size_t bytes_just_read = 0;
    if (!stream->ReadBytes(buffer, bytes_to_read, &bytes_just_read) ||
        bytes_just_read == 0) {
      LOG(ERROR) << "Unable to read symbol record.";
      return false;
    }
    ::fprintf(out, "\t\t");
    for (size_t i = 0; i < bytes_just_read; ++i)
      ::fprintf(out, "%X", buffer[i]);
    ::fprintf(out, "\n");
    bytes_read += bytes_just_read;
  }

  return true;
}

}  //  namespace

void DumpSymbolRecord(FILE* out,
                      PdbStream* stream,
                      const SymbolRecordVector& sym_record_vector) {
  DCHECK(stream != NULL);

  ::fprintf(out, "%d symbol record in the stream:\n",
            sym_record_vector.size());
  SymbolRecordVector::const_iterator symbol_iter =
    sym_record_vector.begin();
  // Dump each symbol contained in the vector.
  for (; symbol_iter != sym_record_vector.end(); symbol_iter++) {
    if (!stream->Seek(symbol_iter->start_position)) {
      LOG(ERROR) << "Unable to seek to symbol record at position "
                 << StringPrintf("0x%08X.", symbol_iter->start_position);
      return;
    }
    const char* symbol_type_text = SymbolTypeName(symbol_iter->type);
    if (symbol_type_text != NULL) {
      ::fprintf(out, "\tSymbol Type: 0x%04X %s\n",
                symbol_iter->type,
                symbol_type_text);
    } else {
      ::fprintf(out, "\tUnknown symbol Type: 0x%04X\n", symbol_iter->type);
    }
    bool success = false;
    switch (symbol_iter->type) {
// Call a function to dump a specific (struct_type) kind of structure.
#define SYM_TYPE_DUMP(sym_type, struct_type) \
    case cci::sym_type: { \
      success = Dump ## struct_type(out, stream, symbol_iter->len); \
      break; \
    }
      SYM_TYPE_CASE_TABLE(SYM_TYPE_DUMP);
#undef SYM_TYPE_DUMP
    }

    if (!success) {
      // In case of failure we just dump the hex data of this symbol.
      if (!stream->Seek(symbol_iter->start_position)) {
        LOG(ERROR) << "Unable to seek to symbol record at position "
                   << StringPrintf("0x%08X.", symbol_iter->start_position);
        return;
      }
      DumpUnknown(out, stream, symbol_iter->len);
    }
    stream->Seek(common::AlignUp(stream->pos(), 4));
    if (stream->pos() != symbol_iter->start_position + symbol_iter->len) {
      LOG(ERROR) << "Symbol record stream is not valid.";
      return;
    }
  }
}

}  // namespace pdb
