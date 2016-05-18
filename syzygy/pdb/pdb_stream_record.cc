// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pdb/pdb_stream_record.h"

#include "base/strings/utf_string_conversions.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/cvinfo_ext.h"

namespace pdb {

NumericConstant::NumericConstant() : kind_(CONSTANT_UNINITIALIZED) {
}

bool ReadWideString(common::BinaryStreamParser* parser,
                    base::string16* string_field) {
  std::string narrow_string;
  if (!parser->ReadString(&narrow_string))
    return false;
  return base::UTF8ToWide(narrow_string.c_str(), narrow_string.length(),
                          string_field);
}

bool ReadUnsignedNumeric(common::BinaryStreamParser* parser,
                         uint64_t* data_field) {
  DCHECK_NE(static_cast<common::BinaryStreamParser*>(nullptr), parser);
  DCHECK_NE(static_cast<uint64_t*>(nullptr), data_field);

  NumericConstant numeric;
  if (!ReadNumericConstant(parser, &numeric))
    return false;

  if (numeric.kind() != NumericConstant::CONSTANT_UNSIGNED)
    return false;

  *data_field = numeric.unsigned_value();
  return true;
}

bool ReadNumericConstant(common::BinaryStreamParser* parser,
                         NumericConstant* constant) {
  DCHECK_NE(static_cast<common::BinaryStreamParser*>(nullptr), parser);
  DCHECK_NE(static_cast<NumericConstant*>(nullptr), constant);

  uint16_t value_type = 0;
  if (!parser->Read(&value_type))
    return false;

  // If the value is small then it's simply this value.
  if (value_type < Microsoft_Cci_Pdb::LF_NUMERIC) {
    constant->kind_ = NumericConstant::CONSTANT_UNSIGNED;
    constant->unsigned_value_ = value_type;
    return true;
  }

  // Otherwise load the constant given its value type.
  switch (value_type) {
    case Microsoft_Cci_Pdb::LF_CHAR: {
      int8_t value = 0;
      if (!parser->Read(&value))
        return false;
      constant->kind_ = NumericConstant::CONSTANT_SIGNED;
      constant->signed_value_ = value;
      return true;
    }
    case Microsoft_Cci_Pdb::LF_USHORT: {
      uint16_t value = 0;
      if (!parser->Read(&value))
        return false;
      constant->kind_ = NumericConstant::CONSTANT_UNSIGNED;
      constant->unsigned_value_ = value;
      return true;
    }
    case Microsoft_Cci_Pdb::LF_ULONG: {
      uint32_t value = 0;
      if (!parser->Read(&value))
        return false;
      constant->kind_ = NumericConstant::CONSTANT_UNSIGNED;
      constant->unsigned_value_ = value;
      return true;
    }
    case Microsoft_Cci_Pdb::LF_UQUADWORD: {
      uint64_t value = 0;
      if (!parser->Read(&value))
        return false;
      constant->kind_ = NumericConstant::CONSTANT_UNSIGNED;
      constant->unsigned_value_ = value;
      return true;
    }
    case Microsoft_Cci_Pdb::LF_SHORT: {
      int16_t value = 0;
      if (!parser->Read(&value))
        return false;
      constant->kind_ = NumericConstant::CONSTANT_SIGNED;
      constant->unsigned_value_ = value;
      return true;
    }
    case Microsoft_Cci_Pdb::LF_LONG: {
      int32_t value = 0;
      if (!parser->Read(&value))
        return false;
      constant->kind_ = NumericConstant::CONSTANT_SIGNED;
      constant->unsigned_value_ = value;
      return true;
    }
    case Microsoft_Cci_Pdb::LF_QUADWORD: {
      int64_t value = 0;
      if (!parser->Read(&value))
        return false;
      constant->kind_ = NumericConstant::CONSTANT_SIGNED;
      constant->unsigned_value_ = value;
      return true;
    }
    default: { return false; }
  }
}

}  // namespace pdb
