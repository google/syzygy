// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/image_filter.h"

#include <errno.h>

#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/strings/stringprintf.h"

namespace pe {

namespace {

using base::DictionaryValue;
using base::ListValue;
using base::Value;

// Keys used by the JSON serialization.
const char kBaseAddress[] = "base_address";
const char kChecksum[] = "checksum";
const char kFilter[] = "filter";
const char kPath[] = "path";
const char kSignature[] = "signature";
const char kSize[] = "size";
const char kTimeDateStamp[] = "time_date_stamp";

// Outputs |value| as a hex-coded string. Returns true on succes, false on
// failure.
bool OutputHexUint32(uint32 value, core::JSONFileWriter* json) {
  DCHECK(json != NULL);

  std::string s;
  if (json->pretty_print()) {
    s = base::StringPrintf("0x%08X", value);
  } else {
    s = base::StringPrintf("%X", value);
  }

  if (!json->OutputString(s))
    return false;

  return true;
}

// Parses a hex-coded value from |string|, placing it in |value|. Returns true
// on success, false if anything went wront. Logs an error message on failure.
bool ParseHexUint32(const std::string& string, uint32* value) {
  DCHECK(value != NULL);

  char* end_ptr = NULL;
  errno = 0;
  *value = ::strtoul(string.c_str(), &end_ptr, 16);
  if (errno != 0 || end_ptr != string.c_str() + string.size()) {
    LOG(ERROR) << "String does not contain a 32-bit hex value: " << string;
    return false;
  }

  return true;
}

// Gets a uint32 value from the |dict| entry under |key|. Expects the value to
// be stored as a hex-encoded string, which will be decoded. Returns true on
// success, false otherwise. Logs an error message on failure.
bool GetHexUint32(const DictionaryValue& dict,
                  const char* key,
                  uint32* value) {
  DCHECK(key != NULL);
  DCHECK(value != NULL);

  std::string s;
  if (!dict.GetString(key, &s) ||
      !ParseHexUint32(s, value)) {
    LOG(ERROR) << "Dictionary does not contain a valid hex-formatted "
               << "string under key \"" << key << "\".";
    return false;
  }

  return true;
}

// Gets an integer value from the |dict| entry under |key|. Expects the value
// to be stored as an integer. Returns true on success, false otherwise. Logs
// and error message on failure.
bool GetInteger(const DictionaryValue& dict, const char* key, int* value) {
  DCHECK(key != NULL);
  DCHECK(value != NULL);
  if (!dict.GetInteger(key, value)) {
    LOG(ERROR) << "Dictionary does not contain integer under key \""
               << key << "\".";
    return false;
  }
  return true;
}

// Loads a module signature from the given |dict|, populating the signature
// member of |filter|. Returns true on success, false otherwise. Logs an error
// message on failure.
bool LoadSignatureFromJSON(const DictionaryValue& dict, ImageFilter* filter) {
  DCHECK(filter != NULL);

  uint32 base_address = 0;
  int size = 0;
  PEFile::Signature& s = filter->signature;
  if (!GetHexUint32(dict, kBaseAddress, &base_address) ||
      !GetHexUint32(dict, kChecksum, &s.module_checksum) ||
      !GetInteger(dict, kSize, &size) ||
      size <= 0 ||
      !GetHexUint32(dict, kTimeDateStamp, &s.module_time_date_stamp) ||
      !dict.GetString(kPath, &s.path)) {
    LOG(ERROR) << "Invalid signature dictionary.";
    return false;
  }
  s.base_address.set_value(base_address);
  s.module_size = size;

  return true;
}

// Loads a relative address range from the given list. The list is expected to
// be of length 2, with the first entry being a string containing a hex-encoded
// RVA, and the second being an integer length. Adds the range to the address
// filter in |filter|. Returns true on success, false otherwise. Logs an error
// message on failure.
bool LoadRangeFromJSON(const ListValue& range, ImageFilter* filter) {
  DCHECK(filter != NULL);

  if (range.GetSize() != 2)
    return false;

  ListValue::const_iterator it = range.begin();
  Value* address_value = *(it++);
  Value* length_value = *it;
  DCHECK(address_value != NULL);
  DCHECK(length_value != NULL);

  std::string address_string;
  uint32 address = 0;
  if (!address_value->GetAsString(&address_string) ||
      !ParseHexUint32(address_string, &address)) {
    return false;
  }

  int length = 0;
  if (!length_value->GetAsInteger(&length) || length <= 0)
    return false;

  // Mark the range we just parsed.
  filter->filter.Mark(ImageFilter::Range(
      ImageFilter::RelativeAddress(address), length));

  return true;
}

// Loads a relative address filter from the given |list|, populating the
// address filter in |filter|. Expects that the signature member of |filter|
// has already been appropriately initialized. Returns true on success, false
// otherwise. Logs an error message on failure.
bool LoadFilterFromJSON(const ListValue& list, ImageFilter* filter) {
  DCHECK(filter != NULL);

  // Initialize the filter. This assumes that the signature has already been
  // loaded.
  filter->filter = ImageFilter::RelativeAddressFilter(
      ImageFilter::Range(ImageFilter::RelativeAddress(0),
                         filter->signature.module_size));

  ListValue::const_iterator it = list.begin();
  for (; it != list.end(); ++it) {
    Value* value = *it;
    DCHECK(value != NULL);

    // LoadRangeFromJSON takes care of logging on failure, and adding the range
    // to the filter on success.
    ListValue* range = NULL;
    if (!value->GetAsList(&range) ||
        !LoadRangeFromJSON(*range, filter)) {
      LOG(ERROR) << "Encountered invalid range in filter list.";
      return false;
    }
  }

  return true;
}

}  // namespace

void ImageFilter::Init(const PEFile::Signature& pe_signature) {
  signature = pe_signature;
  filter = RelativeAddressFilter(
      Range(RelativeAddress(0), signature.module_size));
}

void ImageFilter::Init(const PEFile& pe_file) {
  pe_file.GetSignature(&signature);
  filter = RelativeAddressFilter(
      Range(RelativeAddress(0), signature.module_size));
}

bool ImageFilter::Init(const base::FilePath& path) {
  PEFile pe_file;
  if (!pe_file.Init(path))
    return false;
  Init(pe_file);
  return true;
}

bool ImageFilter::IsForModule(const PEFile::Signature& pe_signature) const {
  if (!pe_signature.IsConsistent(signature))
    return false;
  return true;
}

bool ImageFilter::IsForModule(const PEFile& pe_file) const {
  PEFile::Signature pe_signature;
  pe_file.GetSignature(&pe_signature);
  if (!IsForModule(pe_signature))
    return false;
  return true;
}

bool ImageFilter::IsForModule(const base::FilePath& path) const {
  PEFile pe_file;
  if (!pe_file.Init(path))
    return false;
  if (!IsForModule(pe_file))
    return false;
  return true;
}

bool ImageFilter::SaveToJSON(core::JSONFileWriter* json) const {
  DCHECK(json != NULL);

  core::JSONFileWriter& j = *json;

  if (!j.OutputComment("This is a serialized ImageFilter.") ||
      !j.OpenDict()) {
    return false;
  }

  // Write the module signature.
  if (!j.OutputComment("This is the signature of the module to which this") ||
      !j.OutputComment("filter applies.") ||
      !j.OutputKey(kSignature) ||
      !j.OpenDict() ||
      !j.OutputKey(kPath) ||
      !j.OutputString(signature.path) ||
      !j.OutputKey(kBaseAddress) ||
      !OutputHexUint32(signature.base_address.value(), json) ||
      !j.OutputKey(kChecksum) ||
      !OutputHexUint32(signature.module_checksum, json) ||
      !j.OutputKey(kSize) ||
      !j.OutputInteger(signature.module_size) ||
      !j.OutputKey(kTimeDateStamp) ||
      !OutputHexUint32(signature.module_time_date_stamp, json) ||
      !j.CloseDict()) {
    return false;
  }

  if (!j.OutputComment("This is the filtered address space, consisting of") ||
      !j.OutputComment("a list of [rva, length] tuples.") ||
      !j.OutputKey(kFilter) ||
      !j.OpenList()) {
    return false;
  }

  // Write the ranges in the filter.
  RelativeAddressFilter::RangeSet::const_iterator it =
      filter.marked_ranges().begin();
  for (; it != filter.marked_ranges().end(); ++it) {
    if (!j.OpenList() ||
        !OutputHexUint32(it->start().value(), json) ||
        !j.OutputInteger(it->size()) ||
        !j.CloseList()) {
      return false;
    }
  }

  if (!j.CloseList() || !j.CloseDict())
    return false;

  return true;
}

bool ImageFilter::SaveToJSON(bool pretty_print, FILE* file) const {
  DCHECK(file != NULL);

  core::JSONFileWriter json_writer(file, pretty_print);
  if (!SaveToJSON(&json_writer))
    return false;

  return true;
}

bool ImageFilter::SaveToJSON(bool pretty_print,
                             const base::FilePath& path) const {
  base::ScopedFILE file(base::OpenFile(path, "wb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Unable to open file for writing: " << path.value();
    return false;
  }

  if (!SaveToJSON(pretty_print, file.get()))
    return false;

  return true;
}

bool ImageFilter::LoadFromJSON(const DictionaryValue& dict) {
  // Get the signature dictionary.
  const DictionaryValue* signature_dict;
  if (!dict.GetDictionary(kSignature, &signature_dict)) {
    LOG(ERROR) << "Dictionary does not contain a dictionary under key \""
               << kSignature << "\".";
    return false;
  }
  if (!LoadSignatureFromJSON(*signature_dict, this))
    return false;

  // Get the filter list and parse it.
  const ListValue* filter;
  if (!dict.GetList(kFilter, &filter)) {
    LOG(ERROR) << "Dictionary does not contain a list under key \""
               << kFilter << "\".";
    return false;
  }
  if (!LoadFilterFromJSON(*filter, this))
    return false;

  return true;
}

bool ImageFilter::LoadFromJSON(FILE* file) {
  DCHECK(file != NULL);

  // Read the file into one big array.
  char buffer[4096] = {};
  std::vector<char> json;
  while (!::feof(file)) {
    size_t bytes = ::fread(buffer, sizeof(buffer[0]), arraysize(buffer), file);
    if (::ferror(file)) {
      LOG(ERROR) << "Error reading from file.";
      return false;
    }
    DCHECK_LT(0u, bytes);
    size_t offset = json.size();
    json.resize(offset + bytes);
    ::memcpy(json.data() + offset, buffer, bytes);
  }

  if (json.empty()) {
    LOG(ERROR) << "File is empty.";
    return false;
  }

  base::JSONReader json_reader;
  scoped_ptr<base::Value> value(
      json_reader.Read(base::StringPiece(json.data(), json.size())));
  if (value.get() == NULL) {
    LOG(ERROR) << "Failed to parse JSON from file.";
    return false;
  }

  base::DictionaryValue* dict;
  if (!value->GetAsDictionary(&dict) || dict == NULL) {
    LOG(ERROR) << "JSON does not contain dictionary at top level.";
    return false;
  }

  if (!LoadFromJSON(*dict))
    return false;

  return true;
}

bool ImageFilter::LoadFromJSON(const base::FilePath& path) {
  base::ScopedFILE file(base::OpenFile(path, "rb"));
  if (file.get() == NULL) {
    LOG(ERROR) << "Unable to open file for reading: " << path.value();
    return false;
  }

  if (!LoadFromJSON(file.get()))
    return false;

  return true;
}

}  // namespace pe
