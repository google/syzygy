// Copyright 2014 Google Inc. All Rights Reserved.
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

#include "syzygy/ar/ar_reader.h"

#include <set>

#include "base/logging.h"
#include "base/strings/string_number_conversions.h"
#include "syzygy/common/align.h"

namespace ar {

namespace {

typedef ArReader::SymbolIndexMap SymbolIndexMap;
typedef ArReader::FileOffsetVector FileOffsetVector;

// Calculates that length of a space terminated string with a maximum size.
template<size_t kArrayLength>
size_t ArStringLength(const char (&s)[kArrayLength]) {
  DCHECK_NE(reinterpret_cast<const char*>(NULL), &s[0]);
  size_t l = kArrayLength;
  while (l > 0 && s[l - 1] == ' ')
    --l;
  return l;
}

// Parses an unsigned integer from a space-terminated string. The output -1 is
// reserved to indicate an empty string, ie: no value.
template<size_t kArrayLength, typename OutputType>
bool ParseArNumber(const char (&s)[kArrayLength], OutputType* output) {
  DCHECK_NE(reinterpret_cast<const char*>(NULL), &s[0]);
  DCHECK_NE(reinterpret_cast<OutputType*>(NULL), output);

  // Ensure the output size is sufficiently big for the string we're parsing.
  // bits log(2) / log(10) >= digits
  // digits <= 0.3 * bits
  // 10 * digits <= 3 * bits
  COMPILE_ASSERT(10 * kArrayLength <= 3 * 8 * sizeof(OutputType),
                 output_type_to_small_for_input_string);

  size_t l = ArStringLength(s);
  if (l == 0) {
    *output = ~0;
    return true;
  }

  OutputType value = 0;
  for (size_t i = 0; i < l; ++i) {
    value *= 10;
    if (s[i] < '0' || s[i] > '9') {
      LOG(ERROR) << "Invalid number in archive file header.";
      return false;
    }
    value += s[i] - '0';
  }

  *output = value;
  return true;
}

bool ParseArFileHeader(const ArFileHeader& header,
                       ParsedArFileHeader* parsed_header) {
  DCHECK_NE(reinterpret_cast<ParsedArFileHeader*>(NULL), parsed_header);

  size_t name_len = ArStringLength(header.name);
  parsed_header->name = std::string(header.name, name_len);

  // The time is in seconds since epoch.
  uint64 timestamp;
  if (!ParseArNumber(header.timestamp, &timestamp))
    return false;
  parsed_header->timestamp = base::Time::FromDoubleT(
      static_cast<double>(timestamp));

  if (!ParseArNumber(header.mode, &parsed_header->mode))
    return false;

  if (!ParseArNumber(header.size, &parsed_header->size))
    return false;

  return true;
}

template<typename Object>
bool ReadObject(FILE* file, Object* object) {
  DCHECK_NE(reinterpret_cast<FILE*>(NULL), file);
  DCHECK_NE(reinterpret_cast<Object*>(NULL), object);
  if (::fread(object, sizeof(Object), 1, file) != 1) {
    LOG(ERROR) << "Failed to read from archive.";
    return false;
  }
  return true;
}

bool ParseSecondarySymbolTable(
    size_t file_size,
    const uint8* data,
    size_t length,
    SymbolIndexMap* symbols,
    FileOffsetVector* file_offsets) {
  DCHECK_NE(reinterpret_cast<const uint8*>(NULL), data);
  DCHECK_NE(reinterpret_cast<SymbolIndexMap*>(NULL), symbols);
  DCHECK_NE(reinterpret_cast<FileOffsetVector*>(NULL), file_offsets);

  if (length < sizeof(uint32)) {
    LOG(ERROR) << "Secondary symbol table contains no file count.";
    return false;
  }

  // Validate the size of the secondary symbol table.
  const uint32* offsets = reinterpret_cast<const uint32*>(data) + 1;
  size_t file_count = offsets[-1];
  if (length < (file_count + 2) * sizeof(uint32)) {
    LOG(ERROR) << "Secondary symbol table file offsets are truncated.";
  }

  size_t symbol_count = offsets[file_count];

  // Get pointers to the various parts of the symbol table.
  const uint16* indices = reinterpret_cast<const uint16*>(
      offsets + file_count + 1);
  const uint16* indices_end = indices + symbol_count;
  const char* names = reinterpret_cast<const char*>(indices + symbol_count);
  const char* names_end = reinterpret_cast<const char*>(data + length);
  if (names >= names_end) {
    LOG(ERROR) << "Secondary symbol table indices are truncated.";
    return false;
  }

  // Read and validate the file offsets.
  *file_offsets = FileOffsetVector(offsets, offsets + file_count);
  for (size_t i = 0; i < file_count; ++i) {
    if (offsets[i] >= file_size) {
      LOG(ERROR) << "Invalid symbol offset encountered in archive.";
      return false;
    }
  }

  // Read the file indices for each symbol.
  std::set<std::string> symbol_names;
  for (size_t i = 0; i < symbol_count; ++i) {
    size_t name_len = ::strnlen(names, names_end - names);
    if (name_len == 0) {
      LOG(ERROR) << "Symbol " << i << " has an invalid name.";
      return false;
    }

    uint16 file_index = indices[i];
    std::string name = std::string(names, name_len);
    names += name_len + 1;

    if (file_index == 0 || file_index > file_count) {
      LOG(ERROR) << "Invalid file index " << file_index << " for symbol "
                 << i << ": " << name;
      return false;
    }

    // File indices are 1-indexed in the archive, but we use 0-indexing.
    if (!symbols->insert(std::make_pair(name, file_index - 1)).second) {
      LOG(WARNING) << "Duplicate symbol encountered in archive.";
      return false;
    }
  }

  return true;
}

}  // namespace

ArReader::ArReader()
    : length_(0), offset_(0), start_of_object_files_(0) {
}

bool ArReader::Init(const base::FilePath& ar_path) {
  DCHECK(path_.empty());

  path_ = ar_path;
  file_.reset(file_util::OpenFile(path_, "rb"));
  if (file_.get() == NULL) {
    LOG(ERROR) << "Failed to open file for reading: " << path_.value();
    return false;
  }

  if (!file_util::GetFileSize(path_, reinterpret_cast<int64*>(&length_))) {
    LOG(ERROR) << "Unable to get the archive file size.";
    return false;
  }

  // Parse the global header.
  ArGlobalHeader global_header = {};
  if (!ReadObject(file_.get(), &global_header))
    return false;
  if (::memcmp(global_header.magic,
               kArGlobalMagic,
               sizeof(kArGlobalMagic)) != 0) {
    LOG(ERROR) << "Invalid archive file global header.";
    return false;
  }
  offset_ += sizeof(global_header);

  // Read (and ignore) the primary symbol table. This needs to be present but
  // it contains data that is also to be found in the secondary symbol table,
  // with higher fidelity.
  ParsedArFileHeader header;
  if (!ReadNextFile(&header, NULL)) {
    LOG(ERROR) << "Failed to read primary symbol table.";
    return false;
  }
  if (header.name != "/") {
    LOG(ERROR) << "Did not find primary symbol table in archive.";
    return false;
  }

  // Read and parse the secondary symbol table.
  DataBuffer data;
  if (!ReadNextFile(&header, &data)) {
    LOG(ERROR) << "Failed to read secondary symbol table.";
    return false;
  }
  if (header.name != "/") {
    LOG(ERROR) << "Did not find secondary symbol table in archive.";
    return false;
  }
  if (!ParseSecondarySymbolTable(length_, data.data(), data.size(),
                                  &symbols_, &offsets_)) {
    LOG(ERROR) << "Failed to parse secondary symbol table.";
    return false;
  }

  // Expect a filename table.
  if (!ReadNextFile(&header, &data)) {
    LOG(ERROR) << "Failed to read filename table.";
    return false;
  }
  if (header.name != "//") {
    LOG(ERROR) << "Did not find filename table in archive.";
    return false;
  }
  std::swap(data, filenames_);

  // Remember where the remaining files begin.
  start_of_object_files_ = offset_;

  return true;
}

bool ArReader::BuildFileIndex() {
  DCHECK(files_.empty());
  DCHECK(files_inverse_.empty());

  if (!SeekStart())
    return false;

  files_.reserve(offsets_.size());

  size_t index = 0;
  while (HasNext()) {
    // Read the file and get its translated name.
    uint32 file_offset = static_cast<uint32>(offset_);
    ParsedArFileHeader header;
    if (!ReadNextFile(&header, NULL))
      return false;
    std::string filename;
    if (!TranslateFilename(header.name, &filename))
      return false;

    // Store or validate the file offset.
    if (index >= offsets_.size() || offsets_[index] != file_offset) {
      LOG(ERROR) << "Encoded file offsets do not match archive contents.";
      return false;
    }

    files_.push_back(filename);
    if (!files_inverse_.insert(std::make_pair(filename, index)).second) {
      LOG(ERROR) << "Object \"" << header.name
                 << "\" has a duplicate file name: " << filename;
      return false;
    }

    ++index;
  }

  if (!SeekStart())
    return false;

  return true;
}

bool ArReader::SeekStart() {
  if (offset_ != start_of_object_files_ &&
      ::fseek(file_.get(), start_of_object_files_, SEEK_SET) != 0) {
    LOG(ERROR) << "Failed to seek to beginning of archive files.";
    return false;
  }
  offset_ = start_of_object_files_;

  return true;
}

bool ArReader::HasNext() const {
  if (offset_ < length_)
    return true;
  return false;
}

bool ArReader::ExtractNext(ParsedArFileHeader* header,
                           DataBuffer* data) {
  DCHECK_NE(reinterpret_cast<ParsedArFileHeader*>(NULL), header);
  if (!ReadNextFile(header, data))
    return false;

  // Store the actual filename in the header.
  std::string filename;
  if (!TranslateFilename(header->name, &filename))
    return false;
  header->name = filename;

  return true;
}

bool ArReader::Extract(size_t index,
                       ParsedArFileHeader* header,
                       DataBuffer* data) {
  DCHECK_NE(reinterpret_cast<ParsedArFileHeader*>(NULL), header);

  if (index >= offsets_.size())
    return false;

  // Seek to the file in question.
  if (::fseek(file_.get(), offsets_[index], SEEK_SET) != 0) {
    LOG(ERROR) << "Failed to seek to file " << index << ".";
    return false;
  }
  offset_ = offsets_[index];

  if (!ExtractNext(header, data))
    return false;

  return true;
}

bool ArReader::ReadNextFile(ParsedArFileHeader* header,
                            DataBuffer* data) {
  DCHECK_NE(reinterpret_cast<ParsedArFileHeader*>(NULL), header);

  // Read and parse the file header.
  ArFileHeader raw_header = {};
  if (!ReadObject(file_.get(), &raw_header))
    return false;
  if (!ParseArFileHeader(raw_header, header))
    return false;
  offset_ += sizeof(raw_header);

  uint64 aligned_size = common::AlignUp64(header->size,
                                          kArFileAlignment);
  uint64 seek_size = aligned_size;

  // Read the actual file contents if necessary.
  if (data != NULL) {
    seek_size = aligned_size - header->size;
    data->resize(header->size);
    if (::fread(data->data(), 1, header->size, file_.get()) !=
            header->size) {
      LOG(ERROR) << "Failed to read file \"" << header->name
                 << "\" at offset " << offset_ << " of archive \""
                 << path_.value() << "\".";
      return false;
    }
    offset_ += header->size;
  }

  // Seek to the beginning of the next file.
  if (seek_size > 0 && ::fseek(file_.get(), seek_size, SEEK_CUR) != 0) {
    LOG(ERROR) << "Failed to seek to next file at offset " << offset_
               << " of archive \"" << path_.value() << "\".";
    return false;
  }
  offset_ += seek_size;

  return true;
}

bool ArReader::TranslateFilename(const std::string& internal_name,
                                 std::string* full_name) {
  DCHECK_NE(reinterpret_cast<std::string*>(NULL), full_name);

  if (internal_name.empty()) {
    LOG(ERROR) << "Invalid internal archive filename: " << internal_name;
    return false;
  }

  // If there is no leasing slash then the name is directly encoded in the
  // header.
  if (internal_name[0] != '/') {
    if (internal_name.back() != '/') {
      LOG(ERROR) << "Invalid filename: " << internal_name;
      return false;
    }
    *full_name = std::string(internal_name.begin(),
                             internal_name.end() - 1);
    return true;
  }

  uint32 filename_offset = 0;
  if (!base::StringToUint(internal_name.c_str() + 1, &filename_offset)) {
    LOG(ERROR) << "Unable to parse filename offset: " << internal_name;
    return false;
  }

  if (filename_offset >= filenames_.size()) {
    LOG(ERROR) << "Invalid filename offset: " << filename_offset;
    return false;
  }

  const char* data = reinterpret_cast<char*>(filenames_.data());
  size_t filename_length = ::strnlen(data + filename_offset,
                                     filenames_.size() - filename_offset);
  *full_name = std::string(data + filename_offset, filename_length);

  return true;
}

}  // namespace ar
