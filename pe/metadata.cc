// Copyright 2011 Google Inc.
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

#include "syzygy/pe/metadata.h"

#include <time.h>
#include "base/command_line.h"
#include "base/json/json_reader.h"
#include "base/json/string_escape.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/values.h"
#include "syzygy/core/block_graph.h"
#include "syzygy/common/defs.h"

namespace pe {

using core::BlockGraph;
typedef PEFile::RelativeAddress RelativeAddress;

namespace {

// Metadata JSON keys.
const char kCommandLineKey[] = "command_line";
const char kCreationTimeKey[] = "creation_time";
const char kToolchainVersionKey[] = "toolchain_version";
const char kModuleSignatureKey[] = "module_signature";

// SyzygyVersion JSON keys.
const char kMajorKey[] = "major";
const char kMinorKey[] = "minor";
const char kBuildKey[] = "build";
const char kPatchKey[] = "patch";
const char kLastChangeKey[] = "last_change";

// PEFile::Signature JSON keys.
const char kPathKey[] = "path";
const char kBaseAddressKey[] = "base_address";
const char kModuleSizeKey[] = "module_size";
const char kModuleTimeDateStampKey[] = "module_time_date_stamp";
const char kModuleChecksumKey[] = "module_checksum";

std::string TimeToString(const Time& time) {
  // Want the output format to be consistent with what Time::FromString
  // accepts as input. An example follows:
  // Tue, 15 Nov 1994 12:45:26 GMT.
  char buffer[64];
  time_t tt = time.ToTimeT();
  struct tm timeinfo = {};
  gmtime_s(&timeinfo, &tt);
  strftime(buffer, sizeof(buffer), "%a, %d %b %Y %H:%M:%S GMT", &timeinfo);
  return std::string(buffer);
}

bool StringToTime(const std::string& string, Time* time) {
  std::wstring wstring;
  return UTF8ToWide(string.c_str(), string.size(), &wstring) &&
      Time::FromString(wstring.c_str(), time);
}

// The following are utility functions for writing directly to a JSON formatted
// file. We avoid going through Value because we like to annotate with
// comments.
// TODO(chrisha): Maybe create a JsonStreamWriter? We're outputting commented
//     JSON in a couple of places now.

// Outputs indent spaces to file.
bool OutputIndent(FILE* file, int indent, bool pretty_print) {
  DCHECK(file != NULL);
  if (!pretty_print)
    return true;
  for (int i = 0; i < indent; ++i) {
    if (fputc(' ', file) == EOF)
      return false;
  }
  return true;
}

// Outputs an end of line, only if pretty-printing.
bool OutputLineEnd(FILE* file, bool pretty_print) {
  DCHECK(file != NULL);
  return !pretty_print || fputc('\n', file) != EOF;
}

// Outputs text. If pretty printing, will respect the indent.
bool OutputText(FILE* file, const char* text, int indent, bool pretty_print) {
  DCHECK(file != NULL);
  return OutputIndent(file, indent, pretty_print) &&
      fprintf(file, "%s", text) >= 0;
}

// Outputs a comment with the given indent, only if pretty-printing.
bool OutputComment(
    FILE* file, const char* comment, int indent, bool pretty_print) {
  DCHECK(file != NULL);
  if (!pretty_print)
    return true;
  return OutputIndent(file, indent, pretty_print) &&
      fprintf(file, "// %s\n", comment) >= 0;
}

// Outputs a JSON dictionary key, pretty-printed if so requested. Assumes that
// if pretty-printing, we're already on a new line. Also assumes that key is
// appropriately escaped if it contains invalid characters.
bool OutputKey(FILE* file, const char* key, int indent, bool pretty_print) {
  DCHECK(file != NULL);
  DCHECK(key != NULL);
  return OutputIndent(file, indent, pretty_print) &&
      fprintf(file, "\"%s\":", key) >= 0 &&
      OutputIndent(file, 1, pretty_print);
}

// Outputs a SyzygyVersion object in JSON format as a dictionary. Does not
// output a newline after the dictionary.
bool OutputSyzygyVersion(FILE* file,
                         const common::SyzygyVersion& version,
                         int indent,
                         bool pretty_print) {
  DCHECK(file != NULL);

  std::string comment("Toolchain version: ");
  comment.append(version.GetVersionString());

  std::string last_change = base::GetDoubleQuotedJson(version.last_change());

  return OutputText(file, "{", 0, pretty_print) &&
      OutputLineEnd(file, pretty_print) &&
      OutputComment(file, comment.c_str(), indent + 2, pretty_print) &&
      OutputKey(file, kMajorKey, indent + 2, pretty_print) &&
      fprintf(file, "%d,", version.major()) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kMinorKey, indent + 2, pretty_print) &&
      fprintf(file, "%d,", version.minor()) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kBuildKey, indent + 2, pretty_print) &&
      fprintf(file, "%d,", version.build()) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kPatchKey, indent + 2, pretty_print) &&
      fprintf(file, "%d,", version.patch()) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kLastChangeKey, indent + 2, pretty_print) &&
      fprintf(file, "%s", last_change.c_str()) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputText(file, "}", indent, pretty_print);
}

// Outputs a PEFile::Signature in JSON format as a dictionary. Does not output
// a newline after the dictionary.
bool OutputPEFileSignature(FILE* file,
                           const PEFile::Signature& signature,
                           int indent,
                           bool pretty_print) {
  DCHECK(file != NULL);

  std::string path;
  WideToUTF8(signature.path.c_str(), signature.path.size(), &path);
  path = base::GetDoubleQuotedJson(path);

  return OutputText(file, "{", 0, pretty_print) &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kPathKey, indent + 2, pretty_print) &&
      fprintf(file, "%s,", path.c_str()) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kBaseAddressKey, indent + 2, pretty_print) &&
      fprintf(file, "%d,", signature.base_address) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kModuleSizeKey, indent + 2, pretty_print) &&
      fprintf(file, "%d,", signature.module_size) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kModuleTimeDateStampKey, indent + 2, pretty_print) &&
      fprintf(file, "\"0x%llx\",", signature.module_time_date_stamp) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kModuleChecksumKey, indent + 2, pretty_print) &&
      fprintf(file, "\"0x%x\"", signature.module_checksum) >= 0 &&
      OutputLineEnd(file, pretty_print) &&
      OutputText(file, "}", indent, pretty_print);
}

// Loads a syzygy version from a JSON dictionary.
bool LoadSyzygyVersion(const DictionaryValue& dictionary,
                       common::SyzygyVersion* version) {
  DCHECK(version != NULL);

  int major = 0;
  int minor = 0;
  int build = 0;
  int patch = 0;
  std::string last_change;
  if (!dictionary.GetInteger(kMajorKey, &major) ||
      !dictionary.GetInteger(kMinorKey, &minor) ||
      !dictionary.GetInteger(kBuildKey, &build) ||
      !dictionary.GetInteger(kPatchKey, &patch) ||
      !dictionary.GetString(kLastChangeKey, &last_change)) {
    LOG(ERROR) << "Unable to parse SyzygyVersion from JSON dictionary.";
    return false;
  }

  version->set_major(major);
  version->set_minor(minor);
  version->set_build(build);
  version->set_patch(patch);
  version->set_last_change(last_change.c_str());

  return true;
}

// Loads a PEFile::Signature from a JSON dictionary.
bool LoadPEFileSignature(const DictionaryValue& dictionary,
                         PEFile::Signature* signature) {
  DCHECK(signature != NULL);

  std::string path;
  int base_address = 0;
  int module_size = 0;
  std::string stamp;
  std::string checksum;
  Value* value = NULL;
  if (!dictionary.GetString(kPathKey, &path) ||
      !dictionary.GetInteger(kBaseAddressKey, &base_address) ||
      !dictionary.GetInteger(kModuleSizeKey, &module_size) ||
      !dictionary.GetString(kModuleTimeDateStampKey, &stamp) ||
      !dictionary.GetString(kModuleChecksumKey, &checksum)) {
    LOG(ERROR) << "Unable to parse PEFile::Signature from JSON dictionary.";
    return false;
  }

  UTF8ToWide(path.c_str(), path.size(), &signature->path);
  signature->base_address = PEFile::AbsoluteAddress(base_address);
  signature->module_size = module_size;

  char* end = NULL;
  signature->module_time_date_stamp = _strtoui64(stamp.c_str(), &end, 16);
  if (end == stamp.c_str()) {
    LOG(ERROR) << "Unable to parse " << kModuleTimeDateStampKey << ".";
    return false;
  }

  signature->module_checksum = strtoul(checksum.c_str(), &end, 16);
  if (end == checksum.c_str()) {
    LOG(ERROR) << "Unable to parse " << kModuleChecksumKey << ".";
    return false;
  }

  return true;
}

}  // namespace

Metadata::Metadata() {
}

bool Metadata::Init(const PEFile::Signature& module_signature) {
  // Populate the command line string.
  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);
  if (!WideToUTF8(cmd_line->command_line_string().c_str(),
                  cmd_line->command_line_string().size(),
                  &command_line_)) {
    LOG(ERROR) << "Unable to convert command-line to UTF8.";
    return false;
  }

  // Set the remaining properties.
  creation_time_ = base::Time::Now();
  toolchain_version_ = common::kSyzygyVersion;
  module_signature_ = module_signature;

  return true;
}

bool Metadata::IsConsistent(const PEFile::Signature& module_signature) const {
  if (!common::kSyzygyVersion.IsCompatible(toolchain_version_)) {
    LOG(ERROR) << "Metadata is not compatible with current toolchain version.";
    return false;
  }

  if (!module_signature.IsConsistent(module_signature_)) {
    LOG(ERROR) << "Metadata is not consistent with input module.";
    return false;
  }

  return true;
}

bool Metadata::SaveToJSON(FILE* file, int indent, bool pretty_print) const {
  std::string command_line = base::GetDoubleQuotedJson(command_line_);
  std::string creation_time =
      base::GetDoubleQuotedJson(TimeToString(creation_time_));

  return OutputText(file, "{", 0, pretty_print) &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kCommandLineKey, indent + 2, pretty_print) &&
      OutputText(file, command_line.c_str(), 0, pretty_print) &&
      OutputText(file, ",", 0, pretty_print) &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kCreationTimeKey, indent + 2, pretty_print) &&
      OutputText(file, creation_time.c_str(), 0, pretty_print) &&
      OutputText(file, ",", 0, pretty_print) &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kToolchainVersionKey, indent + 2, pretty_print) &&
      OutputSyzygyVersion(file, toolchain_version_, indent + 2, pretty_print) &&
      OutputText(file, ",", 0, pretty_print) &&
      OutputLineEnd(file, pretty_print) &&
      OutputKey(file, kModuleSignatureKey, indent + 2, pretty_print) &&
      OutputPEFileSignature(
          file, module_signature_, indent + 2, pretty_print) &&
      OutputLineEnd(file, pretty_print) &&
      OutputText(file, "}", indent, pretty_print);
}

bool Metadata::LoadFromJSON(const DictionaryValue& metadata) {
  std::string creation_time;
  DictionaryValue* toolchain_version_dict = NULL;
  DictionaryValue* module_signature_dict = NULL;
  if (!metadata.GetString(kCommandLineKey, &command_line_) ||
      !metadata.GetString(kCreationTimeKey, &creation_time) ||
      !metadata.GetDictionary(kToolchainVersionKey, &toolchain_version_dict) ||
      !metadata.GetDictionary(kModuleSignatureKey, &module_signature_dict)) {
    LOG(ERROR) << "Unable to parse metadata.";
    return false;
  }

  if (!LoadSyzygyVersion(*toolchain_version_dict, &toolchain_version_) ||
      !LoadPEFileSignature(*module_signature_dict, &module_signature_))
    return false;

  // Parse the creation time from its string representation.
  return StringToTime(creation_time, &creation_time_);
}

bool Metadata::SaveToPE(PEFileBuilder* pe_file_builder) const {
  RelativeAddress start = pe_file_builder->next_section_address();
  RelativeAddress insert_at = start;

  // Serialize the metadata to a ByteVector.
  core::ByteVector bytes;
  core::ScopedOutStreamPtr out_stream;
  out_stream.reset(core::CreateByteOutStream(std::back_inserter(bytes)));
  core::NativeBinaryOutArchive out_archive(out_stream.get());
  out_archive.Save(*this);

  // Output some of the information in duplicate, in a human-readable form, so
  // that we can easily grep for this stuff in the actual binaries.
  std::string path;
  if (!WideToUTF8(module_signature_.path.c_str(),
                  module_signature_.path.size(),
                  &path)) {
    LOG(ERROR) << "Unable to convert module path to UTF8.";
    return false;
  }
  std::string text("Command-line: ");
  text.append(command_line_);
  text.append("\nCreation time: ");
  text.append(TimeToString(creation_time_));
  text.append("\nToolchain version: ");
  text.append(toolchain_version_.GetVersionString());
  text.append("\nModule path: ");
  text.append(path);
  text.append("\n");
  out_archive.Save(text);

  // Stuff the metadata into the address space.
  BlockGraph::Block* new_block =
      pe_file_builder->address_space().AddBlock(BlockGraph::DATA_BLOCK,
                                                insert_at,
                                                bytes.size(),
                                                "Metadata");
  if (new_block == NULL) {
    LOG(ERROR) << "Unable to allocate metadata block.";
    return false;
  }
  insert_at += bytes.size();
  new_block->set_data_size(bytes.size());
  new_block->CopyData(bytes.size(), &bytes[0]);

  // Wrap this data in a read-only data section.
  uint32 syzygy_size = insert_at - start;
  pe_file_builder->AddSegment(common::kSyzygyMetadataSectionName,
                              syzygy_size,
                              syzygy_size,
                              IMAGE_SCN_CNT_INITIALIZED_DATA |
                              IMAGE_SCN_CNT_UNINITIALIZED_DATA);

  return true;
}

bool Metadata::LoadFromPE(const PEFile& pe_file) {
  // Get the metadata section data.
  size_t metadata_id =
      pe_file.GetSectionIndex(common::kSyzygyMetadataSectionName);
  if (metadata_id == pe::kInvalidSection) {
    LOG(ERROR) << "Module does not contain a metadata section.";
    return false;
  }
  const IMAGE_SECTION_HEADER* section = pe_file.section_header(metadata_id);
  DCHECK(section != NULL);
  RelativeAddress metadata_addr(section->VirtualAddress);
  size_t metadata_size = section->Misc.VirtualSize;
  const core::Byte* metadata = pe_file.GetImageData(metadata_addr,
                                                    metadata_size);
  if (metadata == NULL) {
    LOG(ERROR) << "Unable to get metadata section data.";
    return false;
  }

  // Parse the metadata.
  core::ScopedInStreamPtr in_stream;
  in_stream.reset(core::CreateByteInStream(metadata, metadata + metadata_size));
  core::NativeBinaryInArchive in_archive(in_stream.get());
  if (!in_archive.Load(this)) {
    LOG(ERROR) << "Unable to parse module metadata.";
    return false;
  }

  return true;
}

bool Metadata::operator==(const Metadata& rhs) const {
  return command_line_ == rhs.command_line_ &&
      creation_time_ == rhs.creation_time_ &&
      toolchain_version_ == rhs.toolchain_version_ &&
      module_signature_ == rhs.module_signature_;
}

}  // namespace pe
