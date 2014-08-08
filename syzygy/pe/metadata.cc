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

#include "syzygy/pe/metadata.h"

#include <time.h>

#include "base/command_line.h"
#include "base/values.h"
#include "base/json/json_reader.h"
#include "base/json/string_escape.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/defs.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/pe/pe_utils.h"

namespace pe {

using base::DictionaryValue;
using block_graph::BlockGraph;
using core::RelativeAddress;

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
  return Time::FromString(string.c_str(), time);
}

// Outputs a SyzygyVersion object in JSON format as a dictionary. Does not
// output a newline after the dictionary.
bool OutputSyzygyVersion(const common::SyzygyVersion& version,
                         core::JSONFileWriter* json_file) {
  DCHECK(json_file != NULL);

  if (!json_file->OpenDict())
    return false;

  if (json_file->pretty_print()) {
    std::string comment("Toolchain version: ");
    comment.append(version.GetVersionString());
    if (!json_file->OutputComment(comment))
      return false;
  }

  return json_file->OutputKey(kMajorKey) &&
      json_file->OutputInteger(version.major()) &&
      json_file->OutputKey(kMinorKey) &&
      json_file->OutputInteger(version.minor()) &&
      json_file->OutputKey(kBuildKey) &&
      json_file->OutputInteger(version.build()) &&
      json_file->OutputKey(kPatchKey) &&
      json_file->OutputInteger(version.patch()) &&
      json_file->OutputKey(kLastChangeKey) &&
      json_file->OutputString(version.last_change()) &&
      json_file->CloseDict();
}

// Outputs a PEFile::Signature in JSON format as a dictionary. Does not output
// a newline after the dictionary.
bool OutputPEFileSignature(const PEFile::Signature& signature,
                           core::JSONFileWriter* json_file) {
  DCHECK(json_file != NULL);

  std::string path;
  base::WideToUTF8(signature.path.c_str(), signature.path.size(), &path);
  path = base::GetQuotedJSONString(path);

  std::string time_stamp(
      base::StringPrintf("0x%llX", signature.module_time_date_stamp));
  std::string checksum(base::StringPrintf("0x%X", signature.module_checksum));

  return json_file->OpenDict() &&
      json_file->OutputKey(kPathKey) &&
      json_file->OutputString(signature.path) &&
      json_file->OutputKey(kBaseAddressKey) &&
      json_file->OutputInteger(signature.base_address.value()) &&
      json_file->OutputKey(kModuleSizeKey) &&
      json_file->OutputInteger(signature.module_size) &&
      json_file->OutputKey(kModuleTimeDateStampKey) &&
      json_file->OutputString(time_stamp) &&
      json_file->OutputKey(kModuleChecksumKey) &&
      json_file->OutputString(checksum) &&
      json_file->CloseDict();
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
  if (!dictionary.GetString(kPathKey, &path) ||
      !dictionary.GetInteger(kBaseAddressKey, &base_address) ||
      !dictionary.GetInteger(kModuleSizeKey, &module_size) ||
      !dictionary.GetString(kModuleTimeDateStampKey, &stamp) ||
      !dictionary.GetString(kModuleChecksumKey, &checksum)) {
    LOG(ERROR) << "Unable to parse PEFile::Signature from JSON dictionary.";
    return false;
  }

  base::UTF8ToWide(path.c_str(), path.size(), &signature->path);
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
  if (!base::WideToUTF8(cmd_line->GetCommandLineString().c_str(),
                  cmd_line->GetCommandLineString().size(),
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

bool Metadata::SaveToJSON(core::JSONFileWriter* json_file) const {
  DCHECK(json_file != NULL);

  return json_file->OpenDict() &&
      json_file->OutputKey(kCommandLineKey) &&
      json_file->OutputString(command_line_) &&
      json_file->OutputKey(kCreationTimeKey) &&
      json_file->OutputString(TimeToString(creation_time_)) &&
      json_file->OutputKey(kToolchainVersionKey) &&
      OutputSyzygyVersion(toolchain_version_, json_file) &&
      json_file->OutputKey(kModuleSignatureKey) &&
      OutputPEFileSignature(module_signature_, json_file) &&
      json_file->CloseDict();
}

bool Metadata::LoadFromJSON(const DictionaryValue& metadata) {
  std::string creation_time;
  const DictionaryValue* toolchain_version_dict = NULL;
  const DictionaryValue* module_signature_dict = NULL;
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

bool Metadata::SaveToBlock(BlockGraph::Block* block) const {
  // Serialize the metadata to a ByteVector.
  core::ByteVector bytes;
  core::ScopedOutStreamPtr out_stream;
  out_stream.reset(core::CreateByteOutStream(std::back_inserter(bytes)));
  core::NativeBinaryOutArchive out_archive(out_stream.get());
  if (!out_archive.Save(*this))
    return false;

  // Output some of the information in duplicate, in a human-readable form, so
  // that we can easily grep for this stuff in the actual binaries.
  std::string path;
  if (!base::WideToUTF8(module_signature_.path.c_str(),
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
  if (!out_archive.Save(text))
    return false;
  if (!out_archive.Flush())
    return false;

  block->SetData(NULL, 0);
  block->set_size(bytes.size());
  if (block->CopyData(bytes.size(), &bytes[0]) == NULL) {
    LOG(ERROR) << "Unable to allocate metadata.";
    return false;
  }

  return true;
}

bool Metadata::LoadFromBlock(const BlockGraph::Block* block) {
  // Parse the metadata.
  core::ScopedInStreamPtr in_stream;
  in_stream.reset(core::CreateByteInStream(block->data(),
                                           block->data() + block->data_size()));
  core::NativeBinaryInArchive in_archive(in_stream.get());
  if (!in_archive.Load(this)) {
    LOG(ERROR) << "Unable to parse module metadata.";
    return false;
  }

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

// Serialization 'Save' implementation.
bool Metadata::Save(core::OutArchive* out_archive) const {
  DCHECK(out_archive != NULL);
  return out_archive->Save(command_line_) &&
      out_archive->Save(creation_time_) &&
      out_archive->Save(toolchain_version_) &&
      out_archive->Save(module_signature_);
}

// Serialization 'Load' implementation.
bool Metadata::Load(core::InArchive* in_archive) {
  DCHECK(in_archive != NULL);
  return in_archive->Load(&command_line_) &&
      in_archive->Load(&creation_time_) &&
      in_archive->Load(&toolchain_version_) &&
      in_archive->Load(&module_signature_);
}

}  // namespace pe
