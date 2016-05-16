// Copyright 2016 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/asan/reporters/kasko_reporter.h"

#include "base/file_version_info.h"
#include "base/path_service.h"
#include "base/version.h"
#include "base/files/file_path.h"
#include "base/strings/string_util.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/kasko/api/client.h"

namespace agent {
namespace asan {

static_assert(kasko::api::kProtobufStreamType ==
    ReporterInterface::kCrashdataProtobufStreamType,
    "protobuf stream type id mismatch");

// Define required export names.
const char* reporters::KaskoReporter::ReportCrashWithProtobuf::name_ =
    "ReportCrashWithProtobuf";
const char* reporters::KaskoReporter::
    ReportCrashWithProtobufAndMemoryRanges::name_ =
        "ReportCrashWithProtobufAndMemoryRanges";
const char* reporters::KaskoReporter:: SetCrashKeyValueImpl::name_ =
    "SetCrashKeyValueImpl";

namespace reporters {

// static
std::unique_ptr<KaskoReporter> KaskoReporter::Create() {
  // Initialize the required reporter functions
  KaskoFunctions kasko_functions;
  kasko_functions.set_crash_key_value_impl.Lookup();
  kasko_functions.report_crash_with_protobuf.Lookup();
  kasko_functions.report_crash_with_protobuf_and_memory_ranges.Lookup();
  if (!AreValid(kasko_functions))
    return nullptr;

  return std::unique_ptr<KaskoReporter>(new KaskoReporter(kasko_functions));
}

// static
bool KaskoReporter::AreValid(const KaskoFunctions& kasko_functions) {
  // The crash key function and at least one reporting function must be
  // present.
  if (!kasko_functions.set_crash_key_value_impl.IsValid())
    return false;
  return (kasko_functions.report_crash_with_protobuf.IsValid() ||
      kasko_functions.report_crash_with_protobuf_and_memory_ranges.IsValid());
}

const char* KaskoReporter::GetName() const {
  return "KaskoReporter";
}

uint32_t KaskoReporter::GetFeatures() const {
  uint32_t features = FEATURE_CRASH_KEYS | FEATURE_CUSTOM_STREAMS;
  if (kasko_functions_.report_crash_with_protobuf_and_memory_ranges.IsValid())
    features |= FEATURE_MEMORY_RANGES;
  if (SupportsEarlyCrashKeys())
    features |= FEATURE_EARLY_CRASH_KEYS;
  return features;
}

bool KaskoReporter::SetCrashKey(base::StringPiece key,
                                base::StringPiece value) {
  DCHECK(kasko_functions_.set_crash_key_value_impl.IsValid());

  std::wstring wkey = base::UTF8ToWide(key);
  std::wstring wvalue = base::UTF8ToWide(value);
  kasko_functions_.set_crash_key_value_impl.Run(wkey.c_str(), wvalue.c_str());
  return true;
}

bool KaskoReporter::SetMemoryRanges(const MemoryRanges& memory_ranges) {
  // This is only supported if the appropriate reporting function was found.
  if (!kasko_functions_.report_crash_with_protobuf_and_memory_ranges.IsValid())
    return false;

  // Convert the memory ranges to the null terminated format Kasko expects.
  range_bases_.resize(memory_ranges.size() + 1);
  range_lengths_.resize(memory_ranges.size() + 1);
  for (size_t i = 0; i < memory_ranges.size(); ++i) {
    range_bases_[i] = memory_ranges[i].first;
    range_lengths_[i] = memory_ranges[i].second;
  }
  range_bases_.back() = nullptr;
  range_lengths_.back() = 0;
  return true;
}

bool KaskoReporter::SetCustomStream(uint32_t stream_type,
                                    const uint8_t* stream_data,
                                    size_t stream_length) {
  // Only support setting the Kasko stream type.
  if (stream_type != kCrashdataProtobufStreamType)
    return false;
  protobuf_.assign(reinterpret_cast<const char*>(stream_data), stream_length);
  return true;
}

// Crashes the running process and sends a crash report.
void KaskoReporter::DumpAndCrash(EXCEPTION_POINTERS* exception_pointers) {
  // Prefer to use the memory ranges version.
  if (kasko_functions_.report_crash_with_protobuf_and_memory_ranges.IsValid()) {
      kasko_functions_.report_crash_with_protobuf_and_memory_ranges.Run(
          exception_pointers, protobuf_.c_str(), protobuf_.size(),
          range_bases_.data(), range_lengths_.data());
  } else {
    DCHECK(kasko_functions_.report_crash_with_protobuf.IsValid());
    kasko_functions_.report_crash_with_protobuf.Run(
        exception_pointers, protobuf_.c_str(), protobuf_.size());
  }

  // The crash function shouldn't return, but putting a NOTREACHED here makes
  // this function difficult to test.
}

bool KaskoReporter::DumpWithoutCrash(const CONTEXT& context) {
  // This functionality is not supported in Kasko.
  return false;
}

// static
bool KaskoReporter::SupportsEarlyCrashKeys() {
  // Whether or not this is safe to do is really dependent on the crash key
  // system as implemented in a given binary. Kasko doesn't provide its own,
  // but rather relies on that provided by the instrumented binary itself.
  // Binaries need to be evaluated individually and added to this whitelist
  // explicitly if early crash key support is required.
  //
  // This whole thing becomes a moot point when using Crashpad, as it provides
  // a uniform and safe early crash key mechanism. Moving forward, all Chromium
  // projects will be using it.

  // The process needs to be an instance of "chrome.exe".
  base::FilePath path;
  if (!PathService::Get(base::FILE_EXE, &path))
    return false;
  if (!base::EqualsCaseInsensitiveASCII(path.BaseName().value(),
                                        L"chrome.exe")) {
    return false;
  }

  std::unique_ptr<FileVersionInfo> version_info(
      FileVersionInfo::CreateFileVersionInfo(path));
  if (!version_info.get())
    return false;

  // The version string may have the format "0.1.2.3 (baadf00d)". The
  // revision hash must be stripped in order to use base::Version.
  std::string v = base::WideToUTF8(version_info->product_version());
  size_t offset = v.find_first_not_of("0123456789.");
  if (offset != v.npos)
    v.resize(offset);

  // Ensure the version is sufficiently new. Prior to M36 the crashkey
  // implementation used a structure that wasn't ready or safe to use before
  // all initializers had run. Afterwards it uses a global static structure so
  // crash key writing early on is safe.
  base::Version version(v);
  if (!version.IsValid())
    return false;
  if (version < base::Version("36.0.0.0"))
    return false;

  return true;
}

}  // namespace reporters
}  // namespace asan
}  // namespace agent
