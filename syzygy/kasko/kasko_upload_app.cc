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

#include "syzygy/kasko/kasko_upload_app.h"

#include "base/bind.h"
#include "base/files/file_util.h"
#include "syzygy/kasko/crash_keys_serialization.h"
#include "syzygy/kasko/reporter.h"

namespace kasko {

namespace {

// URL of the default crash handler.
#define KASKO_DEFAULT_UPLOAD_URL "https://clients2.google.com/cr/report"

const char kUsageFormatStr[] =
    "Usage: %ls --minidump=<MINIDUMP> [options]\n"
    "\n"
    "  A tool that uploads minidumps and crashkeys to a crash server.\n"
    "\n"
    "Required parameters\n"
    "  --minidump=<MINIDUMP>"
    "    Path to the minidump file to upload.\n"
    "\n"
    "Optional parameters\n"
    "  --crash-keys=<CRASHKEYS>\n"
    "    Path to the JSON formatted crash keys to upload. Defaults to the\n"
    "    filename obtained by replacing the minidump extension with .kys.\n"
    "  --upload-url=<URL>\n"
    "    URL where the crash should be upload. Defaults to:\n"
    "    " KASKO_DEFAULT_UPLOAD_URL "\n"
    "\n";

// Callback that is invoked upon successful upload.
void OnUploadCallback(
    base::string16* output_report_id,
    const base::string16& report_id,
    const base::FilePath& minidump_path,
    const std::map<base::string16, base::string16>& crash_keys) {
  DCHECK_NE(static_cast<base::string16*>(nullptr), output_report_id);
  *output_report_id = report_id;
}

}  // namespace

#define KASKO_MINIDUMP_SWITCH "minidump"

// A small helper macro for converting an 8-bit char string to a 16-bit char
// string.
#define WIDEN_IMPL(x) L ## x
#define WIDEN(x) WIDEN_IMPL(x)

const char KaskoUploadApp::kMinidumpSwitch[] = KASKO_MINIDUMP_SWITCH;
const char KaskoUploadApp::kCrashKeysSwitch[] = "crash-keys";
const char KaskoUploadApp::kUploadUrlSwitch[] = "upload-url";
const base::char16 KaskoUploadApp::kDefaultUploadUrl[] =
    WIDEN(KASKO_DEFAULT_UPLOAD_URL);

KaskoUploadApp::KaskoUploadApp()
    : application::AppImplBase("Kasko Upload") {
}

bool KaskoUploadApp::ParseCommandLine(const base::CommandLine* command_line) {
  DCHECK_NE(static_cast<base::CommandLine*>(nullptr), command_line);

  if (!command_line->HasSwitch(kMinidumpSwitch)) {
    PrintUsage(command_line->GetProgram(),
               "You must specify --" KASKO_MINIDUMP_SWITCH ".");
    return false;
  }

  minidump_path_ = command_line->GetSwitchValuePath(kMinidumpSwitch);
  LOG(INFO) << "Using minidump path: " << minidump_path_.value();

  if (command_line->HasSwitch(kCrashKeysSwitch)) {
    crash_keys_path_ = command_line->GetSwitchValuePath(kCrashKeysSwitch);
    LOG(INFO) << "Using crash-keys path: " << crash_keys_path_.value();
  } else {
    crash_keys_path_ = minidump_path_.ReplaceExtension(L".kys");
    LOG(INFO) << "Using default crash-keys path: " << crash_keys_path_.value();
  }

  if (command_line->HasSwitch(kUploadUrlSwitch)) {
    upload_url_ = command_line->GetSwitchValueNative(kUploadUrlSwitch);
    LOG(INFO) << "Using upload URL: " << upload_url_;
  } else {
    upload_url_ = kDefaultUploadUrl;
    LOG(INFO) << "Using default upload URL: " << upload_url_;
  }

  return true;
}

int KaskoUploadApp::Run() {
  if (!base::PathExists(crash_keys_path_)) {
    LOG(ERROR) << "Crash keys file not found: " << crash_keys_path_.value();
    return kReturnCodeCrashKeysFileMissing;
  }

  std::map<base::string16, base::string16> crash_keys;
  if (!ReadCrashKeysFromFile(crash_keys_path_, &crash_keys)) {
    LOG(ERROR) << "Failed to read crash keys from file: "
               << crash_keys_path_.value();
    return kReturnCodeCrashKeysFileMalformed;
  }

  for (const auto& kv : crash_keys) {
    LOG(INFO) << "Read crash key \"" << kv.first << "\": \"" << kv.second
              << "\"";
  }

  // Ensure that the minimum set of necessary crash keys is present.
  static const base::char16* kRequiredCrashKeys[] = {
    L"prod", L"ver", L"platform", L"ptype", L"guid", L"channel" };
  size_t missing_keys = 0;
  for (size_t i = 0; i < arraysize(kRequiredCrashKeys); ++i) {
    if (crash_keys.count(kRequiredCrashKeys[i]) == 0) {
      ++missing_keys;
      LOG(ERROR) << "Missing required crash key \"" << kRequiredCrashKeys[i]
                 << "\".";
    }
  }
  if (missing_keys > 0)
    return kReturnCodeCrashKeysAbsent;

  if (!base::PathExists(minidump_path_)) {
    LOG(ERROR) << "Minidump file not found: " << minidump_path_.value();
    return kReturnCodeMinidumpFileMissing;
  }

  base::string16 report_id;
  Reporter::OnUploadCallback on_upload = base::Bind(
      &OnUploadCallback, base::Unretained(&report_id));
  if (!Reporter::UploadCrashReport(on_upload, upload_url_, minidump_path_,
                                   crash_keys)) {
    LOG(ERROR) << "Failed to upload crash report.";
    return kReturnCodeUploadFailed;
  }

  LOG(INFO) << "Report successfully uploaded with report ID: " << report_id;
  return kReturnCodeSuccess;
}

void KaskoUploadApp::PrintUsage(const base::FilePath& program,
                                const base::StringPiece& message) {

  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());
}

}  // namespace kasko
