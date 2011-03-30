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
//
// The logic and some lifting for report entries.
#include "sawdust/app/report.h"

#include <istream>  // NOLINT - streams used as abstracts, without formatting.
#include <fstream>  // NOLINT
#include "base/file_path.h"
#include "base/file_util.h"
#include "base/logging.h"
#include "base/scoped_ptr.h"

namespace {

const char kChromeUploadTitle[] = "Application.etl";
const char kKernelUploadTitle[] = "Kernel.etl";

class FileEntry : public ReportContent::ReportEntryWithInit {
 public:
  FileEntry(const FilePath& file, const char * title)
      : file_path_(file), public_title_(title), marked_ok_(false) {
  }

  ~FileEntry() {
    if (stream_.is_open())
      stream_.close();
    if (marked_ok_ && file_util::PathExists(file_path_))
      file_util::Delete(file_path_, false);
  }

  // Initialization simply means: open the file.
  HRESULT Initialize() {
    stream_.open(file_path_.value().c_str(),
                 std::ios_base::in | std::ios_base::binary);
    return stream_.bad() ? E_ACCESSDENIED : S_OK;
  }

  std::istream& Data() { return stream_; }  // Override (IReportContentEntry).
  const char* Title() const { return public_title_.c_str(); }

  void MarkCompleted() {
    marked_ok_ = true;
  }

 private:
  std::ifstream stream_;
  FilePath file_path_;
  std::string public_title_;
  bool marked_ok_;
};

class RegistryEntry : public ReportContent::ReportEntryWithInit {
 public:
  explicit RegistryEntry(const std::vector<std::wstring>& all_entries,
                         RegistryExtractor* extractor_instance)
      : data_(all_entries), reg_data_proc_(extractor_instance) {
    DCHECK(!all_entries.empty());
  }

  HRESULT Initialize() {
    int inserted_items = reg_data_proc_->Initialize(data_);
    return inserted_items > 0 ? S_OK : S_FALSE;
  }

  std::istream& Data() { return reg_data_proc_->Data(); }
  const char* Title() const { return reg_data_proc_->Title(); }

  void MarkCompleted() {
    reg_data_proc_->MarkCompleted();
  }

 private:
  std::vector<std::wstring> data_;
  scoped_ptr<RegistryExtractor> reg_data_proc_;
};

class BaseSystemInfoEntry : public ReportContent::ReportEntryWithInit {
 public:
  explicit BaseSystemInfoEntry(const TracerConfiguration& config,
                               SystemInfoExtractor* extractor_instance)
      : harvest_env_vars_(config.HarvestEnvVariables()),
        info_extractor_(extractor_instance)  {
  }

  HRESULT Initialize() {
    info_extractor_->Initialize(harvest_env_vars_);
    return S_OK;
  }

  std::istream& Data() { return info_extractor_->Data(); }
  const char * Title() const { return info_extractor_->Title(); }

  void MarkCompleted() {
    info_extractor_->MarkCompleted();
  }

 private:
  scoped_ptr<SystemInfoExtractor> info_extractor_;
  bool harvest_env_vars_;
};

}  // namespace

ReportContent::~ReportContent() {
  while (!entry_queue_.empty()) {
    delete entry_queue_.front();
    entry_queue_.pop_front();
  }
}

HRESULT ReportContent::Initialize(const TracerController& controller,
                                  const TracerConfiguration& config) {
  FilePath source_file_path;

  if (!controller.GetCompletedEventLogFileName(&source_file_path)) {
    LOG(ERROR) << "No data to upload. Weird.";
    return E_FAIL;
  }
  entry_queue_.push_back(new FileEntry(source_file_path, kChromeUploadTitle));

  if (config.IsKernelLoggingEnabled()) {
    if (controller.GetCompletedKernelEventLogFileName(&source_file_path)) {
      entry_queue_.push_back(new FileEntry(source_file_path,
                                           kKernelUploadTitle));
    } else {
      // Even though this is a failure, we will just pretend it is OK.
      // Better to upload something than nothing at all.
      LOG(ERROR) << "Kernel log requested but not found!";
    }
  }

  std::vector<std::wstring> registry_keys;
  if (config.GetRegistryQuery(&registry_keys) && !registry_keys.empty()) {
    entry_queue_.push_back(new RegistryEntry(registry_keys,
                                             CreateRegistryExtractor()));
  }

  entry_queue_.push_back(new BaseSystemInfoEntry(config,
                                                 CreateInfoExtractor()));

  return S_OK;
}

HRESULT ReportContent::GetNextEntry(IReportContentEntry** entry) {
  DCHECK(entry != NULL);
  HRESULT hr = S_OK;
  current_entry_.reset();
  if (entry_queue_.empty()) {
    hr = S_FALSE;
  } else {
    current_entry_.reset(entry_queue_.front());
    entry_queue_.pop_front();
    // If initialization fails, the error will percolate all the way up.
    hr = current_entry_->Initialize();
  }

  if (SUCCEEDED(hr) && entry != NULL)
    *entry = current_entry_.get();

  return hr;
}
