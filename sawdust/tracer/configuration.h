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
// Configuration of the tracer (event sources, upload target and so on).
#ifndef SAWDUST_TRACER_CONFIGURATION_H_
#define SAWDUST_TRACER_CONFIGURATION_H_

#include <list>
#include <map>
#include <string>
#include <vector>

#include "base/file_path.h"
#include "base/scoped_ptr.h"
#include "base/values.h"
#include "base/version.h"
#include "base/win/event_trace_provider.h"

// Reads complete configuration data (for the entire mechanism, including
// tracing, config data harvesting and upload) from a json file. Verifies data
// and exposes settings through the public interface.
class TracerConfiguration {
 public:
  // Describes an ETW provider we might listen to.
  struct ProviderSettings {
    // The provider's GUID
    GUID provider_guid;
    // The provider's name.
    std::string provider_name;
    // The current log level.
    base::win::EtwEventLevel log_level;
    // The current enable flags.
    base::win::EtwEventFlags enable_flags;
  };

  typedef std::list<ProviderSettings> ProviderDefinitions;

  enum ExitAction {
    REPORT_ASK = 0,  // Ask user if the default action should be taken.
    REPORT_NONE,  // Do nothing, just stop logging and quit.
    REPORT_CLEAR,  // Wipe data out before quiting.
    REPORT_AUTO,  // Don't ask, just upload.
    LAST_REPORT_TYPE  // Last. Do not use except as a stop.
  };

  static const char kAppKey[];
  static const char kModuleKey[];
  static const char kVersionKey[];
  static const char kVersionKeyKey[];

  TracerConfiguration();
  virtual ~TracerConfiguration() {}

  // Initialize the object with a json string, presumably read from a text file.
  bool Initialize(const std::string& json, const FilePath& op_directory_root,
                  std::string* error_message_out);

  // Providers to initialize.
  const ProviderDefinitions& settings() const {
    return provider_defs_;
  }

  // Should kernel events be logged, too.
  bool IsKernelLoggingEnabled() const {
    return trace_kernel_on_;
  }

  unsigned GetLogFileSizeCapMb() const {
    return max_chrome_file_size_;
  }

  unsigned GetKernelLogFileSizeCapMb() const {
    return max_kernel_file_size_;
  }

  // These functions yield a file name to use. There is no guarantee you will
  // get the same path next time you call, that may depend on other settings.
  bool GetLogFileName(FilePath* return_path) const;
  bool GetKernelLogFileName(FilePath* return_path) const;

  // Application name, provided in configuration JSON to help classify uploads.
  bool GetTracedApplication(std::wstring* app_name) const;

  // Version as declared in JSON or retrieved from the registry. Note that this
  // may not match of the executable that was snooped upon.
  Version* GetDeclaredApplicationVersion() const;

  // Return a word from the arbitrary parameter bag under report\parameters.
  // See constants below for 'standard vocabulary'.
  bool GetParameterWord(const std::string& key, std::wstring* the_word) const;

  // Where to upload the file.
  bool GetUploadPath(std::wstring* upload_url, bool* assume_remote) const;
  bool GetUploadPath(const Version& version,
                     std::wstring* upload_url, bool* assume_remote) const;

  ExitAction ActionOnExit() const;

  // Get all requested registry subtrees we should harvest.
  bool GetRegistryQuery(std::vector<std::wstring>* query_keys) const;

  bool HarvestEnvVariables() const { return harvest_env_variables_; }

 protected:
  // Part of initialization. Populates provider_defs_ with values extracted from
  // |providers_node|.
  bool PopulateProvidersTable(Value* providers_node,
                              std::string* error_string_out);
  // Part of initialization. Sets member variables describing the upload
  // procedure.
  bool ExtractUploadInstructions(Value* upload_node,
                                 std::string* error_string_out);
  // Part of initialization. Populates registry_query_ from |registry_node|.
  bool ExtractRegistryKeys(Value* registry_node,
                           std::string* error_string_out);
  // Part of initialization. Sets variables describing desired properties of
  // ETW log files.
  bool ExtractLogSettings(Value* log_node,
                          std::string* error_string_out);

  // Utility function for processing pattern used to describe upload target.
  static bool ExpandBracketPattern(const std::wstring& pattern,
                                   DictionaryValue* dict,
                                   std::wstring* expanded_pattern);
  // Set |target_file| to a good name for a temporary log file (usually not
  // a 'temp file' in the OS sense).
  static bool GetTargetFilePath(const FilePath& dir,
                                const std::wstring& name_pat,
                                FilePath* target_file);
  // Extract a mandatory value (under |key|) from |parent|. Evaluates data type.
  static HRESULT ExtractValue(DictionaryValue* parent, const char* key,
                              Value::ValueType expected_type,
                              std::string* error_out,
                              Value** retrieved_value);
  // Extract an optional value (under |key|) from |parent|. Evaluates data type.
  static HRESULT ExtractOptionalValue(DictionaryValue* parent, const char* key,
                                      Value::ValueType expected_type,
                                      std::string* error_out,
                                      Value** retrieved_value);
 private:
  typedef std::map<std::string, base::win::EtwEventLevel> MapOfLevelNames;
  typedef std::map<std::string, ExitAction> MapOfActionNames;

  void Clear();

  // Test seam.
  virtual bool VerifyLocalTargetPathOK(const std::wstring& file_path) const;

  bool GetRawUploadPath(std::wstring* upload_url, bool* assume_remote) const;
  bool InternalGetExpandedPath(const Version* force_version,
                               std::wstring* upload_url,
                               bool* assume_remote) const;

  static HRESULT InternalExtractValue(DictionaryValue* parent, const char* key,
                                      Value::ValueType expected_type,
                                      std::string* error_out,
                                      Value** retrieved_value);

  ProviderDefinitions provider_defs_;
  FilePath root_in_fs_;

  std::wstring chrome_file_pat_;
  std::wstring kernel_file_pat_;
  bool trace_kernel_on_;
  unsigned max_kernel_file_size_;
  unsigned max_chrome_file_size_;

  bool harvest_env_variables_;

  std::wstring target_url_;
  ExitAction exit_action_;
  scoped_ptr<DictionaryValue> upload_params_;
  scoped_ptr<ListValue> registry_query_;

  static MapOfLevelNames named_levels_;
  static MapOfActionNames named_actions_;

  DISALLOW_COPY_AND_ASSIGN(TracerConfiguration);
};

#endif  // SAWDUST_TRACER_CONFIGURATION_H_
