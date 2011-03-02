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
// Configuration reader for sawbuck (reads from a JSON string).
#include "sawdust/tracer/configuration.h"

#include <Objbase.h>
#include <algorithm>

#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/logging.h"
#include "base/string_split.h"
#include "base/string_util.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/win/registry.h"
#include "googleurl/src/gurl.h"

namespace {
const char kProvidersKey[] = "providers";
const char kUploadKey[] = "report";
const char kRegistryEntriesKey[] = "registry-harvest";
const char kSettingsKey[] = "other";

const char kGuidKey[] = "guid";
const char kNameKey[] = "name";
const char kLevelKey[] = "level";
const char kFlagsKey[] = "flags";

const char kKernelOn[] = "kernel_trace";
const char kKernelFile[] = "kernel_event_file";
const char kChromeFile[] = "chrome_event_file";
const char kKernelFileSize[] = "kernel_file_size";
const char kChromeFileSize[] = "chrome_file_size";
const char kHarvestEnvVars[] = "get_environment_strings";

const char kTargetKey[] = "target";
const char kOnExitKey[] = "exit_handler";

const char kOtherParametersKey[] = "parameters";
const wchar_t kDefaultAppName[] = L"Chrome";

const char kErrorRootType[] =
    "Unexpected JSON parse result: incorrect root type.";
const char kErrorProviderDescriptionFmt[] =
    "Configuration file error: incorrect description of the provider %s.";
const char kErrorWordNotInDictionaryFmt[] =
    "Configuration file error: value \'%s\' not in the dictionary.";
const char kMalformedGUIDFmt[] =
    "Configuration file error: supposed GUID (%S) is incorrect.";
const char kErrorElementTypeFmt[] =
    "Unexpected JSON parse result: incorrect element type (%s).";
const wchar_t kOpenBrace = L'{';
const wchar_t kCloseBrace = L'}';

const unsigned kDefaultFileSize = 15;
const unsigned kMaxFileSize = 250;
const bool kDefaultKernelTraceOn = true;
const bool kDefaultEnvHarvesting = true;
}  // namespace


TracerConfiguration::MapOfLevelNames TracerConfiguration::named_levels_;
TracerConfiguration::MapOfActionNames TracerConfiguration::named_actions_;

const char TracerConfiguration::kAppKey[] = "prod";
const char TracerConfiguration::kModuleKey[] = "module";
const char TracerConfiguration::kVersionKey[] = "version";
const char TracerConfiguration::kVersionKeyKey[] = "version_regkey";

TracerConfiguration::TracerConfiguration()
    : trace_kernel_on_(kDefaultKernelTraceOn),
      max_kernel_file_size_(kDefaultFileSize),
      max_chrome_file_size_(kDefaultFileSize),
      exit_action_(REPORT_ASK),
      harvest_env_variables_(kDefaultEnvHarvesting) {
  if (named_levels_.empty()) {
    named_levels_["verbose"] = TRACE_LEVEL_VERBOSE;
    named_levels_["information"] = TRACE_LEVEL_INFORMATION;
    named_levels_["warning"] = TRACE_LEVEL_WARNING;
    named_levels_["error"] = TRACE_LEVEL_ERROR;
    named_levels_["critical"] = TRACE_LEVEL_CRITICAL;
  }

  if (named_actions_.empty()) {
    named_actions_[""] = REPORT_ASK;
    named_actions_["ask"] = REPORT_ASK;
    named_actions_["none"] = REPORT_NONE;
    named_actions_["clear"] = REPORT_CLEAR;
    named_actions_["auto"] = REPORT_AUTO;
  }
}

// Initializes the object from a given JSON formatted string, returns false on
// failure, true otherwise. Some variables (file paths) may be given as
// non-absolute in the config string. All non-absolute paths will be considered
// as if they were relative to the given target_directory.
bool TracerConfiguration::Initialize(const std::string& json,
                                     const FilePath& target_directory,
                                     std::string* error_message_out) {
  Clear();
  std::string json_error;
  int error_code;
  Value* config_data = base::JSONReader::ReadAndReturnError(json, true,
                                                            &error_code,
                                                            &json_error);
  if (config_data == NULL) {
    LOG(WARNING) << "Incorrect configuration data format: (" << error_code <<
        ") " << json_error;
    if (error_message_out != NULL) {
      *error_message_out = "JSON format error: ";
      error_message_out->append(json_error);
    }
    return false;
  }

  if (!config_data->IsType(Value::TYPE_DICTIONARY)) {
    LOG(WARNING) << kErrorRootType;
    if (error_message_out != NULL)
      *error_message_out = kErrorRootType;
    return false;
  }

  // The format has been read OK. Try to make sense of the content now.
  DictionaryValue* config_dictionary =
      static_cast<DictionaryValue*>(config_data);
  Value* child_node = NULL;
  bool return_status = true;
  return_status = return_status &&
                  SUCCEEDED(ExtractValue(config_dictionary, kProvidersKey,
                                         Value::TYPE_LIST, error_message_out,
                                         &child_node)) &&
                  (child_node == NULL ||
                   PopulateProvidersTable(child_node, error_message_out));
  return_status = return_status &&
                  SUCCEEDED(ExtractOptionalValue(config_dictionary, kUploadKey,
                                                 Value::TYPE_DICTIONARY,
                                                 error_message_out,
                                                 &child_node)) &&
                  (child_node == NULL ||
                   ExtractUploadInstructions(child_node, error_message_out));
  return_status = return_status &&
                  SUCCEEDED(ExtractOptionalValue(config_dictionary,
                                                 kRegistryEntriesKey,
                                                 Value::TYPE_LIST,
                                                 error_message_out,
                                                 &child_node)) &&
                  (child_node == NULL ||
                   ExtractRegistryKeys(child_node, error_message_out));
  return_status = return_status &&
                  SUCCEEDED(ExtractOptionalValue(config_dictionary,
                                                 kSettingsKey,
                                                 Value::TYPE_DICTIONARY,
                                                 error_message_out,
                                                 &child_node)) &&
                  (child_node == NULL ||
                   ExtractLogSettings(child_node, error_message_out));

  root_in_fs_ = target_directory;
  return return_status;
}

// Use the list at providers_node to extract all elements.
bool TracerConfiguration::PopulateProvidersTable(Value* providers_node,
    std::string* error_string_out) {
  DCHECK(providers_node != NULL &&
         providers_node->IsType(Value::TYPE_LIST));
  DCHECK(provider_defs_.empty());
  ListValue* providers_list = static_cast<ListValue*>(providers_node);

  for (ListValue::const_iterator it = providers_list->begin();
       it != providers_list->end(); ++it) {
    std::string error_string;
    if (!(*it)->IsType(Value::TYPE_DICTIONARY)) {
      // That's an error.
      base::SStringPrintf(&error_string, kErrorProviderDescriptionFmt,
                          "(wrong element type)");
      LOG(WARNING) << error_string;
      if (error_string_out != NULL)
        *error_string_out = error_string;
      return false;
    }

    DictionaryValue* provider_dict = static_cast<DictionaryValue*>(*it);
    Value* data_value;
    std::string tmp_str, name;
    std::wstring tmp_wstr;
    base::win::EtwEventLevel level = TRACE_LEVEL_INFORMATION;
    base::win::EtwEventFlags flags = 0;
    GUID provider_guid = {};

    if (FAILED(ExtractValue(provider_dict, kGuidKey, Value::TYPE_STRING,
                            error_string_out, &data_value)) ||
        !data_value->GetAsString(&tmp_wstr)) {
      return false;
    } else if (FAILED(::CLSIDFromString(tmp_wstr.c_str(), &provider_guid))) {
      base::SStringPrintf(&error_string, kMalformedGUIDFmt, tmp_wstr.c_str());
      LOG(WARNING) << error_string;
      if (error_string_out != NULL)
        *error_string_out = error_string;
      return false;
    }

    if (FAILED(ExtractOptionalValue(provider_dict, kNameKey, Value::TYPE_STRING,
                                    error_string_out, &data_value)) ||
        (data_value != NULL && !data_value->GetAsString(&name))) {
      return false;
    }

    if (FAILED(ExtractValue(provider_dict, kLevelKey, Value::TYPE_STRING,
                            error_string_out, &data_value)) ||
        !data_value->GetAsString(&tmp_str)) {
        return false;
    } else {
      MapOfLevelNames::const_iterator found_it = named_levels_.find(tmp_str);
      if (found_it != named_levels_.end()) {
        level = found_it->second;
      } else {
        // That's an error.
        base::SStringPrintf(&error_string,
                            kErrorWordNotInDictionaryFmt, tmp_str.c_str());
        LOG(WARNING) << error_string;
        if (error_string_out != NULL)
          *error_string_out = error_string;
        return false;
      }
    }

    int flag_as_int = 0;
    if (FAILED(ExtractValue(provider_dict, kFlagsKey, Value::TYPE_INTEGER,
                            error_string_out, &data_value)) ||
        !data_value->GetAsInteger(&flag_as_int)) {
      return false;
    } else {
      flags = static_cast<base::win::EtwEventFlags>(flag_as_int);
    }

    provider_defs_.push_back(ProviderSettings());
    ProviderSettings& new_definition = provider_defs_.back();
    new_definition.provider_guid = provider_guid;
    new_definition.provider_name = name;
    new_definition.enable_flags = flags;
    new_definition.log_level = level;
  }

  return !provider_defs_.empty();
}

// A part of initialization code. Makes sense of values under "report" key in
// the configuration JSON.
bool TracerConfiguration::ExtractUploadInstructions(Value* upload_node,
    std::string* error_string_out) {
  DCHECK(upload_node != NULL && upload_node->IsType(Value::TYPE_DICTIONARY));
  DictionaryValue* upload_dict = static_cast<DictionaryValue*>(upload_node);

  target_url_.clear();
  exit_action_ = REPORT_ASK;

  Value* param_value = NULL;
  if (SUCCEEDED(ExtractOptionalValue(upload_dict, kTargetKey,
                                     Value::TYPE_STRING, NULL, &param_value)) &&
      param_value != NULL) {
    param_value->GetAsString(&target_url_);
  }

  param_value = NULL;
  if (SUCCEEDED(ExtractOptionalValue(upload_dict, kOnExitKey,
                                     Value::TYPE_STRING, NULL, &param_value)) &&
      param_value != NULL) {
    std::string action_key;
    param_value->GetAsString(&action_key);
    MapOfActionNames::const_iterator found_it = named_actions_.find(action_key);
    if (found_it == named_actions_.end())  {
      base::SStringPrintf(error_string_out, kErrorWordNotInDictionaryFmt,
                          action_key.c_str());
      return false;
    }
    exit_action_ = found_it->second;
  }

  param_value = NULL;
  upload_params_.reset();
  if (SUCCEEDED(ExtractOptionalValue(upload_dict, kOtherParametersKey,
                                     Value::TYPE_DICTIONARY, NULL,
                                     &param_value)) &&
      param_value != NULL) {
    upload_params_.reset(
        static_cast<DictionaryValue*>(param_value)->
            DeepCopyWithoutEmptyChildren());
  }

  return true;
}

// A part of initialization code. Makes sense of values under "registry-harvest"
// key in the configuration JSON.
bool TracerConfiguration::ExtractRegistryKeys(Value* registry_node,
    std::string* error_string_out) {
  // We expect (1) a list (2) populated with strings.
  DCHECK(registry_node != NULL && registry_node->IsType(Value::TYPE_LIST));
  ListValue* registry_list = static_cast<ListValue*>(registry_node);
  for (ListValue::const_iterator vit = registry_list->begin();
       vit != registry_list->end(); ++vit) {
    if (*vit == NULL || !(*vit)->IsType(Value::TYPE_STRING)) {
      if (error_string_out != NULL) {
        base::SStringPrintf(error_string_out,
            kErrorElementTypeFmt, kRegistryEntriesKey);
      }
      return false;
    }
  }
  registry_query_.reset(static_cast<ListValue*>(registry_list->DeepCopy()));
  return true;
}

// Retrieve 'other' (misc) section of the settings string. Errors are pretty
// much ignored (logged) since we will always have 'reasonable defaults'
// for all values and sanitize everything.
bool TracerConfiguration::ExtractLogSettings(Value* log_node,
    std::string* error_string_out) {
  DCHECK(log_node != NULL && log_node->IsType(Value::TYPE_DICTIONARY));
  DictionaryValue* options_dict = static_cast<DictionaryValue*>(log_node);
  chrome_file_pat_.clear();
  kernel_file_pat_.clear();
  trace_kernel_on_ = kDefaultKernelTraceOn;
  max_kernel_file_size_ = kDefaultFileSize;
  max_chrome_file_size_ = kDefaultFileSize;
  harvest_env_variables_ = kDefaultEnvHarvesting;
  std::string error_string;
  Value* param_value = NULL;
  if (SUCCEEDED(ExtractOptionalValue(options_dict, kChromeFile,
                                     Value::TYPE_STRING, &error_string,
                                     &param_value)) && param_value != NULL) {
    param_value->GetAsString(&chrome_file_pat_);
  }

  param_value = NULL;
  if (SUCCEEDED(ExtractOptionalValue(options_dict, kKernelFile,
                                     Value::TYPE_STRING, error_string_out,
                                     &param_value)) && param_value != NULL) {
    param_value->GetAsString(&kernel_file_pat_);
  }

  param_value = NULL;
  if (SUCCEEDED(ExtractOptionalValue(options_dict, kKernelOn,
                                     Value::TYPE_BOOLEAN, error_string_out,
                                     &param_value)) && param_value != NULL) {
    param_value->GetAsBoolean(&trace_kernel_on_);
  }

  param_value = NULL;
  if (SUCCEEDED(ExtractOptionalValue(options_dict, kKernelFileSize,
                                     Value::TYPE_INTEGER, error_string_out,
                                     &param_value)) && param_value != NULL) {
    int raw_value = 0;
    param_value->GetAsInteger(&raw_value);
    if (raw_value > 0)
      max_kernel_file_size_ = __min(raw_value, kMaxFileSize);
  }

  param_value = NULL;
  if (SUCCEEDED(ExtractOptionalValue(options_dict, kChromeFileSize,
                                     Value::TYPE_INTEGER, error_string_out,
                                     &param_value)) && param_value != NULL) {
    int raw_value = 0;
    param_value->GetAsInteger(&raw_value);
    if (raw_value > 0)
      max_chrome_file_size_ = __min(raw_value, kMaxFileSize);
  }

  param_value = NULL;
  if (SUCCEEDED(ExtractOptionalValue(options_dict, kHarvestEnvVars,
                                     Value::TYPE_BOOLEAN, error_string_out,
                                     &param_value)) && param_value != NULL) {
      param_value->GetAsBoolean(&harvest_env_variables_);
  }

  return true;
}

bool TracerConfiguration::GetLogFileName(FilePath* return_path) const {
  return GetTargetFilePath(root_in_fs_, chrome_file_pat_,  return_path);
}

bool TracerConfiguration::GetKernelLogFileName(FilePath* return_path) const {
  return GetTargetFilePath(root_in_fs_, kernel_file_pat_,  return_path);
}

// Get the target URL. If it is a local path (a file to place), assume_remote
// will be set to false. Otherwise, the caller should write to a remote
// host through an http request. Warning: never overwrite local files.
bool TracerConfiguration::GetUploadPath(
    std::wstring* upload_url, bool* assume_remote) const {
  DCHECK(upload_url != NULL);
  DCHECK(assume_remote != NULL);
  return InternalGetExpandedPath(NULL, upload_url, assume_remote);
}

bool TracerConfiguration::GetUploadPath(const Version& force_version,
                                        std::wstring* upload_url,
                                        bool* assume_remote) const {
  DCHECK(upload_url != NULL);
  DCHECK(assume_remote != NULL);
  return InternalGetExpandedPath(&force_version, upload_url, assume_remote);
}

// The actual routine constructing upload url/path. When force_version is given,
// it might be woven into the upload path. If the target pattern is declared
// using 'keyword-in-curly-braces' format it is expanded here.
bool TracerConfiguration::InternalGetExpandedPath(const Version* force_version,
                                                  std::wstring* upload_url,
                                                  bool* assume_remote) const {
  if (target_url_.empty())
    return false;  // Uploading has not been configured.

  std::wstring expanded_pattern;
  if (target_url_.end() ==
      std::find(target_url_.begin(), target_url_.end(), '{')) {
    // Separate 'easy branch' to cut down on copying etc.
    expanded_pattern = target_url_;
  } else {
    // Assume target_url_ to be a 'pattern' calling for replacing certain keys
    // with values from a dictionary.
    scoped_ptr<DictionaryValue> local_copy(
        upload_params_->DeepCopyWithoutEmptyChildren());
    if (!local_copy->HasKey(kAppKey))
      local_copy->SetString(kAppKey, L"Chrome");

    if (force_version != NULL) {
      local_copy->SetString(kVersionKey, force_version->GetString());
    } else {
      scoped_ptr<Version> ver(GetDeclaredApplicationVersion());
      if (ver != NULL)
        local_copy->SetString(kVersionKey, ver->GetString());
    }

    if (!ExpandBracketPattern(target_url_, local_copy.get(), &expanded_pattern))
      return false;
  }

  // Is it a properly formatted URL?
  GURL url_as_url(expanded_pattern);
  bool is_url = false;
  bool is_file_path = false;

  is_url = url_as_url.is_valid() && url_as_url.has_host();

  if (url_as_url.is_valid() && !is_url)
    is_file_path = VerifyLocalTargetPathOK(expanded_pattern);

  if (is_url || is_file_path) {
    if (upload_url)
      *upload_url = expanded_pattern;
    if (assume_remote)
      *assume_remote = is_url;
    return true;
  }

  return false;
}

// This is a test seam which permits circumventing a call relating to the FS.
bool TracerConfiguration::VerifyLocalTargetPathOK(
    const std::wstring& file_path) const {
  FilePath try_file_trick(file_path);
  return file_util::DirectoryExists(try_file_trick.DirName());
}

TracerConfiguration::ExitAction TracerConfiguration::ActionOnExit() const {
  if (target_url_.empty() && exit_action_ == REPORT_ASK) {
    return REPORT_CLEAR;
  }

  return exit_action_;
}

// Set all member variables to their initial state.
void TracerConfiguration::Clear() {
  provider_defs_.clear();
  root_in_fs_.clear();

  chrome_file_pat_.clear();
  kernel_file_pat_.clear();
  trace_kernel_on_ = false;
  max_kernel_file_size_ = 0;
  max_chrome_file_size_ = 0;

  target_url_.clear();
  exit_action_ = REPORT_ASK;
  upload_params_.reset();
  harvest_env_variables_ = false;
}

bool TracerConfiguration::GetTracedApplication(std::wstring* app_name) const {
  if (app_name && (upload_params_ == NULL ||
                   !upload_params_->GetString(kAppKey, app_name))) {
    *app_name = kDefaultAppName;
  }
  return true;
}

// There are two parameters which serve to help figure out the version. One is a
// registry key, which should correspond to the version (presumably put there
// by the setup). Otherwise, this is just a plain text given in JSON.
Version* TracerConfiguration::GetDeclaredApplicationVersion() const {
  bool retrieved = false;
  std::wstring retrieved_param;
  if (GetParameterWord(kVersionKeyKey, &retrieved_param)) {
    // retrieved_param should be the entire path, including the root key.
    std::vector<std::wstring> path_bits;
    HKEY rootkey = NULL;
    base::SplitString(retrieved_param, '\\', &path_bits);
    if (path_bits.size() >= 3) {  // Root + path + value.
      // It has to be either HKLM or HKCU.
      if (path_bits.front() == L"HKEY_LOCAL_MACHINE")
        rootkey = HKEY_LOCAL_MACHINE;
      else if (path_bits.front() == L"HKEY_CURRENT_USER")
        rootkey = HKEY_CURRENT_USER;
      else
        LOG(WARNING) << "Incorrect root key: " << path_bits.front();
    }

    if (rootkey != NULL) {
      // Get the rest of the path.
      std::wstring value_key = path_bits.back();
      path_bits.pop_back();
      path_bits.erase(path_bits.begin());

      std::wstring key_path = JoinString(path_bits, '\\');
      base::win::RegKey reg_key(rootkey, key_path.c_str(), KEY_READ);
      retrieved = reg_key.Valid() && reg_key.ReadValue(value_key.c_str(),
                                                       &retrieved_param);
    }
  }

  retrieved = retrieved || GetParameterWord(kVersionKey, &retrieved_param);

  if (retrieved)
    return Version::GetVersionFromString(WideToUTF8(retrieved_param));

  return NULL;
}

bool TracerConfiguration::GetParameterWord(const std::string& key,
                                           std::wstring* the_word) const {
  return upload_params_ != NULL && upload_params_->GetString(key, the_word);
}

// Populates the query_keys vector with string as they were declared in the
// original JSON, no validation done here.
bool TracerConfiguration::GetRegistryQuery(
    std::vector<std::wstring>* query_keys) const {
  if (registry_query_ == NULL || registry_query_->empty())
    return false;

  if (query_keys == NULL) {
    NOTREACHED() << "Incorrect parameter (NULL)";
    return true;
  }

  query_keys->clear();
  query_keys->reserve(registry_query_->GetSize());
  std::wstring retrieved_text;
  for (ListValue::const_iterator vit = registry_query_->begin();
       vit != registry_query_->end(); ++vit) {
    if (*vit && (*vit)->GetAsString(&retrieved_text))
      query_keys->push_back(retrieved_text);
  }

  return true;
}

// A simple helper, intended to cut down on error handling code. Retrieves a
// child node of |parent| identified as key and assigns it to |retrieved_value|.
// If such a node doesn't exist, an error message will be generated,
// |error_out| populated and E_FAIL returned.
// Furthermore, if the extracted not is not of type |expected_type|, error
// information will be set and E_FAIL is returned. In all other cases error
// information remains unchanged and the function returns S_OK;
// |retrieved_value| is modified only when the function returns S_OK.
HRESULT TracerConfiguration::ExtractValue(
    DictionaryValue* parent, const char* key, Value::ValueType expected_type,
        std::string* error_out, Value** retrieved_value) {
  HRESULT hr = InternalExtractValue(parent, key, expected_type, error_out,
                                    retrieved_value);
  if (hr == S_FALSE)  // No value.
    hr = E_FAIL;
  return hr;
}

// Like ExtractValue (see comments above) except that if the value is not
// present, the function still succeeds (S_FALSE is returned). Again,
// |retrieved_value| is modified only when the function succeeds. (it may be
// set to null when S_FALSE).
HRESULT TracerConfiguration::ExtractOptionalValue(
    DictionaryValue* parent, const char* key, Value::ValueType expected_type,
        std::string* error_out, Value** retrieved_value) {
  HRESULT hr = InternalExtractValue(parent, key, expected_type, error_out,
                                    retrieved_value);
  if (S_FALSE == hr && retrieved_value != NULL)
    *retrieved_value = NULL;

  return hr;
}

HRESULT TracerConfiguration::InternalExtractValue(
    DictionaryValue* parent, const char* key, Value::ValueType expected_type,
        std::string* error_out, Value** retrieved_value) {
  DCHECK(parent != NULL && key != NULL);
  Value* return_value = NULL;
  HRESULT hr = S_FALSE;  // S_FALSE stands for 'value not available'.

  if (parent->Get(key, &return_value)) {
    if (!return_value->IsType(expected_type)) {
      std::string error_string;
      base::SStringPrintf(&error_string,
          "Error in parsing configuration file: %s has incorrect type."
          " Expected %d, got %d.", key, expected_type, return_value->GetType());
      LOG(WARNING) << error_string;

      if (error_out != NULL)
        *error_out = error_string;

      hr = E_FAIL;
    } else {
      hr = S_OK;
      if (retrieved_value != NULL)
        *retrieved_value = return_value;
    }
  }

  return hr;
}

// A convenience function of perplexing semantics. Its object is to populate
// target_file with a path to a writable file (returns false if failed to do so
// and true if all was OK).
// target_file is created as follows:
// 1) if name_pat is not given, by a valid temporary file name under dir
// 2) if name_pat is a proper absolute path, it is just it.
// 3) otherwise, a file under dir.
bool TracerConfiguration::GetTargetFilePath(const FilePath& dir,
                                            const std::wstring& name_pat,
                                            FilePath* target_file) {
  DCHECK(target_file != NULL);

  if (name_pat.empty()) {
    return file_util::CreateTemporaryFileInDir(dir, target_file);
  }

  FilePath pat_path(name_pat);
  // Most useful case: dir is the directory and name_pat is a file title.
  if (!pat_path.IsAbsolute())
    pat_path = dir.Append(pat_path);
  // If the name_pat was an absolute file path, we will try that.

  if (!file_util::DirectoryExists(pat_path)) {
    *target_file = pat_path;
    return true;
  }
  return false;
}

// Given a pattern in the format {var0}slice1{var1}slice2{var2}...sliceN{varN}
// and a string-valued dictionary dict of var0...varN, the function will expand
// the pattern by replacing {varX} with corresponding values from the
// dictionary. Nested or unbalanced braces are illegal. There is no escape
// sequence to put a brace into a slice (but variables' values can contain
// braces).
bool TracerConfiguration::ExpandBracketPattern(const std::wstring& pattern,
                                               DictionaryValue* dict,
                                               std::wstring* expanded_pattern) {
  DCHECK(dict != NULL && expanded_pattern != NULL);
  std::wstring::const_iterator current_bit_start = pattern.end();
  bool in_variable_bit = false;
  std::vector<std::wstring> all_bits;
  unsigned total_bit_len = 0;
  for (std::wstring::const_iterator l = pattern.begin();
       l != pattern.end(); ++l) {
    // Keep track of where the current fragment has started.
    if (current_bit_start == pattern.end())
      current_bit_start = l;

    if ((*l == kOpenBrace && in_variable_bit) ||
        (*l == kCloseBrace && !in_variable_bit)) {
      // An error condition - unbalanced or nested braces.
      LOG(WARNING) << "Format error (unexpected " << *l << " at " <<
          (l - pattern.begin()) << ") in " << pattern;
      return false;
    }
    switch (*l) {
      case kOpenBrace:
        DCHECK(!in_variable_bit && current_bit_start != pattern.end());
        if (current_bit_start != l) {  // Might have been empty.
          total_bit_len += l - current_bit_start;
          all_bits.push_back(std::wstring(current_bit_start, l));
        }
        // Note the state change and reset the fragment (will be set in the
        // next iteration.)
        in_variable_bit = true;
        current_bit_start = pattern.end();
        break;
      case kCloseBrace:
        DCHECK(in_variable_bit && current_bit_start != pattern.end());
        if (current_bit_start != l) {
          std::wstring keyword(current_bit_start, l);
          std::wstring replacement_value;
          if (dict == NULL ||
              !dict->GetString(WideToASCII(keyword), &replacement_value)) {
            LOG(WARNING) << "Format error: unknown keyword " << keyword;
            return false;
          }
          total_bit_len += replacement_value.size();
          all_bits.push_back(replacement_value);
        }  // The reverse (empty var) is allowed. Just excise {} and move on.
        in_variable_bit = false;
        current_bit_start = pattern.end();
        break;
    }
  }

  // We may still have the last bit to insert at this point.
  if (current_bit_start != pattern.end()) {
    all_bits.push_back(std::wstring(current_bit_start, pattern.end()));
    current_bit_start = pattern.end();
  }

  DCHECK_GT(total_bit_len, static_cast<unsigned int>(0));
  if (NULL != expanded_pattern) {
    expanded_pattern->clear();
    expanded_pattern->reserve(total_bit_len * sizeof(std::wstring::value_type));
    for (std::vector<std::wstring>::const_iterator bit = all_bits.begin();
         bit != all_bits.end(); ++bit) {
      (*expanded_pattern) += *bit;
    }
  }
  return true;
}
