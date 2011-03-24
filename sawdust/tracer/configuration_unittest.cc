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
#include "sawdust/tracer/configuration.h"

#include <map>
#include <set>

#include "base/file_path.h"
#include "base/json/json_reader.h"
#include "base/json/json_writer.h"
#include "base/logging.h"
#include "base/scoped_ptr.h"
#include "base/values.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "sawdust/tracer/tracer_unittest_util.h"


namespace {

// A derivative of the tested class with some functions mocked-out.
class TestingTracerConfiguration : public TracerConfiguration {
 public:
  explicit TestingTracerConfiguration(
      const std::set<std::wstring>* allowed_dirs)
      : TracerConfiguration(),
        allowed_dirs_(allowed_dirs) {
  }

  static bool CallExpandBracketPattern(const std::wstring& pattern,
                                       DictionaryValue* dict,
                                       std::wstring* expanded_pattern) {
    return ExpandBracketPattern(pattern, dict, expanded_pattern);
  }

  static std::pair<bool, Value*>
      CallExtractValue(DictionaryValue* parent,
                       const char* key,
                       bool required,
                       Value::ValueType expected_type) {
    Value* retrieved_value = NULL;
    HRESULT hr = S_OK;
    if (required) {
      hr = ExtractValue(parent, key, expected_type, NULL, &retrieved_value);
    } else {
      hr = ExtractOptionalValue(parent, key, expected_type,
                                NULL, &retrieved_value);
    }
    return std::pair<bool, Value*>(SUCCEEDED(hr), retrieved_value);
  }

 private:
  bool VerifyLocalTargetPathOK(const std::wstring& file_path) const {
    // Override will claim to know directories which are in allowed_dirs_.
    FilePath try_file_trick(file_path);
    return (allowed_dirs_->find(try_file_trick.DirName().value()) !=
            allowed_dirs_->end());
  }
  const std::set<std::wstring>* allowed_dirs_;

  DISALLOW_COPY_AND_ASSIGN(TestingTracerConfiguration);
};

// The base class for running tests from a canned JSON containing test cases.
class TracerConfigurationTest : public testing::Test {
 public:
  TracerConfigurationTest() {
  }

  virtual void SetUp() {
#define ADD_TO_MAP(map_obj, method_name)\
    (map_obj)[#method_name] = &TracerConfigurationTest::Verify##method_name;

    tested_object_.reset(new TestingTracerConfiguration(&known_existing_dirs_));
    ADD_TO_MAP(verification_map_, IsKernelLoggingEnabled);
    ADD_TO_MAP(verification_map_, GetLogFileSizeCapMb);
    ADD_TO_MAP(verification_map_, GetKernelLogFileSizeCapMb);
    ADD_TO_MAP(verification_map_, GetLogFileName);
    ADD_TO_MAP(verification_map_, GetKernelLogFileName);
    ADD_TO_MAP(verification_map_, GetTracedApplication);
    ADD_TO_MAP(verification_map_, GetDeclaredApplicationVersion);
    ADD_TO_MAP(verification_map_, ActionOnExit);
    ADD_TO_MAP(verification_map_, GetParameterWord);
    ADD_TO_MAP(verification_map_, GetUploadPath);
    ADD_TO_MAP(verification_map_, HarvestEnvVariables);
#undef ADD_TO_MAP
  }

  virtual void TearDown() {
    tested_object_.reset(NULL);
  }

  void RunTestOnLocalFile(std::wstring file_title) {
    scoped_ptr<Value> test_data(LoadJsonDataFile(file_title));
    ASSERT_TRUE(test_data != NULL && test_data->IsType(Value::TYPE_LIST));

    // test_data contains a list of test cases which we will now execute.
    const ListValue& test_cases = static_cast<const ListValue&>(*test_data);
    for (ListValue::const_iterator test_case_it = test_cases.begin();
         test_case_it != test_cases.end(); ++test_case_it) {
      ASSERT_TRUE((*test_case_it)->IsType(Value::TYPE_DICTIONARY));
      const DictionaryValue* test_case =
          static_cast<const DictionaryValue*>(*test_case_it);

      known_existing_dirs_.clear();  // Must not depend on that.
      bool parses_ok = false;
      ASSERT_TRUE(test_case->GetBoolean("parses-ok", &parses_ok));
      Value* test_case_init = NULL;
      ASSERT_TRUE(test_case->Get("test-case", &test_case_init));
      ReInitializeConfiguration(*test_case_init,
                                FilePath(L"C:\\TotalFakeDir"), !parses_ok);
      if (parses_ok) {
        // Get verification data and run the comparison test.
        DictionaryValue* test_case_data = NULL;
        ListValue* dirs_to_spoof = NULL;
        ASSERT_TRUE(test_case->GetDictionary("test-data", &test_case_data));
        if (test_case->GetList("have-dirs", &dirs_to_spoof) &&
            dirs_to_spoof != NULL) {
          for (ListValue::const_iterator dir_it = dirs_to_spoof->begin();
               dir_it != dirs_to_spoof->end(); ++dir_it) {
            std::wstring directory;
            if ((*dir_it)->GetAsString(&directory))
              known_existing_dirs_.insert(directory);
          }
        }
        VerifyConfiguration(*test_case_data);
      }
    }
  }

 protected:
  // Put in initialization data from init_data and prepare the verification set.
  // It has to be always called as a part of a test case.
  // Initialization and verification are two separate steps split to clearly
  // isolate possible points of failure.
  void ReInitializeConfiguration(const Value& init_data,
                                 const FilePath& root_dir,
                                 bool expect_failure) {
    ASSERT_TRUE(init_data.IsType(Value::TYPE_DICTIONARY));
    std::string json_text, error_string;
    base::JSONWriter::Write(&init_data, false, &json_text);

    ASSERT_FALSE(json_text.empty());
    ASSERT_EQ(tested_object_->Initialize(json_text, root_dir, &error_string),
              !expect_failure);
  }

  // Iterate through the verification data and make sure designated functions
  // return expected values.
  void VerifyConfiguration(const DictionaryValue& verification_data) {
    for (DictionaryValue::key_iterator kit = verification_data.begin_keys();
         kit != verification_data.end_keys(); ++kit) {
      // Check if there is a matching verification function for this key.
      // If there isn't any, it is a failed test.
      VerificationMapType::iterator verificator_it =
          verification_map_.find(*kit);
      ASSERT_FALSE(verificator_it == verification_map_.end());

      Value* retrieved_value = NULL;
      ASSERT_TRUE(verification_data.Get(*kit, &retrieved_value) &&
                  retrieved_value != NULL);
      VerificationMethod method = verificator_it->second;
      (this->*method)(*retrieved_value);
    }
  }

  // Helper retrieval functions (polymorphism used to cut down on boilerplate
  // in CheckResultEqualDirect<> expansions.
  static bool SafeRetrieveValue(const Value& test_value, bool* ret) {
    return test_value.GetAsBoolean(ret);
  }

  static bool SafeRetrieveValue(const Value& test_value, unsigned* ret) {
    int retrieved = 0;
    if (test_value.GetAsInteger(&retrieved)) {
      DCHECK_GE(retrieved, 0);  // Hard check, test data must make sense.
      *ret = retrieved;
      return true;
    }
    return false;
  }

  static bool SafeRetrieveValue(const Value& test_value,
                                TracerConfiguration::ExitAction* ret) {
    int retrieved = 0;
    if (test_value.GetAsInteger(&retrieved)) {
      // Hard check, test data must make sense.
      DCHECK(retrieved >= static_cast<int>(TracerConfiguration::REPORT_ASK) &&
          retrieved < static_cast<int>(TracerConfiguration::LAST_REPORT_TYPE));

      *ret = static_cast<TracerConfiguration::ExitAction>(retrieved);
      return true;
    }
    return false;
  }

  static bool SafeRetrieveValue(const Value& test_value, FilePath* ret) {
    // Note that direct path comparisons will work only for absolute paths.
    // Path creation logic must be exercised separately in a unit test.
    std::wstring path_as_str;
    bool retrieved = test_value.GetAsString(&path_as_str);
    if (!retrieved || path_as_str.empty())
      return false;

    *ret = FilePath(path_as_str);
    return true;
  }

  static bool SafeRetrieveValue(const Value& test_value, std::wstring* ret) {
    return test_value.GetAsString(ret);
  }

  // Compare the RT-typed value stored in test_value with whatever method
  // invoked on object returns.
  template<typename RT>
  bool CheckResultEqualDirect(const TracerConfiguration* object,
                              RT (TracerConfiguration::*method)(void) const,
                              const Value& test_value) const {
    RT test_typed_value = RT();
    if (!SafeRetrieveValue(test_value, &test_typed_value))
      return false;
    return (object->*method)() == test_typed_value;
  }

  template<typename RT>
  bool CheckResultEqualIndirect(const TracerConfiguration* object,
      bool (TracerConfiguration::*method)(RT*) const,  // NOLINT - not a cast.
          const Value& test_value) const {
    RT test_typed_value = RT();
    RT config_typed_value = RT();
    bool in_test = SafeRetrieveValue(test_value, &test_typed_value);
    bool in_config = (object->*method)(&config_typed_value);
    // The indirect comparison is 'true' if the value is present neither in the
    // instance under test nor in test data.
    if (in_test && in_config)
      return test_typed_value == config_typed_value;
    else
      return !in_test && !in_config;
  }

  // Block of verification methods (name pattern is: Verify{method name}).
  // There is one such method for each method of TracerConfiguration we test/
  // Much of it is boilerplate. Some clever templating code would do but then
  // failure points would not be obvious.
  void VerifyIsKernelLoggingEnabled(const Value& test_value) const {
    ASSERT_TRUE(CheckResultEqualDirect(tested_object_.get(),
        &TracerConfiguration::IsKernelLoggingEnabled, test_value));
  }

  void VerifyGetLogFileSizeCapMb(const Value& test_value) const {
    ASSERT_TRUE(CheckResultEqualDirect(tested_object_.get(),
        &TracerConfiguration::GetLogFileSizeCapMb, test_value));
  }

  void VerifyGetKernelLogFileSizeCapMb(const Value& test_value) const {
    ASSERT_TRUE(CheckResultEqualDirect(tested_object_.get(),
        &TracerConfiguration::GetKernelLogFileSizeCapMb, test_value));
  }

  void VerifyGetLogFileName(const Value& test_value) const {
    ASSERT_TRUE(CheckResultEqualIndirect(tested_object_.get(),
        &TracerConfiguration::GetLogFileName, test_value));
  }

  void VerifyGetKernelLogFileName(const Value& test_value) const {
    ASSERT_TRUE(CheckResultEqualIndirect(tested_object_.get(),
        &TracerConfiguration::GetKernelLogFileName, test_value));
  }

  void VerifyGetTracedApplication(const Value& test_value) const {
    ASSERT_TRUE(CheckResultEqualIndirect(tested_object_.get(),
        &TracerConfiguration::GetTracedApplication, test_value));
  }

  void VerifyGetDeclaredApplicationVersion(const Value& test_value) const {
    // This tests simple version declaration only. Testing the mechanics of
    // getting versions from the registry will require mocking registry access
    // function and is done in a separate unit test.
    scoped_ptr<Version> config_ver(
        tested_object_->GetDeclaredApplicationVersion());
    ASSERT_TRUE(config_ver != NULL);
    std::string ver_string;
    ASSERT_TRUE(test_value.GetAsString(&ver_string));
    scoped_ptr<Version> test_ver(Version::GetVersionFromString(ver_string));
    ASSERT_TRUE(test_ver != NULL);

    ASSERT_EQ(0, test_ver->CompareTo(*config_ver));
  }

  void VerifyActionOnExit(const Value& test_value) const {
    ASSERT_TRUE(CheckResultEqualDirect(tested_object_.get(),
        &TracerConfiguration::ActionOnExit, test_value));
  }

  void VerifyGetParameterWord(const Value& test_value) const {
    // Make sure declared keywords are present in the tested object. This is
    // trivial code, but I will exercise it anyway.
    ASSERT_TRUE(test_value.IsType(Value::TYPE_DICTIONARY));
    const DictionaryValue& keyword_dictionary =
        static_cast<const DictionaryValue&>(test_value);

    for (DictionaryValue::key_iterator kit = keyword_dictionary.begin_keys();
         kit != keyword_dictionary.end_keys(); ++kit) {
      std::wstring keyword_value, test_keyword_value;
      ASSERT_TRUE(keyword_dictionary.GetString(*kit, &test_keyword_value));
      ASSERT_TRUE(tested_object_->GetParameterWord(*kit, &keyword_value));
      ASSERT_EQ(test_keyword_value, keyword_value);
    }
  }

  void VerifyGetUploadPath(const Value& test_value) const {
    ASSERT_TRUE(test_value.IsType(Value::TYPE_LIST));
    const ListValue& test_values = static_cast<const ListValue&>(test_value);

    if (test_values.GetSize() == 0) {
      std::wstring upload_url;
      bool assume_remote = true;
      ASSERT_FALSE(tested_object_->GetUploadPath(&upload_url, &assume_remote));
    } else {
      // Functions which do all guesswork regarding path (file_util) are mocked
      // on SetUp, so it can be kept simple here.
      ASSERT_EQ(test_values.GetSize(), 2);
      std::wstring upload_url, test_upload_url;
      bool assume_remote = true;
      bool test_assume_remote = true;
      ASSERT_TRUE(tested_object_->GetUploadPath(&upload_url, &assume_remote));
      ASSERT_TRUE(test_values.GetString(0, &test_upload_url) &&
                  test_values.GetBoolean(1, &test_assume_remote));
      ASSERT_EQ(test_assume_remote, assume_remote);
      ASSERT_EQ(test_upload_url, upload_url);
    }
  }

  void VerifyHarvestEnvVariables(const Value& test_value) const {
    ASSERT_TRUE(CheckResultEqualDirect(tested_object_.get(),
        &TracerConfiguration::HarvestEnvVariables, test_value));
  }

  typedef void (TracerConfigurationTest::*VerificationMethod)
      (const Value&) const;
  typedef std::map<std::string, VerificationMethod> VerificationMapType;

  scoped_ptr<TracerConfiguration> tested_object_;
  VerificationMapType verification_map_;
  std::set<std::wstring> known_existing_dirs_;

 private:
  DISALLOW_COPY_AND_ASSIGN(TracerConfigurationTest);
};

// And here the real test invocation for canned JSON data.
TEST_F(TracerConfigurationTest, TestRealJsonFeeds) {
  RunTestOnLocalFile(L"configuration_unittest_data.json");
}

// Test configuration object's behaviour when fed incorrect data.
TEST(ConfigurationTest, InvalidJsonData) {
  TracerConfiguration test_config;

  FilePath path(L"test_root_dir");
  std::string error_message_out;
  ASSERT_FALSE(test_config.Initialize(std::string(), path, &error_message_out));
  ASSERT_FALSE(test_config.Initialize("#$%^&* Plainly not JSON!", path,
                                      &error_message_out));

  ASSERT_FALSE(test_config.Initialize("[{\"format\": \"is just wrong\"}]", path,
               &error_message_out));
}

// Tests the simple path customization mechanism embedded in the config handler.
TEST(ConfigurationTest, ExpandingUrlTest) {
  scoped_ptr<Value> test_data(
      LoadJsonDataFile(L"configuration_unittest_expressions.json"));
  ASSERT_TRUE(test_data != NULL && test_data->IsType(Value::TYPE_LIST));

  const ListValue& test_cases = static_cast<const ListValue&>(*test_data);

  for (ListValue::const_iterator case_it = test_cases.begin();
       case_it != test_cases.end(); ++case_it) {
    ASSERT_TRUE((*case_it)->IsType(Value::TYPE_DICTIONARY));
    const DictionaryValue* the_test_case =
        static_cast<const DictionaryValue*>(*case_it);
    DictionaryValue* expand_dictionary = NULL;
    Value* expected_response = NULL;
    std::wstring pattern;

    ASSERT_TRUE(the_test_case->GetDictionary("keywords", &expand_dictionary));
    ASSERT_TRUE(the_test_case->GetString("expression", &pattern));
    if (!the_test_case->Get("result", &expected_response))
      expected_response = NULL;

    bool expect_failure = (expected_response == NULL ||
                           !expected_response->IsType(Value::TYPE_STRING));
    std::wstring result_text;
    ASSERT_EQ(!expect_failure,
        TestingTracerConfiguration::CallExpandBracketPattern(
            pattern, expand_dictionary, &result_text));
    if (!expect_failure) {
      std::wstring expect_response_string;
      ASSERT_TRUE(expected_response->GetAsString(&expect_response_string));
      ASSERT_EQ(result_text, expect_response_string);
    }
  }
}

// A test for the the logic of extracting 'optional' values from config JSONs.
TEST(ConfigurationTest, ValueExtractionHelperTest) {
  DictionaryValue dictionary;
  dictionary.SetBoolean("boolean", true);
  dictionary.SetInteger("integer", 42);
  dictionary.SetDouble("double", 3.1415);
  dictionary.SetString("string", L"But what was the question?");
  dictionary.Set("dictionary", new DictionaryValue());
  dictionary.Set("list", new ListValue());

  // Now let's make sure values that are indeed there can be extracted,
  std::pair<bool, Value*> retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "boolean",
                                                   true, Value::TYPE_BOOLEAN);
  ASSERT_TRUE(retrieval.first && retrieval.second != NULL &&
              retrieval.second->IsType(Value::TYPE_BOOLEAN));
  retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "integer",
                                                   true, Value::TYPE_INTEGER);
  ASSERT_TRUE(retrieval.first && retrieval.second != NULL &&
              retrieval.second->IsType(Value::TYPE_INTEGER));
  retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "double",
                                                   true, Value::TYPE_DOUBLE);
  ASSERT_TRUE(retrieval.first && retrieval.second != NULL &&
              retrieval.second->IsType(Value::TYPE_DOUBLE));
  retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "string",
                                                   true, Value::TYPE_STRING);
  ASSERT_TRUE(retrieval.first && retrieval.second != NULL &&
              retrieval.second->IsType(Value::TYPE_STRING));
  retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "dictionary",
                                                   true,
                                                   Value::TYPE_DICTIONARY);
  ASSERT_TRUE(retrieval.first && retrieval.second != NULL &&
              retrieval.second->IsType(Value::TYPE_DICTIONARY));
  retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "list",
                                                   true, Value::TYPE_LIST);
  ASSERT_TRUE(retrieval.first && retrieval.second != NULL &&
              retrieval.second->IsType(Value::TYPE_LIST));

  // Type constraints are enforced on existing values regardless if we think it
  // optional or mandatory.
  retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "dictionary",
                                                   true, Value::TYPE_LIST);
  ASSERT_FALSE(retrieval.first);
  ASSERT_TRUE(retrieval.second == NULL);

  retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "string",
                                                   false, Value::TYPE_DOUBLE);
  ASSERT_FALSE(retrieval.first);
  ASSERT_TRUE(retrieval.second == NULL);

  // Retrieving a non-existing value.
  retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "nothing",
                                                   true, Value::TYPE_DOUBLE);
  ASSERT_FALSE(retrieval.first);
  ASSERT_TRUE(retrieval.second == NULL);

  retrieval =
      TestingTracerConfiguration::CallExtractValue(&dictionary, "nothing",
                                                   false, Value::TYPE_DOUBLE);
  ASSERT_TRUE(retrieval.first);  // It is ok not to have an optional value.
  ASSERT_TRUE(retrieval.second == NULL);  // But it is still null.
}

}  // namespace
