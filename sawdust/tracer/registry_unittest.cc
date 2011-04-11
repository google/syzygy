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
#include "sawdust/tracer/registry.h"

#include <algorithm>
#include <functional>
#include <set>
#include <streambuf>
#include <string>
#include <vector>

#include "base/logging.h"
#include "base/scoped_ptr.h"
#include "base/string_split.h"
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/win/registry.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"

#include "sawdust/tracer/tracer_unittest_util.h"

namespace {
const wchar_t kUnitTestRegistrySubKey[] = L"SOFTWARE\\Sawdust Unit Tests";
const wchar_t kUnitTestMachineOverrideSubKey[] =
    L"SOFTWARE\\Sawdust Unit Tests\\HKLM Override";
const wchar_t kUnitTestUserOverrideSubKey[] =
    L"SOFTWARE\\Sawdust Unit Tests\\HKCU Override";
const wchar_t kBaseExerciseKey[] = L"Software\\Google\\Sawbuck\\Junk";
const wchar_t kListExerciseKey[] = L"Software\\Google\\Sawdust\\List";
const wchar_t kTreeExerciseKey[] = L"Software\\Google\\Sawdust\\Tree";

const char kTestDataForMultiLineText[] =
    "Line 1\"\n"
    "Long line 2 starts here... and goes on and on and on and on and on and on"
    " and on and on and on and on and on and on and on and on and on and on "
    "and on and on \n"
    " \n"
    "text test\n";

const size_t kBinaryDataTestSize = 512;

class RegistryExtractorTest : public testing::Test {
 public:
  RegistryExtractorTest()
      : fake_hklm_(HKEY_CURRENT_USER, kUnitTestMachineOverrideSubKey, KEY_READ),
        fake_hkcu_(HKEY_CURRENT_USER, kUnitTestUserOverrideSubKey, KEY_READ) {
  }
  void SetUp() {
    // Create the subkeys to hold the overridden HKLM and HKCU
    // policy settings.
    fake_hklm_.Create(HKEY_CURRENT_USER,
                      kUnitTestMachineOverrideSubKey,
                      KEY_ALL_ACCESS);
    fake_hkcu_.Create(HKEY_CURRENT_USER,
                      kUnitTestUserOverrideSubKey,
                      KEY_ALL_ACCESS);

    // Now set-up overrides for HKLM and HKCU
    EXPECT_EQ(ERROR_SUCCESS, RegOverridePredefKey(HKEY_LOCAL_MACHINE,
                                                  fake_hklm_.Handle()));
    EXPECT_EQ(ERROR_SUCCESS, RegOverridePredefKey(HKEY_CURRENT_USER,
                                                  fake_hkcu_.Handle()));
  }

  void TearDown() {
    // Turn overrides off.
    EXPECT_EQ(ERROR_SUCCESS, RegOverridePredefKey(HKEY_LOCAL_MACHINE, 0));
    EXPECT_EQ(ERROR_SUCCESS, RegOverridePredefKey(HKEY_CURRENT_USER, 0));
    fake_hklm_.Close();
    fake_hkcu_.Close();
    base::win::RegKey kill_key(HKEY_CURRENT_USER, kUnitTestRegistrySubKey,
                               KEY_ALL_ACCESS);
    kill_key.DeleteKey(L"");
  }

 protected:
  base::win::RegKey fake_hklm_;
  base::win::RegKey fake_hkcu_;
};

TEST_F(RegistryExtractorTest, FormatMultiStringValue) {
  std::string source_data(kTestDataForMultiLineText);
  std::string append_data;
  size_t buffer_size = 0;
  scoped_array<wchar_t> string_table(
      CreateNullNullTerminatedDescription(source_data, &buffer_size));

  RegistryExtractor::FormatMultiStringValue(string_table.get(), buffer_size, 0,
                                            &append_data);
  // append_data has no trailing \n.
  ASSERT_EQ(source_data, append_data + '\n');

  std::vector<std::string> source_bits, test_bits;
  // Now with indentation and non-empty string.
  const int kIndent = 4;
  append_data.clear();
  append_data.append(kIndent, '\t');
  RegistryExtractor::FormatMultiStringValue(string_table.get(), buffer_size,
                                            kIndent, &append_data);
  base::SplitStringDontTrim(source_data, '\n', &source_bits);
  base::SplitStringDontTrim(append_data, '\n', &test_bits);

  // +1 accounts for the trailing empty bit.
  ASSERT_EQ(source_bits.size(), test_bits.size() + 1);
  ASSERT_TRUE(source_bits.back().empty());
  for (std::vector<std::string>::const_iterator src_it = source_bits.begin(),
       test_it = test_bits.begin();
       test_it != test_bits.end(); ++src_it, ++test_it) {
     std::string indented(kIndent, '\t');
     indented.append(*src_it);
     ASSERT_EQ(indented, *test_it);
  }
}

TEST_F(RegistryExtractorTest, FormatBinaryValue) {
  const char data[] = {char(0xAA), char(0x00), char(0xCA),  // NOLINT
                       char(0x7A), char(0xEA), char(0x12),  // NOLINT
                       char(0x01), char(0xFF)};  // NOLINT - to see hex.
  std::string repr_string("AA 00 CA 7A EA 12 01 FF");
  std::string test_content;
  RegistryExtractor::FormatBinaryValue(data, sizeof(data), &test_content);
  ASSERT_EQ(test_content, repr_string);
}

TEST_F(RegistryExtractorTest, FormatBinaryValueLarge) {
  int random_buffer[kBinaryDataTestSize];
  std::generate(random_buffer, random_buffer + kBinaryDataTestSize, rand);
  std::string reference_content, test_content;
  unsigned char* as_uchar = reinterpret_cast<unsigned char*>(random_buffer);

  const size_t buffer_size = kBinaryDataTestSize *
      sizeof(random_buffer[0]) / sizeof(as_uchar[0]);

  for (unsigned char* out_byte = as_uchar;
       out_byte < as_uchar + buffer_size; ++out_byte) {
    int byte_value(*out_byte);
    base::StringAppendF(&reference_content, "%02X ", byte_value);
  }
  RegistryExtractor::FormatBinaryValue(reinterpret_cast<char*>(as_uchar),
                                       buffer_size, &test_content);
  ASSERT_EQ(reference_content, test_content + ' ');
}

TEST_F(RegistryExtractorTest, CreateFormattedRegValueSimple) {
  // The principle: create a bunch of values in a key and then retrieve them.
  base::win::RegKey junk_reg_folder(HKEY_CURRENT_USER, kBaseExerciseKey,
                                    KEY_ALL_ACCESS);
  EXPECT_TRUE(junk_reg_folder.Valid());

  const wchar_t* kDwordKey = L"REG_DWORD_type";
  const DWORD kDwordValue = 0x2C;
  const wchar_t* kSzKey = L"REG_SZ_type";
  const wchar_t* kSzValue = L"A short and nice string.";
  const wchar_t* kBinKey = L"REG_BINARY_type";
  const char kBinValue[] = {char(0xAA), char(0x00), char(0xCA),  // NOLINT
                            char(0x7A), char(0xEA), char(0x12),  // NOLINT
                            char(0x01), char(0xFF)};  // NOLINT - to see hex.
  const char* kBinValueFmt = "AA 00 CA 7A EA 12 01 FF";
  const wchar_t* kQwordKey = L"REG_QWORD_type";
  const uint64 kQwordValue = 0x2C;

  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.WriteValue(kDwordKey, kDwordValue));
  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.WriteValue(kSzKey, kSzValue));
  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.WriteValue(kBinKey,
      reinterpret_cast<const void*>(&kBinValue[0]),
          sizeof(kBinValue), REG_BINARY));
  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.WriteValue(kQwordKey,
      reinterpret_cast<const void*>(&kQwordValue),
          sizeof(kQwordValue), REG_QWORD));

  // Now get them all and check.
  std::string formatted_utf8;
  ASSERT_TRUE(RegistryExtractor::CreateFormattedRegValue(&junk_reg_folder,
      kDwordKey, 0, &formatted_utf8));
  ASSERT_NE(std::string::npos, formatted_utf8.find("2C"));

  ASSERT_TRUE(RegistryExtractor::CreateFormattedRegValue(&junk_reg_folder,
      kQwordKey, 0, &formatted_utf8));
  ASSERT_NE(std::string::npos, formatted_utf8.find("2C"));

  ASSERT_TRUE(RegistryExtractor::CreateFormattedRegValue(&junk_reg_folder,
      kSzKey, 0, &formatted_utf8));
  ASSERT_NE(std::string::npos, formatted_utf8.find(WideToUTF8(kSzValue)));

  ASSERT_TRUE(RegistryExtractor::CreateFormattedRegValue(&junk_reg_folder,
      kBinKey, 0, &formatted_utf8));
  ASSERT_NE(std::string::npos, formatted_utf8.find(kBinValueFmt));

  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.DeleteKey(L""));
}

TEST_F(RegistryExtractorTest, CreateFormattedRegValueMultiline) {
  base::win::RegKey junk_reg_folder(HKEY_CURRENT_USER, kBaseExerciseKey,
                                    KEY_ALL_ACCESS);
  EXPECT_TRUE(junk_reg_folder.Valid());

  const wchar_t* kMultilineKey = L"REG_MULTI_SZ_type";
  const int kIndent = 4;

  std::string source_data(kTestDataForMultiLineText);
  size_t buffer_size = 0;
  scoped_array<wchar_t> string_table(
      CreateNullNullTerminatedDescription(source_data, &buffer_size));

  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.WriteValue(kMultilineKey,
      reinterpret_cast<const void*>(string_table.get()),
          buffer_size * sizeof(*string_table.get()), REG_MULTI_SZ));

  std::string test_data;
  ASSERT_TRUE(RegistryExtractor::CreateFormattedRegValue(&junk_reg_folder,
      kMultilineKey, kIndent, &test_data));

  std::vector<std::string> source_bits, test_bits;
  base::SplitStringDontTrim(source_data, '\n', &source_bits);
  base::SplitStringDontTrim(test_data, '\n', &test_bits);

  // +1 accounts for the trailing empty bit.
  ASSERT_EQ(source_bits.size(), test_bits.size() + 1);
  ASSERT_TRUE(source_bits.back().empty());

  std::vector<std::string>::const_iterator src_it = source_bits.begin();
  std::vector<std::string>::const_iterator test_it = test_bits.begin();
  ASSERT_EQ(*test_it, *src_it);
  for (++src_it, ++test_it; test_it != test_bits.end(); ++src_it, ++test_it) {
     std::string indented(kIndent, '\t');
     indented.append(*src_it);
     ASSERT_EQ(indented, *test_it);
  }

  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.DeleteKey(L""));
}

// The tested code works around size limitation of retrieved buffers. We want
// to test that.
TEST_F(RegistryExtractorTest, CreateFormattedRegValueLarge) {
  std::wstring test_string_source;
  test_string_source.reserve(2048);
  while (test_string_source.size() < 2000)
    test_string_source.append(L"Yet a bit more! ");

  base::win::RegKey junk_reg_folder(HKEY_CURRENT_USER, kBaseExerciseKey,
                                    KEY_ALL_ACCESS);
  EXPECT_TRUE(junk_reg_folder.Valid());
  EXPECT_EQ(ERROR_SUCCESS,
      junk_reg_folder.WriteValue(L"string_value", test_string_source.c_str()));
  std::string test_data;
  ASSERT_TRUE(RegistryExtractor::CreateFormattedRegValue(&junk_reg_folder,
      L"string_value", 0, &test_data));
  ASSERT_EQ(WideToUTF8(test_string_source), test_data);
  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.DeleteKey(L""));
}

TEST_F(RegistryExtractorTest, CreateFormattedRegValueExpand) {
  // Get an env-string first. Any string.
  wchar_t* env_strings = ::GetEnvironmentStrings();
  ASSERT_TRUE(env_strings != NULL);
  std::vector<std::wstring> all_lines;
  SplitStringFromDblNullTerminated(env_strings, &all_lines);
  ::FreeEnvironmentStrings(env_strings);

  std::vector<std::wstring> assignment;
  for (std::vector<std::wstring>::const_iterator assgn_it = all_lines.begin();
       assgn_it != all_lines.end() && assignment.size() != 2; ++assgn_it) {
    assignment.clear();
    base::SplitString(*assgn_it, L'=', &assignment);
  }

  ASSERT_EQ(assignment.size(), 2);

  std::wstring insert_string = base::StringPrintf(L"Value is %%%ls%%",
                                                  assignment.front().c_str());
  std::wstring test_string = base::StringPrintf(L"Value is %ls",
                                                assignment.back().c_str());
  base::win::RegKey junk_reg_folder(HKEY_CURRENT_USER, kBaseExerciseKey,
                                    KEY_ALL_ACCESS);
  EXPECT_TRUE(junk_reg_folder.Valid());

  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.WriteValue(L"expand_value",
      reinterpret_cast<const void*>(insert_string.c_str()),
          insert_string.size() * sizeof(*insert_string.c_str()),
              REG_EXPAND_SZ));
  std::string test_data;
  ASSERT_TRUE(RegistryExtractor::CreateFormattedRegValue(&junk_reg_folder,
      L"expand_value", 0, &test_data));
  ASSERT_EQ(WideToUTF8(test_string), test_data);

  EXPECT_EQ(ERROR_SUCCESS, junk_reg_folder.DeleteKey(L""));
}

// Tests extracting keys and values fed in different ways.
TEST_F(RegistryExtractorTest, ExtractValues) {
  const wchar_t* kKeyDword = L"dword_value";
  const wchar_t* kKeyString = L"wstring_value";
  const wchar_t* kKeyEmptyString = L"wstring_value_empty";
  const wchar_t* kString1 = L"The answer to life, universe";
  const wchar_t* kString2 = L"and everything.";

  base::win::RegKey reg_folder(HKEY_CURRENT_USER, kListExerciseKey,
                               KEY_ALL_ACCESS);
  EXPECT_TRUE(reg_folder.Valid());
  EXPECT_EQ(ERROR_SUCCESS, reg_folder.WriteValue(kKeyDword, 0x2A));
  EXPECT_EQ(ERROR_SUCCESS, reg_folder.WriteValue(kKeyString, kString1));
  reg_folder.Close();

  EXPECT_EQ(ERROR_SUCCESS, reg_folder.Create(HKEY_LOCAL_MACHINE,
                                             kListExerciseKey, KEY_ALL_ACCESS));
  EXPECT_EQ(ERROR_SUCCESS, reg_folder.WriteValue(kKeyDword, 0x2B));
  EXPECT_EQ(ERROR_SUCCESS, reg_folder.WriteValue(kKeyString, kString2));
  EXPECT_EQ(ERROR_SUCCESS,
            reg_folder.WriteValue(kKeyEmptyString, NULL, 0, REG_SZ));
  reg_folder.Close();

  std::vector<std::wstring> init_list;
  std::set<std::string> answers;  // What do we expect to see.
  std::wstring insert_word(L"HKEY_CURRENT_USER\\");
  insert_word += kListExerciseKey;
  insert_word += L"\\";

  init_list.push_back(insert_word);
  init_list.back() += kKeyDword;
  answers.insert(WideToUTF8(StringPrintf(L"%ls\t(0x%0*X)",
                                         init_list.back().c_str(), 8, 0x2A)));
  init_list.push_back(insert_word);
  init_list.back() += kKeyString;
  answers.insert(WideToUTF8(StringPrintf(L"%ls\t(%ls)",
                                         init_list.back().c_str(), kString1)));

  insert_word = L"HKEY_LOCAL_MACHINE\\";
  insert_word += kListExerciseKey;
  insert_word += L"\\";
  init_list.push_back(insert_word);
  init_list.back() += kKeyDword;
  answers.insert(WideToUTF8(StringPrintf(L"%ls\t(0x%0*X)",
                                         init_list.back().c_str(), 8, 0x2B)));
  init_list.push_back(insert_word);
  init_list.back() += kKeyString;
  answers.insert(WideToUTF8(StringPrintf(L"%ls\t(%ls)",
                                         init_list.back().c_str(), kString2)));
  init_list.push_back(insert_word);
  init_list.back() += kKeyEmptyString;
  answers.insert(WideToUTF8(StringPrintf(L"%ls\t()",
                                         init_list.back().c_str())));
  {
    RegistryExtractor harvester;
    ASSERT_EQ(init_list.size(), harvester.Initialize(init_list));

    // Retrieve data and check that it is correct.
    std::string all_content(std::istreambuf_iterator<char>(harvester.Data()),
                            std::istreambuf_iterator<char>());
    std::vector<std::string> file_lines;
    base::SplitString(all_content, '\n', &file_lines);
    ASSERT_EQ(std::count_if(file_lines.begin(), file_lines.end(),
                            std::not1(std::mem_fun_ref(&std::string::empty))),
              answers.size());
    for (std::vector<std::string>::const_iterator line_it = file_lines.begin();
         line_it != file_lines.end(); ++line_it) {
      if (line_it->empty())
        continue;
      ASSERT_FALSE(answers.find(*line_it) == answers.end());
    }
  }

  // Now report it as directories.
  init_list.clear();
  init_list.push_back(L"HKEY_LOCAL_MACHINE\\");
  init_list.back() += kListExerciseKey;
  init_list.push_back(L"HKEY_CURRENT_USER\\");
  init_list.back() += kListExerciseKey;

  {
    RegistryExtractor harvester;
    ASSERT_EQ(init_list.size(), harvester.Initialize(init_list));

    // Retrieve data and check that it is correct.
    std::string all_content(std::istreambuf_iterator<char>(harvester.Data()),
                            std::istreambuf_iterator<char>());
    std::vector<std::string> file_lines;
    base::SplitString(all_content, '\n', &file_lines);
    ASSERT_EQ(std::count_if(file_lines.begin(), file_lines.end(),
                            std::not1(std::mem_fun_ref(&std::string::empty))),
              answers.size() + init_list.size());  // Expect headers and values.

    std::string current_header;
    for (std::vector<std::string>::const_iterator line_it = file_lines.begin();
         line_it != file_lines.end(); ++line_it) {
      if (line_it->empty())
        continue;
      if (line_it->find('\t') == std::string::npos) {
        current_header = *line_it;
      } else {
        std::string sought_line = current_header + "\\" + *line_it;
        ASSERT_FALSE(answers.find(sought_line) == answers.end());
      }
    }
  }

  // Now try the mixed approach.
  // Now report it as directories.
  std::set<std::string> headers;
  init_list.clear();
  init_list.push_back(L"HKEY_CURRENT_USER\\");
  init_list.back() += kListExerciseKey;
  headers.insert(WideToUTF8(init_list.back()));

  insert_word = L"HKEY_LOCAL_MACHINE\\";
  insert_word += kListExerciseKey;
  insert_word += L"\\";
  init_list.push_back(insert_word);
  init_list.back() += kKeyDword;

  init_list.push_back(insert_word);
  init_list.back() += kKeyString;
  init_list.push_back(insert_word);
  init_list.back() += kKeyEmptyString;

  {
    RegistryExtractor harvester;
    ASSERT_EQ(init_list.size(), harvester.Initialize(init_list));

    // Retrieve data and check that it is correct.
    std::string all_content(std::istreambuf_iterator<char>(harvester.Data()),
                            std::istreambuf_iterator<char>());
    std::vector<std::string> file_lines;
    base::SplitString(all_content, '\n', &file_lines);
    ASSERT_EQ(std::count_if(file_lines.begin(), file_lines.end(),
                            std::not1(std::mem_fun_ref(&std::string::empty))),
              answers.size() + headers.size());

    std::string current_header;
    for (std::vector<std::string>::const_iterator line_it = file_lines.begin();
         line_it != file_lines.end(); ++line_it) {
      if (line_it->empty())
        continue;
      if (headers.find(*line_it) != headers.end()) {
        current_header = *line_it;
      } else {
        std::string sought_line = current_header + "\\" + *line_it;
        ASSERT_TRUE(answers.find(sought_line) != answers.end() ||
                    (line_it->find("HKEY") == 0 &&
                     answers.find(*line_it) != answers.end()));
      }
    }
  }

  // Now we will trust it to remove redundancies.
  init_list.push_back(L"HKEY_LOCAL_MACHINE\\");
  init_list.back() += kListExerciseKey;
  headers.insert(WideToUTF8(init_list.back()));

  {
    RegistryExtractor harvester;
    ASSERT_EQ(headers.size(), harvester.Initialize(init_list));

    // Retrieve data and check that it is correct.
    std::string all_content(std::istreambuf_iterator<char>(harvester.Data()),
                            std::istreambuf_iterator<char>());
    std::vector<std::string> file_lines;
    base::SplitString(all_content, '\n', &file_lines);
    ASSERT_EQ(std::count_if(file_lines.begin(), file_lines.end(),
                            std::not1(std::mem_fun_ref(&std::string::empty))),
              answers.size() + headers.size());  // Expect headers and values.

    std::string current_header;
    for (std::vector<std::string>::const_iterator line_it = file_lines.begin();
         line_it != file_lines.end(); ++line_it) {
      if (line_it->empty())
        continue;
      if (line_it->find('\t') == std::string::npos) {
        current_header = *line_it;
      } else {
        std::string sought_line = current_header + "\\" + *line_it;
        ASSERT_FALSE(answers.find(sought_line) == answers.end());
      }
    }
  }
}

TEST_F(RegistryExtractorTest, RecursiveDescent) {
  std::set<std::string> subtree_1;
  base::win::RegKey reg_folder(HKEY_CURRENT_USER, kTreeExerciseKey,
                               KEY_ALL_ACCESS);
  std::wstring root_string_1(L"HKEY_CURRENT_USER\\");
  root_string_1 += kTreeExerciseKey;
  subtree_1.insert(WideToUTF8(root_string_1));

  reg_folder.WriteValue(L"Value_DW1", 42);
  subtree_1.insert(StringPrintf("Value_DW1\t(0x%0*X)", 8, 42));
  reg_folder.WriteValue(L"Value_Str1", L"A text value");
  subtree_1.insert("Value_Str1\t(A text value)");
  reg_folder.WriteValue(L"Value_Str2", L"Another text");
  subtree_1.insert("Value_Str2\t(Another text)");
  reg_folder.CreateKey(L"Branch_A", KEY_ALL_ACCESS);
  subtree_1.insert("Branch_A");

  reg_folder.WriteValue(L"Value_DW1", 43);
  subtree_1.insert(StringPrintf("Value_DW1\t(0x%0*X)", 8, 43));
  reg_folder.WriteValue(L"Value_Str1", L"A text value 1");
  subtree_1.insert("Value_Str1\t(A text value 1)");
  reg_folder.WriteValue(L"Value_Str2", L"Another text 1");
  subtree_1.insert("Value_Str2\t(Another text 1)");

  reg_folder.Open(HKEY_CURRENT_USER, kTreeExerciseKey, KEY_ALL_ACCESS);
  reg_folder.CreateKey(L"Branch_B", KEY_ALL_ACCESS);
  subtree_1.insert("Branch_B");

  reg_folder.WriteValue(L"Value_DW1", 44);
  subtree_1.insert(StringPrintf("Value_DW1\t(0x%0*X)", 8, 44));
  reg_folder.WriteValue(L"Value_Str1", L"A text value 2");
  subtree_1.insert("Value_Str1\t(A text value 2)");
  reg_folder.WriteValue(L"Value_Str2", L"Another text 2");
  subtree_1.insert("Value_Str2\t(Another text 2)");

  std::set<std::string> subtree_2;
  reg_folder.Create(HKEY_LOCAL_MACHINE, kTreeExerciseKey, KEY_ALL_ACCESS);
  std::wstring root_string_2(L"HKEY_LOCAL_MACHINE\\");
  root_string_2 += kTreeExerciseKey;
  subtree_2.insert(WideToUTF8(root_string_2));

  reg_folder.WriteValue(L"Value_DW1", 45);
  subtree_2.insert(StringPrintf("Value_DW1\t(0x%0*X)", 8, 45));
  reg_folder.WriteValue(L"Value_Str1", L"A text value 3");
  subtree_2.insert("Value_Str1\t(A text value 3)");
  reg_folder.WriteValue(L"Value_Str2", L"Another text 3");
  subtree_2.insert("Value_Str2\t(Another text 3)");
  reg_folder.CreateKey(L"Branch_AA", KEY_ALL_ACCESS);
  subtree_2.insert("Branch_AA");

  reg_folder.WriteValue(L"Value_DW1", 46);
  subtree_2.insert(StringPrintf("Value_DW1\t(0x%0*X)", 8, 46));
  reg_folder.WriteValue(L"Value_Str1", L"A text value 4");
  subtree_2.insert("Value_Str1\t(A text value 4)");
  reg_folder.WriteValue(L"Value_Str2", L"Another text 4");
  subtree_2.insert("Value_Str2\t(Another text 4)");

  std::vector<std::wstring> init_box;
  init_box.push_back(root_string_1);
  init_box.push_back(root_string_2);

  RegistryExtractor harvester;
  ASSERT_EQ(harvester.Initialize(init_box), 2);

  std::string all_content(std::istreambuf_iterator<char>(harvester.Data()),
                          std::istreambuf_iterator<char>());
  std::vector<std::string> file_lines;
  base::SplitString(all_content, '\n', &file_lines);
  ASSERT_EQ(std::count_if(file_lines.begin(), file_lines.end(),
                          std::not1(std::mem_fun_ref(&std::string::empty))),
            subtree_1.size() + subtree_2.size());  // Expect headers and values.

  std::set<std::string>* current_subtree = NULL;
  for (std::vector<std::string>::const_iterator line_it = file_lines.begin();
         line_it != file_lines.end(); ++line_it) {
    if (line_it->empty())
      continue;

    if (line_it->find("HKEY_CURRENT_USER") == 0) {
      current_subtree = &subtree_1;
    } else if (line_it->find("HKEY_LOCAL_MACHINE") == 0) {
      current_subtree = &subtree_2;
    } else {
      ASSERT_TRUE(current_subtree != NULL);
      ASSERT_FALSE(current_subtree->find(*line_it) == current_subtree->end());
    }
  }
}

}  // namespace
