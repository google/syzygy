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

#include "syzygy/core/json_file_writer.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "base/memory/scoped_temp_dir.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace core {

namespace {

class TestJSONFileWriter : public JSONFileWriter {
 public:
  explicit TestJSONFileWriter(FILE* file, bool pretty_print)
      : JSONFileWriter(file, pretty_print) {}

  // Make the internal state functions public.
  using JSONFileWriter::FirstEntry;
  using JSONFileWriter::ReadyForKey;
  using JSONFileWriter::ReadyForValue;
  using JSONFileWriter::RequireKeyValue;
  using JSONFileWriter::CanClose;

  // Make the enumeration values public.
  using JSONFileWriter::kDict;
  using JSONFileWriter::kList;
};

class JSONFileWriterTest: public testing::Test {
 public:
  virtual void SetUp() {
    // Initialize the temp directory for the first test.
    if (temp_dir_.get() == NULL) {
      temp_dir_.reset(new ScopedTempDir());
      ASSERT_TRUE(temp_dir_->CreateUniqueTempDir());
    }

    FilePath path;
    file_.reset(file_util::CreateAndOpenTemporaryFileInDir(temp_dir_->path(),
                                                           &path));
  }

  // Returns the contents of the file, leaving the cursor at the end of the
  // file for further writing.
  bool FileContents(std::string* contents) {
    DCHECK(contents != NULL);

    long length = ftell(file_.get());
    if (length < 0)
      return false;

    contents->resize(length);
    if (length == 0)
      return true;

    if (fseek(file_.get(), 0, SEEK_SET))
      return false;

    if (fread(&(*contents)[0], 1, length, file_.get()) !=
        static_cast<size_t>(length)) {
      return false;
    }

    if (fseek(file_.get(), 0, SEEK_END))
      return false;

    return true;
  }

  FILE* file() {
    return file_.get();
  }

 private:
  // This is static so that a single temp directory is made for all of the
  // unittests, rather than one per instance.
  static scoped_ptr<ScopedTempDir> temp_dir_;
  file_util::ScopedFILE file_;
};

scoped_ptr<ScopedTempDir> JSONFileWriterTest::temp_dir_;

void CreateDict(TestJSONFileWriter* json_file) {
  ASSERT_TRUE(json_file != NULL);

  ASSERT_TRUE(json_file->FirstEntry());
  ASSERT_TRUE(json_file->ReadyForValue());
  ASSERT_FALSE(json_file->RequireKeyValue());

  EXPECT_TRUE(json_file->OutputComment("comment"));
  EXPECT_TRUE(json_file->OpenDict());
  ASSERT_TRUE(json_file->FirstEntry());
  ASSERT_TRUE(json_file->ReadyForKey());
  ASSERT_FALSE(json_file->RequireKeyValue());
  ASSERT_TRUE(json_file->CanClose(TestJSONFileWriter::kDict));

  EXPECT_TRUE(json_file->OutputComment(L"comment"));
  EXPECT_TRUE(json_file->OutputKey("sample key 1"));
  ASSERT_FALSE(json_file->ReadyForKey());
  ASSERT_TRUE(json_file->RequireKeyValue());

  // We shouldn't be able to write a comment in the middle of a key/value pair,
  // nor should we be able to close the dictionary.
  EXPECT_FALSE(json_file->OutputComment("comment"));
  ASSERT_FALSE(json_file->CanClose(TestJSONFileWriter::kDict));

  EXPECT_TRUE(json_file->OutputString("sample value"));
  ASSERT_FALSE(json_file->FirstEntry());
  ASSERT_TRUE(json_file->ReadyForKey());
  ASSERT_FALSE(json_file->RequireKeyValue());
  ASSERT_TRUE(json_file->CanClose(TestJSONFileWriter::kDict));

  EXPECT_TRUE(json_file->OutputKey("sample key 2"));
  ASSERT_FALSE(json_file->ReadyForKey());
  ASSERT_TRUE(json_file->RequireKeyValue());
  ASSERT_FALSE(json_file->CanClose(TestJSONFileWriter::kDict));

  EXPECT_TRUE(json_file->OutputInteger(5));
  ASSERT_FALSE(json_file->FirstEntry());
  ASSERT_TRUE(json_file->ReadyForKey());
  ASSERT_FALSE(json_file->RequireKeyValue());
  ASSERT_TRUE(json_file->CanClose(TestJSONFileWriter::kDict));

  EXPECT_TRUE(json_file->OutputTrailingComment("trailing comment"));
  EXPECT_FALSE(json_file->OutputTrailingComment(L"foo"));

  EXPECT_TRUE(json_file->OutputComment("comment"));

  EXPECT_TRUE(json_file->CloseDict());
  ASSERT_TRUE(json_file->Finished());
}

void CreateList(TestJSONFileWriter* json_file) {
  ASSERT_TRUE(json_file != NULL);

  ASSERT_TRUE(json_file->FirstEntry());
  ASSERT_TRUE(json_file->ReadyForValue());
  ASSERT_FALSE(json_file->RequireKeyValue());

  EXPECT_TRUE(json_file->OpenList());
  ASSERT_TRUE(json_file->FirstEntry());
  ASSERT_FALSE(json_file->RequireKeyValue());
  ASSERT_TRUE(json_file->CanClose(TestJSONFileWriter::kList));

  EXPECT_TRUE(json_file->OutputString("sample value"));
  ASSERT_FALSE(json_file->FirstEntry());
  ASSERT_FALSE(json_file->RequireKeyValue());
  ASSERT_TRUE(json_file->CanClose(TestJSONFileWriter::kList));

  EXPECT_TRUE(json_file->OutputComment(L"comment"));

  EXPECT_TRUE(json_file->OutputDouble(4.5));
  ASSERT_FALSE(json_file->FirstEntry());
  ASSERT_FALSE(json_file->RequireKeyValue());
  ASSERT_TRUE(json_file->CanClose(TestJSONFileWriter::kList));

  EXPECT_TRUE(json_file->OutputBoolean(false));
  ASSERT_FALSE(json_file->FirstEntry());
  ASSERT_FALSE(json_file->RequireKeyValue());
  ASSERT_TRUE(json_file->CanClose(TestJSONFileWriter::kList));

  EXPECT_TRUE(json_file->OutputTrailingComment("trailing comment"));
  EXPECT_FALSE(json_file->OutputTrailingComment(L"foo"));

  EXPECT_TRUE(json_file->OutputComment("comment"));

  EXPECT_TRUE(json_file->CloseList());
  ASSERT_TRUE(json_file->Finished());

  EXPECT_TRUE(json_file->OutputComment("comment"));
}

void CreateNested(TestJSONFileWriter* json_file) {
  ASSERT_TRUE(json_file != NULL);

  ASSERT_TRUE(json_file->FirstEntry());
  ASSERT_TRUE(json_file->ReadyForValue());
  ASSERT_FALSE(json_file->RequireKeyValue());

  EXPECT_TRUE(json_file->OpenDict());
  ASSERT_FALSE(json_file->ReadyForValue());
  ASSERT_FALSE(json_file->RequireKeyValue());

  EXPECT_TRUE(json_file->OutputComment("comment"));

  EXPECT_TRUE(json_file->OutputKey("key"));
  ASSERT_TRUE(json_file->ReadyForValue());
  ASSERT_TRUE(json_file->RequireKeyValue());

  EXPECT_TRUE(json_file->OpenList());
  ASSERT_TRUE(json_file->ReadyForValue());
  ASSERT_FALSE(json_file->RequireKeyValue());

  EXPECT_TRUE(json_file->OutputNull());
  ASSERT_TRUE(json_file->ReadyForValue());
  ASSERT_FALSE(json_file->RequireKeyValue());

  EXPECT_TRUE(json_file->OutputTrailingComment("trailing comment"));
  EXPECT_FALSE(json_file->OutputTrailingComment("foo"));

  EXPECT_TRUE(json_file->Flush());
  EXPECT_TRUE(json_file->Finished());

  EXPECT_TRUE(json_file->OutputComment("comment"));
}

}  // namespace

TEST_F(JSONFileWriterTest, OutputBoolean) {
  TestJSONFileWriter json_file(file(), false);
  ASSERT_TRUE(json_file.FirstEntry());
  ASSERT_TRUE(json_file.ReadyForValue());
  ASSERT_FALSE(json_file.RequireKeyValue());

  EXPECT_TRUE(json_file.OutputBoolean(true));
  ASSERT_TRUE(json_file.Finished());

  std::string s;
  ASSERT_TRUE(FileContents(&s));
  ASSERT_EQ("true", s);
}

TEST_F(JSONFileWriterTest, OutputInteger) {
  TestJSONFileWriter json_file(file(), false);
  ASSERT_TRUE(json_file.FirstEntry());
  ASSERT_TRUE(json_file.ReadyForValue());
  ASSERT_FALSE(json_file.RequireKeyValue());

  EXPECT_TRUE(json_file.OutputInteger(11));
  ASSERT_TRUE(json_file.Finished());

  std::string s;
  ASSERT_TRUE(FileContents(&s));
  ASSERT_EQ("11", s);
}

TEST_F(JSONFileWriterTest, OutputDouble) {
  TestJSONFileWriter json_file(file(), false);
  ASSERT_TRUE(json_file.FirstEntry());
  ASSERT_TRUE(json_file.ReadyForValue());
  ASSERT_FALSE(json_file.RequireKeyValue());

  EXPECT_TRUE(json_file.OutputDouble(4.5));
  ASSERT_TRUE(json_file.Finished());

  std::string s;
  ASSERT_TRUE(FileContents(&s));
  ASSERT_EQ("4.5", s);
}

TEST_F(JSONFileWriterTest, OutputString) {
  TestJSONFileWriter json_file(file(), false);
  ASSERT_TRUE(json_file.FirstEntry());
  ASSERT_TRUE(json_file.ReadyForValue());
  ASSERT_FALSE(json_file.RequireKeyValue());

  EXPECT_TRUE(json_file.OutputString("sample string"));
  ASSERT_TRUE(json_file.Finished());

  std::string s;
  ASSERT_TRUE(FileContents(&s));
  ASSERT_EQ("\"sample string\"", s);
}

TEST_F(JSONFileWriterTest, OutputWstring) {
  TestJSONFileWriter json_file(file(), false);
  ASSERT_TRUE(json_file.FirstEntry());
  ASSERT_TRUE(json_file.ReadyForValue());
  ASSERT_FALSE(json_file.RequireKeyValue());

  EXPECT_TRUE(json_file.OutputString(L"sample string"));
  ASSERT_TRUE(json_file.Finished());

  std::string s;
  ASSERT_TRUE(FileContents(&s));
  ASSERT_EQ("\"sample string\"", s);
}

TEST_F(JSONFileWriterTest, OutputNull) {
  TestJSONFileWriter json_file(file(), false);
  ASSERT_TRUE(json_file.FirstEntry());
  ASSERT_TRUE(json_file.ReadyForValue());
  ASSERT_FALSE(json_file.RequireKeyValue());

  EXPECT_TRUE(json_file.OutputNull());
  ASSERT_TRUE(json_file.Finished());

  std::string s;
  ASSERT_TRUE(FileContents(&s));
  ASSERT_EQ("null", s);
}

TEST_F(JSONFileWriterTest, DestructorAutoFlushes) {
  {
    TestJSONFileWriter json_file(file(), false);
    EXPECT_TRUE(json_file.OpenList());
    EXPECT_TRUE(json_file.OpenDict());
  }

  std::string s;
  ASSERT_TRUE(FileContents(&s));

  std::string expected = "[{}]";

  ASSERT_EQ(expected, s);
}

TEST_F(JSONFileWriterTest, OutputDict) {
  TestJSONFileWriter json_file(file(), false);
  ASSERT_NO_FATAL_FAILURE(CreateDict(&json_file));

  std::string s;
  ASSERT_TRUE(FileContents(&s));

  std::string expected = "{\"sample key 1\":\"sample value\","
      "\"sample key 2\":5}";

  ASSERT_EQ(expected, s);
}

TEST_F(JSONFileWriterTest, OutputDictPrettyPrint) {
  TestJSONFileWriter json_file(file(), true);
  ASSERT_NO_FATAL_FAILURE(CreateDict(&json_file));

  std::string s;
  ASSERT_TRUE(FileContents(&s));

  std::string expected =
      "// comment\n"
      "{\n"
      "  // comment\n"
      "  \"sample key 1\": \"sample value\",\n"
      "  \"sample key 2\": 5  // trailing comment\n"
      "  // comment\n"
      "}";

  ASSERT_EQ(expected, s);
}

TEST_F(JSONFileWriterTest, OutputList) {
  TestJSONFileWriter json_file(file(), false);
  ASSERT_NO_FATAL_FAILURE(CreateList(&json_file));

  std::string s;
  ASSERT_TRUE(FileContents(&s));

  std::string expected = "[\"sample value\",4.5,false]";

  ASSERT_EQ(expected, s);
}

TEST_F(JSONFileWriterTest, OutputListPrettyPrint) {
  TestJSONFileWriter json_file(file(), true);
  ASSERT_NO_FATAL_FAILURE(CreateList(&json_file));

  std::string s;
  ASSERT_TRUE(FileContents(&s));

  std::string expected =
      "[\n"
      "  \"sample value\",\n"
      "  // comment\n"
      "  4.5,\n"
      "  false  // trailing comment\n"
      "  // comment\n"
      "]\n"
      "// comment";

  ASSERT_EQ(expected, s);
}

TEST_F(JSONFileWriterTest, Nested) {
  TestJSONFileWriter json_file(file(), false);
  ASSERT_NO_FATAL_FAILURE(CreateNested(&json_file));

  std::string s;
  ASSERT_TRUE(FileContents(&s));

  std::string expected = "{\"key\":[null]}";

  ASSERT_EQ(expected, s);
}

TEST_F(JSONFileWriterTest, NestedPrettyPrint) {
  TestJSONFileWriter json_file(file(), true);
  ASSERT_NO_FATAL_FAILURE(CreateNested(&json_file));

  std::string s;
  ASSERT_TRUE(FileContents(&s));

  std::string expected =
      "{\n"
      "  // comment\n"
      "  \"key\": [\n"
      "    null  // trailing comment\n"
      "  ]\n"
      "}\n"
      "// comment";

  ASSERT_EQ(expected, s);
}

TEST_F(JSONFileWriterTest, MismatchedDictionaryCausesError) {
  TestJSONFileWriter json_file(file(), false);
  EXPECT_TRUE(json_file.OpenDict());
  EXPECT_FALSE(json_file.CloseList());
}

TEST_F(JSONFileWriterTest, MissingDictionaryKeyCausesError) {
  TestJSONFileWriter json_file(file(), false);
  EXPECT_TRUE(json_file.OpenDict());
  EXPECT_FALSE(json_file.OutputBoolean(false));
}

TEST_F(JSONFileWriterTest, MissingDictionaryValueCausesError) {
  TestJSONFileWriter json_file(file(), false);
  EXPECT_TRUE(json_file.OpenDict());
  EXPECT_TRUE(json_file.OutputKey("key1"));
  EXPECT_FALSE(json_file.OutputKey("key2"));
}

TEST_F(JSONFileWriterTest, MismatchedListCausesError) {
  TestJSONFileWriter json_file(file(), false);
  EXPECT_TRUE(json_file.OpenList());
  EXPECT_FALSE(json_file.CloseDict());
}

TEST_F(JSONFileWriterTest, TrailingCommentSingleValue) {
  TestJSONFileWriter json_file(file(), true);
  ASSERT_TRUE(json_file.ReadyForValue());
  ASSERT_FALSE(json_file.Finished());

  EXPECT_TRUE(json_file.OutputInteger(2));
  ASSERT_FALSE(json_file.ReadyForValue());
  ASSERT_TRUE(json_file.Finished());

  EXPECT_TRUE(json_file.OutputTrailingComment("trailing comment"));

  std::string s;
  ASSERT_TRUE(FileContents(&s));

  std::string expected = "2  // trailing comment";

  ASSERT_EQ(expected, s);
}

}  // namespace core
