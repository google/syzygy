// Copyright 2011 Google Inc. All Rights Reserved.
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

#include "syzygy/core/serialization.h"
#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"

namespace core {

namespace {

const Byte kTestData[] = "This is test data.";

struct Foo {
  int i;
  double d;
  char s[128];

  Foo() : i(0), d(0) {
    memset(s, 0, sizeof(s));
  }

  bool operator==(const Foo& foo) const {
    return i == foo.i && d == foo.d && !memcmp(s, foo.s, sizeof(s));
  }

  // These are the serialization implementation.
  template<class OutArchive> bool Save(OutArchive* out_archive) const {
    return out_archive->Save(i) && out_archive->Save(d) &&
        out_archive->Save(s);
  }
  template<class InArchive> bool Load(InArchive* in_archive) {
    return in_archive->Load(&i) && in_archive->Load(&d) &&
        in_archive->Load(&s);
  }
};

}  // namespace

class SerializationTest : public testing::Test {
 public:
  virtual void SetUp() {
    ASSERT_TRUE(base::CreateNewTempDirectory(L"", &temp_dir_));
  }

  virtual void TearDown() {
    base::DeleteFile(temp_dir_, true);
  }

  template<typename Data> bool TestRoundTrip(const Data& data) {
    base::FilePath path;
    base::ScopedFILE file;
    file.reset(base::CreateAndOpenTemporaryFileInDir(temp_dir_, &path));
    EXPECT_TRUE(file.get() != NULL);
    EXPECT_FALSE(path.empty());

    EXPECT_TRUE(testing::TestSerialization(data));
    EXPECT_TRUE(testing::TestSerialization(data, file.get()));

    return true;
  }

  const base::FilePath& temp_dir() const { return temp_dir_; }

 private:
  base::FilePath temp_dir_;
};

TEST_F(SerializationTest, IteratorOutStream) {
  ByteVector bytes;
  ScopedOutStreamPtr out_stream;
  out_stream.reset(CreateByteOutStream(std::back_inserter(bytes)));

  // Writing data should work, and should match the source data.
  EXPECT_TRUE(out_stream->Write(2, kTestData));
  EXPECT_TRUE(out_stream->Write(sizeof(kTestData) - 2, kTestData + 2));
  EXPECT_EQ(sizeof(kTestData), bytes.size());
  EXPECT_EQ(0, memcmp(&bytes[0], kTestData, sizeof(kTestData)));
}

TEST_F(SerializationTest, IteratorInStream) {
  // Populate a vector of bytes with some test data, and wrap a ByteInStream
  // around it.
  ByteVector bytes;
  bytes.resize(sizeof(kTestData));
  std::copy(kTestData, kTestData + sizeof(kTestData), bytes.begin());
  ScopedInStreamPtr in_stream;
  in_stream.reset(CreateByteInStream(bytes.begin(), bytes.end()));

  // Reading data should work, and should match the source data.
  Byte buffer[sizeof(kTestData)];
  EXPECT_TRUE(in_stream->Read(2, buffer));
  EXPECT_TRUE(in_stream->Read(sizeof(kTestData) - 2, buffer + 2));
  EXPECT_EQ(0, memcmp(&bytes[0], kTestData, sizeof(kTestData)));

  // We should not be able to read past the end of an exhausted buffer.
  EXPECT_FALSE(in_stream->Read(sizeof(kTestData), buffer));
}

TEST_F(SerializationTest, FileOutStream) {
  base::FilePath path;
  base::ScopedFILE file;
  file.reset(base::CreateAndOpenTemporaryFileInDir(temp_dir(), &path));
  EXPECT_TRUE(file.get() != NULL);
  EXPECT_FALSE(path.empty());

  FileOutStream out_stream(file.get());

  // Write some test data to a file.
  EXPECT_TRUE(out_stream.Write(2, kTestData));
  EXPECT_TRUE(out_stream.Write(sizeof(kTestData) - 2, kTestData + 2));

  // Load the data from the file and ensure it matches the original data.
  file.reset();
  file.reset(base::OpenFile(path, "rb"));
  Byte buffer[sizeof(kTestData)];
  EXPECT_EQ(sizeof(kTestData), fread(buffer, 1, sizeof(kTestData),
                                     file.get()));
  EXPECT_EQ(0, memcmp(buffer, kTestData, sizeof(kTestData)));
}

TEST_F(SerializationTest, FileInStream) {
  base::FilePath path;
  base::ScopedFILE file;
  file.reset(base::CreateAndOpenTemporaryFileInDir(temp_dir(), &path));
  EXPECT_TRUE(file.get() != NULL);
  EXPECT_FALSE(path.empty());

  // Write some test data to a file, then close and reopen it for reading.
  EXPECT_EQ(sizeof(kTestData), fwrite(kTestData, 1, sizeof(kTestData),
                                      file.get()));
  file.reset();
  file.reset(base::OpenFile(path, "rb"));

  FileInStream in_stream(file.get());
  Byte buffer[sizeof(kTestData)];
  EXPECT_TRUE(in_stream.Read(sizeof(kTestData), buffer));
  EXPECT_EQ(0, memcmp(buffer, kTestData, sizeof(kTestData)));

  // We should not be able to read any more data.
  EXPECT_FALSE(in_stream.Read(sizeof(kTestData), buffer));
}

TEST_F(SerializationTest, PlainOldDataTypesRoundTrip) {
  EXPECT_TRUE(TestRoundTrip<bool>(true));
  EXPECT_TRUE(TestRoundTrip<char>('c'));
  EXPECT_TRUE(TestRoundTrip<wchar_t>(L'c'));
  EXPECT_TRUE(TestRoundTrip<float>(0.1f));
  EXPECT_TRUE(TestRoundTrip<double>(9.7e45));
  EXPECT_TRUE(TestRoundTrip<int8>(-8));
  EXPECT_TRUE(TestRoundTrip<int16>(-16));
  EXPECT_TRUE(TestRoundTrip<int32>(-32));
  EXPECT_TRUE(TestRoundTrip<int64>(-64));
  EXPECT_TRUE(TestRoundTrip<uint8>(8));
  EXPECT_TRUE(TestRoundTrip<uint16>(16));
  EXPECT_TRUE(TestRoundTrip<uint32>(32));
  EXPECT_TRUE(TestRoundTrip<uint64>(64));
}

TEST_F(SerializationTest, StlTypesRoundTrip) {
  std::string string = "This is a string.";
  EXPECT_TRUE(TestRoundTrip<std::string>(string));

  std::wstring wstring = L"This is a wstring.";
  EXPECT_TRUE(TestRoundTrip<std::wstring>(wstring));

  std::map<int, int> map;
  map.insert(std::make_pair(0, 1));
  map.insert(std::make_pair(1, -1));
  map.insert(std::make_pair(100, 42));
  EXPECT_TRUE(TestRoundTrip(map));

  std::pair<int, int> pair(0, 1);
  EXPECT_TRUE(TestRoundTrip(pair));

  std::set<int> set;
  set.insert(0);
  set.insert(2);
  set.insert(4);
  EXPECT_TRUE(TestRoundTrip(set));

  std::vector<int> vector;
  vector.push_back(1);
  vector.push_back(3);
  vector.push_back(5);
  EXPECT_TRUE(TestRoundTrip(vector));
}

TEST_F(SerializationTest, CustomTypeRoundTrip) {
  const char string[] = "I'm fond of jellybeans.";

  Foo foo;
  foo.i = 42;
  foo.d = 13.7;
  memcpy(foo.s, string, sizeof(string));

  EXPECT_TRUE(TestRoundTrip(foo));
}

}  // namespace core
