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

#include "syzygy/pdb/pdb_symbol_record.h"

#include "base/bind.h"
#include "base/files/file_util.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/common/binary_stream.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/unittest_util.h"
#include "third_party/cci/Files/CvInfo.h"

namespace cci = Microsoft_Cci_Pdb;

namespace pdb {

namespace {

using testing::_;
using testing::Return;

class PdbVisitSymbolsTest : public testing::Test {
 public:
  void SetUpByteStream() {
    reader = new PdbByteStream();
    writer = reader->GetWritableStream();
  }

  scoped_refptr<PdbStream> reader;
  scoped_refptr<WritablePdbStream> writer;
};

class MockVisitorImpl {
 public:
  MOCK_METHOD3(Callback, bool(uint16_t, uint16_t, common::BinaryStreamReader*));
};
typedef testing::StrictMock<MockVisitorImpl> MockVisitor;

}  // namespace

#if 0
TEST(PdbReadSymbolRecordTest, ReadValidSymRecordStream) {
  base::FilePath valid_sym_record_path = testing::GetSrcRelativePath(
      testing::kValidPdbSymbolRecordStreamPath);

  scoped_refptr<pdb::PdbFileStream> valid_sym_record_stream =
      testing::GetStreamFromFile(valid_sym_record_path);
  SymbolRecordVector symbol_vector;
  EXPECT_TRUE(ReadSymbolRecord(valid_sym_record_stream.get(),
                               valid_sym_record_stream->length(),
                               &symbol_vector));
}

TEST(PdbReadSymbolRecordTest, ReadInvalidSymRecordStream) {
  base::FilePath invalid_sym_record_path = testing::GetSrcRelativePath(
      testing::kInvalidPdbSymbolRecordStreamPath);

  scoped_refptr<pdb::PdbFileStream> invalid_sym_record_stream =
      testing::GetStreamFromFile(invalid_sym_record_path);
  SymbolRecordVector symbol_vector;
  EXPECT_FALSE(ReadSymbolRecord(invalid_sym_record_stream.get(),
                                invalid_sym_record_stream->length(),
                                &symbol_vector));
}
#endif

TEST_F(PdbVisitSymbolsTest, FailsOnInvalidTableSize) {
  SetUpByteStream();
  writer->Write(static_cast<uint32_t>(cci::C13));  // Symbol stream type.
  writer->Write(static_cast<uint16_t>(4));         // Symbol length.
  writer->Write(static_cast<uint16_t>(0x2937));    // Made up symbol type.
  writer->Write(static_cast<uint16_t>(0));         // Dummy data.

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  // Don't expect any calls to the visitor callback.
  EXPECT_FALSE(
      VisitSymbols(callback, 0, 2 * reader->length(), true, reader.get()));
}

TEST_F(PdbVisitSymbolsTest, FailsOnMissingStreamType) {
  SetUpByteStream();

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  // Don't expect any calls to the visitor callback.
  EXPECT_FALSE(VisitSymbols(callback, 0, reader->length(), true, reader.get()));
}

TEST_F(PdbVisitSymbolsTest, FailsOnInvalidStreamType) {
  SetUpByteStream();
  writer->Write(static_cast<uint32_t>(cci::C11));  // Symbol stream type.
  writer->Write(static_cast<uint16_t>(0));         // Symbol length.

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  // Don't expect any calls to the visitor callback.
  EXPECT_FALSE(VisitSymbols(callback, 0, reader->length(), true, reader.get()));
}

TEST_F(PdbVisitSymbolsTest, FailsOnMissingSymbolLength) {
  SetUpByteStream();
  writer->Write(static_cast<uint32_t>(cci::C13));  // Symbol stream type.
  writer->Write(static_cast<uint8_t>(1));  // Partial symbol stream length.

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  // Don't expect any calls to the visitor callback.
  EXPECT_FALSE(VisitSymbols(callback, 0, reader->length(), true, reader.get()));
}

TEST_F(PdbVisitSymbolsTest, FailsOnShortSymbolLength) {
  SetUpByteStream();
  writer->Write(static_cast<uint32_t>(cci::C13));  // Symbol stream type.
  writer->Write(static_cast<uint16_t>(1));         // Symbol length.

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  // Don't expect any calls to the visitor callback.
  EXPECT_FALSE(VisitSymbols(callback, 0, reader->length(), true, reader.get()));
}

TEST_F(PdbVisitSymbolsTest, FailsOnMissingSymbolType) {
  SetUpByteStream();
  writer->Write(static_cast<uint32_t>(cci::C13));  // Symbol stream type.
  writer->Write(static_cast<uint16_t>(4));         // Symbol length.

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  // Don't expect any calls to the visitor callback.
  EXPECT_FALSE(VisitSymbols(callback, 0, reader->length(), true, reader.get()));
}

TEST_F(PdbVisitSymbolsTest, FailsOnMissingSymbolData) {
  SetUpByteStream();
  writer->Write(static_cast<uint32_t>(cci::C13));  // Symbol stream type.
  writer->Write(static_cast<uint16_t>(4));         // Symbol length.
  writer->Write(static_cast<uint16_t>(0x1337));    // Symbol type.

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  // Don't expect any calls to the visitor callback.
  EXPECT_FALSE(VisitSymbols(callback, 0, reader->length(), true, reader.get()));
}

TEST_F(PdbVisitSymbolsTest, SucceedsOnEmptySymbolStream) {
  SetUpByteStream();
  writer->Write(static_cast<uint32_t>(cci::C13));  // Symbol stream type.
  writer->Write(static_cast<uint16_t>(0));         // Symbol length.

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  // Don't expect any calls to the visitor callback.
  EXPECT_TRUE(VisitSymbols(callback, 0, reader->length(), true, reader.get()));
}

TEST_F(PdbVisitSymbolsTest, EarlyTermination) {
  SetUpByteStream();
  writer->Write(static_cast<uint32_t>(cci::C13));  // Symbol stream type.
  writer->Write(static_cast<uint16_t>(4));         // Symbol length.
  writer->Write(static_cast<uint16_t>(0x2937));    // Made up symbol type.
  writer->Write(static_cast<uint16_t>(0));         // Dummy data.

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  EXPECT_CALL(visitor, Callback(_, _, _)).Times(1).WillOnce(Return(false));
  EXPECT_FALSE(VisitSymbols(callback, 0, reader->length(), true, reader.get()));
}

TEST_F(PdbVisitSymbolsTest, AllSymbolsVisitedNoHeader) {
  base::FilePath valid_sym_record_path = testing::GetSrcRelativePath(
      testing::kValidPdbSymbolRecordStreamPath);

  reader = testing::GetStreamFromFile(valid_sym_record_path);

  MockVisitor visitor;
  VisitSymbolsCallback callback = base::Bind(
      &MockVisitor::Callback, base::Unretained(&visitor));

  // There are 697 symbols in the sample symbol stream in test_data.
  EXPECT_CALL(visitor, Callback(_, _, _)).Times(697).
      WillRepeatedly(Return(true));
  EXPECT_TRUE(VisitSymbols(callback, 0, reader->length(), false, reader.get()));
}

}  // namespace pdb
