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

#include "syzygy/pdb/unittest_util.h"

#include "gtest/gtest.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/pdb_constants.h"
#include "syzygy/pdb/pdb_util.h"

namespace testing {

const wchar_t kTestPdbFilePath[] =
    L"syzygy\\pdb\\test_data\\test_dll.pdb";

const wchar_t kTestDllFilePath[] =
    L"syzygy\\pdb\\test_data\\test_dll.dll";

const wchar_t kOmappedTestPdbFilePath[] =
    L"syzygy\\pdb\\test_data\\omapped_test_dll.pdb";

const wchar_t kPdbStrPath[] =
    L"third_party\\debugging_tools\\files\\srcsrv\\pdbstr.exe";

const wchar_t kValidPdbDbiStreamPath[] =
    L"syzygy\\pdb\\test_data\\valid_dbi.pdb_stream";

const wchar_t kInvalidPdbDbiStreamPath[] =
    L"syzygy\\pdb\\test_data\\invalid_dbi.pdb_stream";

const wchar_t kValidPdbSymbolRecordStreamPath[] =
    L"syzygy\\pdb\\test_data\\valid_sym_record.pdb_stream";

const wchar_t kInvalidPdbSymbolRecordStreamPath[] =
    L"syzygy\\pdb\\test_data\\invalid_sym_record.pdb_stream";

const wchar_t kValidPdbTypeInfoStreamPath[] =
    L"syzygy\\pdb\\test_data\\valid_type_info.pdb_stream";

const wchar_t kInvalidHeaderPdbTypeInfoStreamPath[] =
    L"syzygy\\pdb\\test_data\\invalid_type_info_header_corrupted.pdb_stream";

const wchar_t kInvalidDataPdbTypeInfoStreamPath[] =
    L"syzygy\\pdb\\test_data\\invalid_type_info_data_corrupted.pdb_stream";

scoped_refptr<pdb::PdbFileStream> GetStreamFromFile(base::FilePath file_path) {
  int64 file_size = 0;
  base::GetFileSize(file_path, &file_size);
  size_t pages[] = {0};

  scoped_refptr<pdb::RefCountedFILE> file = new pdb::RefCountedFILE(
      base::OpenFile(file_path, "rb"));
  scoped_refptr<pdb::PdbFileStream> stream(
    new pdb::PdbFileStream(file, file_size, pages, file_size));

  return stream;
}

void InitMockPdbFile(pdb::PdbFile* pdb_file) {
  scoped_refptr<pdb::PdbByteStream> stream(new pdb::PdbByteStream());
  scoped_refptr<pdb::WritablePdbStream> writer(
      stream->GetWritablePdbStream());

  pdb::PdbInfoHeader70 header = {
      pdb::kPdbCurrentVersion, 123456789, 1,
      { 0xDEADBEEF, 0xCAFE, 0xBABE, { 0, 1, 2, 3, 4, 5, 6, 7 } } };
  pdb::NameStreamMap name_stream_map;
  ASSERT_TRUE(pdb::WriteHeaderInfoStream(header, name_stream_map, writer));

  pdb_file->SetStream(pdb::kPdbHeaderInfoStream, stream);
}

}  // namespace testing
