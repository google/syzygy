// Copyright 2012 Google Inc.
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

#include "syzygy/pdb/pdb_type_info_stream.h"

#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pdb {

TEST(PdbTypeInfoStreamTest, ReadValidTypeInfoStream) {
  FilePath valid_type_info_path = testing::GetSrcRelativePath(
      testing::kValidPDBTypeInfoStreamPath);

  scoped_refptr<pdb::PdbFileStream> valid_type_info_stream =
      testing::GetStreamFromFile(valid_type_info_path);
  TypeInfoHeader header;
  TypeInfoRecordMap types_map;
  EXPECT_TRUE(ReadTypeInfoStream(valid_type_info_stream.get(),
                                 &header,
                                 &types_map));
}

TEST(PdbTypeInfoStreamTest, ReadInvalidDataTypeInfoStream) {
  FilePath invalid_type_info_path = testing::GetSrcRelativePath(
      testing::kInvalidDataPDBTypeInfoStreamPath);

  scoped_refptr<pdb::PdbFileStream> invalid_type_info_stream =
      testing::GetStreamFromFile(invalid_type_info_path);

  TypeInfoHeader header;
  TypeInfoRecordMap types_map;
  EXPECT_FALSE(ReadTypeInfoStream(invalid_type_info_stream.get(),
                                  &header,
                                  &types_map));
}

TEST(PdbTypeInfoStreamTest, ReadInvalidHeaderTypeInfoStream) {
  FilePath invalid_type_info_path = testing::GetSrcRelativePath(
      testing::kInvalidHeaderPDBTypeInfoStreamPath);

  scoped_refptr<pdb::PdbFileStream> invalid_type_info_stream =
      testing::GetStreamFromFile(invalid_type_info_path);
  TypeInfoHeader header;
  TypeInfoRecordMap types_map;
  EXPECT_FALSE(ReadTypeInfoStream(invalid_type_info_stream.get(),
                                  &header,
                                  &types_map));
}

}  // namespace pdb
