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

#include "syzygy/pdb/pdb_dbi_stream.h"

#include "base/files/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/unittest_util.h"

namespace pdb {

TEST(PdbDbiStreamTest, ReadValidDbiStream) {
  base::FilePath valid_dbi_path = testing::GetSrcRelativePath(
      testing::kValidPdbDbiStreamPath);

  scoped_refptr<pdb::PdbFileStream> valid_dbi_stream =
      testing::GetStreamFromFile(valid_dbi_path);
  DbiStream dbi_stream;
  EXPECT_TRUE(dbi_stream.Read(valid_dbi_stream.get()));
}

TEST(PdbDbiStreamTest, ReadInvalidDbiStream) {
  base::FilePath invalid_dbi_path = testing::GetSrcRelativePath(
      testing::kInvalidPdbDbiStreamPath);

  scoped_refptr<pdb::PdbFileStream> invalid_dbi_stream =
      testing::GetStreamFromFile(invalid_dbi_path);

  DbiStream dbi_stream;
  EXPECT_FALSE(dbi_stream.Read(invalid_dbi_stream.get()));
}

}  // namespace pdb
