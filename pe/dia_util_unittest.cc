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

#include "syzygy/pe/dia_util.h"

#include <vector>

#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

using base::win::ScopedBstr;
using base::win::ScopedComPtr;

static const wchar_t kNonsenseStreamName[] =
    L"ThisStreamNameCertainlyDoesNotExist";

class DiaUtilTest : public testing::PELibUnitTest {
};

TEST_F(DiaUtilTest, CreateDiaSource) {
  ScopedComPtr<IDiaDataSource> dia_source;
  EXPECT_TRUE(CreateDiaSource(dia_source.Receive()));
}

TEST_F(DiaUtilTest, CreateDiaSesssionDll) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  EXPECT_TRUE(CreateDiaSession(testing::GetExeRelativePath(kDllName),
                               dia_source.get(),
                               dia_session.Receive()));
}

TEST_F(DiaUtilTest, CreateDiaSesssionPdb) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  EXPECT_TRUE(CreateDiaSession(testing::GetExeRelativePath(kDllPdbName),
                               dia_source.get(),
                               dia_session.Receive()));
}

TEST_F(DiaUtilTest, FindDiaTableByIid) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  ASSERT_TRUE(CreateDiaSession(testing::GetExeRelativePath(kDllPdbName),
                               dia_source.get(),
                               dia_session.Receive()));

  ScopedComPtr<IDiaEnumSectionContribs> section_contribs;
  EXPECT_EQ(kSearchSucceeded,
            FindDiaTable(section_contribs.iid(),
                         dia_session.get(),
                         reinterpret_cast<void**>(section_contribs.Receive())));
}

TEST_F(DiaUtilTest, FindDiaTableByType) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  ASSERT_TRUE(CreateDiaSession(testing::GetExeRelativePath(kDllPdbName),
                               dia_source.get(),
                               dia_session.Receive()));

  ScopedComPtr<IDiaEnumSectionContribs> section_contribs;
  EXPECT_EQ(kSearchSucceeded,
            FindDiaTable(dia_session.get(), section_contribs.Receive()));
}

TEST_F(DiaUtilTest, FindDiaDebugStream) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  ASSERT_TRUE(CreateDiaSession(testing::GetExeRelativePath(kDllPdbName),
                               dia_source.get(),
                               dia_session.Receive()));

  ScopedComPtr<IDiaEnumDebugStreamData> debug_stream;

  EXPECT_EQ(kSearchFailed,
            FindDiaDebugStream(kNonsenseStreamName,
                               dia_session.get(),
                               debug_stream.Receive()));

  EXPECT_EQ(kSearchSucceeded,
            FindDiaDebugStream(kFixupDiaDebugStreamName,
                               dia_session.get(),
                               debug_stream.Receive()));
}

TEST_F(DiaUtilTest, LoadDiaDebugStream) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  ASSERT_TRUE(CreateDiaSession(testing::GetExeRelativePath(kDllPdbName),
                               dia_source.get(),
                               dia_session.Receive()));

  ScopedComPtr<IDiaEnumDebugStreamData> debug_stream;
  ASSERT_EQ(kSearchSucceeded,
            FindDiaDebugStream(kFixupDiaDebugStreamName,
                               dia_session.get(),
                               debug_stream.Receive()));

  std::vector<pdb::PdbFixup> fixups;
  EXPECT_TRUE(LoadDiaDebugStream(debug_stream.get(), &fixups));
  EXPECT_FALSE(fixups.empty());
}

TEST_F(DiaUtilTest, FindAndLoadDiaDebugStreamByName) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  ASSERT_TRUE(CreateDiaSession(testing::GetExeRelativePath(kDllPdbName),
                               dia_source.get(),
                               dia_session.Receive()));

  std::vector<pdb::PdbFixup> fixups;

  EXPECT_EQ(kSearchFailed,
            FindAndLoadDiaDebugStreamByName(kNonsenseStreamName,
                                            dia_session.get(),
                                            &fixups));
  EXPECT_TRUE(fixups.empty());

  EXPECT_EQ(kSearchSucceeded,
            FindAndLoadDiaDebugStreamByName(kFixupDiaDebugStreamName,
                                            dia_session.get(),
                                            &fixups));
  EXPECT_FALSE(fixups.empty());
}

}  // namespace pe
