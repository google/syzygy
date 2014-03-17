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

#include "syzygy/pe/dia_util.h"

#include <map>
#include <set>
#include <vector>

#include "base/bind.h"
#include "base/file_util.h"
#include "base/files/file_path.h"
#include "base/win/scoped_bstr.h"
#include "base/win/scoped_comptr.h"
#include "gmock/gmock.h"
#include "syzygy/core/file_util.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_data.h"
#include "syzygy/pe/unittest_util.h"

namespace pe {

namespace {

using base::win::ScopedBstr;
using base::win::ScopedComPtr;

static const wchar_t kNonsenseStreamName[] =
    L"ThisStreamNameCertainlyDoesNotExist";

// The test_dll output file name configured by the build system.
static const char kTestDllObjPath[] = TEST_DLL_OBJECT_FILE;

struct FilePathLess {
  bool operator()(const std::wstring& lhs, const std::wstring& rhs) {
    return base::FilePath::CompareLessIgnoreCase(lhs, rhs);
  }
};

class DiaUtilTest : public testing::PELibUnitTest {
};

MATCHER_P(IsSameFile, value, "") {
  base::FilePath path1(arg);
  base::FilePath path2(value);
  core::FilePathCompareResult result = core::CompareFilePaths(path1, path2);
  return result == core::kEquivalentFilePaths;
}

}  // namespace

TEST_F(DiaUtilTest, CreateDiaSource) {
  ScopedComPtr<IDiaDataSource> dia_source;
  EXPECT_TRUE(CreateDiaSource(dia_source.Receive()));
}

TEST_F(DiaUtilTest, CreateDiaSesssionDll) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  EXPECT_TRUE(CreateDiaSession(
      testing::GetExeRelativePath(testing::kTestDllName),
      dia_source.get(),
      dia_session.Receive()));
}

TEST_F(DiaUtilTest, CreateDiaSesssionPdb) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  EXPECT_TRUE(CreateDiaSession(
      testing::GetExeRelativePath(testing::kTestDllPdbName),
      dia_source.get(),
      dia_session.Receive()));
}

TEST_F(DiaUtilTest, FindDiaTableByIid) {
  ScopedComPtr<IDiaDataSource> dia_source;
  ASSERT_TRUE(CreateDiaSource(dia_source.Receive()));

  ScopedComPtr<IDiaSession> dia_session;
  ASSERT_TRUE(CreateDiaSession(
      testing::GetExeRelativePath(testing::kTestDllPdbName),
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
  ASSERT_TRUE(CreateDiaSession(
      testing::GetExeRelativePath(testing::kTestDllPdbName),
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
  ASSERT_TRUE(CreateDiaSession(
      testing::GetExeRelativePath(testing::kTestDllPdbName),
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
  ASSERT_TRUE(CreateDiaSession(
      testing::GetExeRelativePath(testing::kTestDllPdbName),
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
  ASSERT_TRUE(CreateDiaSession(
      testing::GetExeRelativePath(testing::kTestDllPdbName),
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

class DiaUtilVisitorTest : public DiaUtilTest {
 public:
  virtual void SetUp() OVERRIDE {
    ASSERT_TRUE(CreateDiaSource(dia_source_.Receive()));
    ASSERT_TRUE(CreateDiaSession(
        testing::GetExeRelativePath(testing::kTestDllName),
        dia_source_.get(),
        dia_session_.Receive()));
    ASSERT_EQ(S_OK, dia_session_->get_globalScope(dia_globals_.Receive()));
  }

  typedef std::vector<std::wstring> StringVector;
  bool OnFunction(StringVector* names, IDiaSymbol* function) {
    EXPECT_TRUE(IsSymTag(function, SymTagFunction));
    ScopedBstr name;
    EXPECT_EQ(S_OK, function->get_name(name.Receive()));
    names->push_back(common::ToString(name));
    return true;
  }

  bool OnCompiland(StringVector* names, IDiaSymbol* compiland) {
    EXPECT_TRUE(IsSymTag(compiland, SymTagCompiland));
    ScopedBstr name;
    EXPECT_EQ(S_OK, compiland->get_name(name.Receive()));
    names->push_back(common::ToString(name));
    return true;
  }

  bool OnCompilandFind(const std::wstring& compiland_path,
                       ScopedComPtr<IDiaSymbol>* compiland_out,
                       IDiaSymbol* compiland) {
    EXPECT_TRUE(IsSymTag(compiland, SymTagCompiland));
    ScopedBstr name;
    EXPECT_EQ(S_OK, compiland->get_name(name.Receive()));
    if (testing::Value(common::ToString(name), IsSameFile(compiland_path))) {
      *compiland_out = compiland;
      return false;
    }
    return true;
  }

  typedef std::set<std::pair<DWORD, DWORD>> LineSet;
  typedef std::map<std::wstring, LineSet, FilePathLess> LineMap;
  bool OnLine(LineMap* line_map, IDiaLineNumber* line) {
    DCHECK_NE(reinterpret_cast<LineMap*>(NULL), line_map);
    DCHECK_NE(reinterpret_cast<IDiaLineNumber*>(NULL), line);

    ScopedComPtr<IDiaSourceFile> source_file;
    EXPECT_HRESULT_SUCCEEDED(line->get_sourceFile(source_file.Receive()));

    ScopedBstr source_name;
    EXPECT_HRESULT_SUCCEEDED(source_file->get_fileName(source_name.Receive()));

    ScopedComPtr<IDiaSymbol> compiland;
    EXPECT_HRESULT_SUCCEEDED(line->get_compiland(compiland.Receive()));

    DWORD line_number = 0;
    EXPECT_HRESULT_SUCCEEDED(line->get_lineNumber(&line_number));
    DWORD line_number_end = 0;
    EXPECT_HRESULT_SUCCEEDED(line->get_lineNumberEnd(&line_number_end));

    // This doesn't necessarily have to hold, but so far it seems to do so.
    EXPECT_EQ(line_number, line_number_end);

    (*line_map)[common::ToString(source_name)].insert(
        std::make_pair(line_number, line_number_end));

    return true;
  }

  ScopedComPtr<IDiaDataSource> dia_source_;
  ScopedComPtr<IDiaSession> dia_session_;
  ScopedComPtr<IDiaSymbol> dia_globals_;
};

TEST_F(DiaUtilVisitorTest, ChildVisitorTest) {
  ChildVisitor visitor(dia_globals_, SymTagFunction);

  StringVector function_names;
  ASSERT_TRUE(visitor.VisitChildren(
      base::Bind(&DiaUtilVisitorTest::OnFunction,
                 base::Unretained(this),
                 &function_names)));

  // Expect that we found a bunch of functions.
  ASSERT_LT(1U, function_names.size());
  // One of them should be "DllMain".
  ASSERT_THAT(function_names, testing::Contains(L"DllMain"));
}

TEST_F(DiaUtilVisitorTest, CompilandVisitorTest) {
  CompilandVisitor visitor(dia_session_);

  StringVector compiland_names;
  ASSERT_TRUE(visitor.VisitAllCompilands(
      base::Bind(&DiaUtilVisitorTest::OnCompiland,
                 base::Unretained(this),
                 &compiland_names)));

  // We expect to have seen some compiland_names.
  ASSERT_LT(0U, compiland_names.size());

  // One of the compiland_names should be the test_dll.obj file.
  std::string test_dll_path(kTestDllObjPath);
  std::wstring test_dll_wide_path(test_dll_path.begin(), test_dll_path.end());
  base::FilePath test_dll_obj =
      base::MakeAbsoluteFilePath(
          testing::GetOutputRelativePath(test_dll_wide_path.c_str()));
  ASSERT_THAT(compiland_names,
              testing::Contains(IsSameFile(test_dll_obj.value())));
}

TEST_F(DiaUtilVisitorTest, LineVisitorTest) {
  CompilandVisitor compiland_visitor(dia_session_);

  // Start by finding the test dll compiland.
  ScopedComPtr<IDiaSymbol> compiland;
  std::string test_dll_path(kTestDllObjPath);
  std::wstring test_dll_wide_path(test_dll_path.begin(), test_dll_path.end());
  base::FilePath test_dll_obj =
      base::MakeAbsoluteFilePath(
          testing::GetOutputRelativePath(test_dll_wide_path.c_str()));
  ASSERT_FALSE(compiland_visitor.VisitAllCompilands(
      base::Bind(&DiaUtilVisitorTest::OnCompilandFind,
                 base::Unretained(this),
                 test_dll_obj.value(),
                 &compiland)));

  ASSERT_TRUE(compiland != NULL);

  // Now enumerate all line entries in that compiland.
  LineVisitor line_visitor(dia_session_, compiland);

  LineMap line_map;
  ASSERT_TRUE(line_visitor.VisitLines(
      base::Bind(&DiaUtilVisitorTest::OnLine,
                 base::Unretained(this),
                 &line_map)));

  // We expect to have at least one file.
  ASSERT_LE(1U, line_map.size());

  base::FilePath test_dll_cc =
      testing::GetSrcRelativePath(L"syzygy\\pe\\test_dll.cc");
  ASSERT_TRUE(line_map.find(test_dll_cc.value()) != line_map.end());

  ASSERT_LT(1U, line_map[test_dll_cc.value()].size());
}

}  // namespace pe
