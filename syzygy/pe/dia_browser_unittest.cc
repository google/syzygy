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
#include "syzygy/pe/dia_browser.h"

#include <diacreate.h>

#include "base/bind.h"
#include "base/path_service.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_ptr.h"
#include "base/win/scoped_comptr.h"
#include "gmock/gmock.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/dia_util.h"

using base::win::ScopedComPtr;
using testing::_;
using testing::Return;

namespace pe {

using builder::Callback;
using builder::Not;
using builder::Opt;
using builder::Or;
using builder::Plus;
using builder::Seq;
using builder::Star;
using builder::Tag;
using builder::Tags;

class PatternTest: public testing::Test {
 public:
  PatternTest() {
  }

  MOCK_METHOD3(OnMatch, DiaBrowser::BrowserDirective(
      const DiaBrowser&,
      const DiaBrowser::SymTagVector&,
      const DiaBrowser::SymbolPtrVector&));

  virtual void SetUp() {
    on_match_ = base::Bind(&PatternTest::OnMatch, base::Unretained(this));
  }

 protected:
  DiaBrowser::MatchCallback on_match_;
};

const wchar_t kPdbName[] = L"syzygy\\pe\\test_data\\test_dll.pdb";

class DiaBrowserTest: public testing::Test {
 public:
  DiaBrowserTest() {
  }

  DiaBrowser::BrowserDirective OnPartialMatchTerminate(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& tag_lineage,
      const DiaBrowser::SymbolPtrVector& symbol_lineage) {
    // Call the 'OnPartialMatch' for bookkeeping reasons.
    OnPartialMatch(dia_browser, tag_lineage, symbol_lineage);
    if (!tag_lineage.empty() && tag_lineage.back() == SymTagUDT)
      return DiaBrowser::kBrowserTerminatePath;
    return DiaBrowser::kBrowserContinue;
  }

  MOCK_METHOD3(OnPartialMatch, DiaBrowser::BrowserDirective(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& tag_lineage,
      const DiaBrowser::SymbolPtrVector& symbol_lineage));

  MOCK_METHOD3(OnFullMatch, DiaBrowser::BrowserDirective(
      const DiaBrowser& dia_browser,
      const DiaBrowser::SymTagVector& tag_lineage,
      const DiaBrowser::SymbolPtrVector& symbol_lineage));

  virtual void SetUp() {
    on_partial_match_term_ =
        base::Bind(&DiaBrowserTest::OnPartialMatchTerminate,
                   base::Unretained(this));
    on_partial_match_ = base::Bind(&DiaBrowserTest::OnPartialMatch,
                                   base::Unretained(this));
    on_full_match_ = base::Bind(&DiaBrowserTest::OnFullMatch,
                                base::Unretained(this));

    if (!SUCCEEDED(dia_source_.CreateInstance(CLSID_DiaSource)))
      ASSERT_HRESULT_SUCCEEDED(NoRegCoCreate(
          pe::kDiaDllName, CLSID_DiaSource, IID_IDiaDataSource,
          reinterpret_cast<void**>(&dia_source_)));

    HRESULT hr = dia_source_->loadDataFromPdb(
        testing::GetSrcRelativePath(kPdbName).value().c_str());
    ASSERT_HRESULT_SUCCEEDED(hr);

    hr = dia_source_->openSession(dia_session_.Receive());
    ASSERT_HRESULT_SUCCEEDED(hr);

    hr = dia_session_->get_globalScope(global_.Receive());
    ASSERT_HRESULT_SUCCEEDED(hr);
  }

  virtual void TearDown() {
    global_.Release();
    dia_session_.Release();
    dia_source_.Release();
  }

 protected:
  DiaBrowser::MatchCallback on_partial_match_term_;
  DiaBrowser::MatchCallback on_partial_match_;
  DiaBrowser::MatchCallback on_full_match_;
  ScopedComPtr<IDiaDataSource> dia_source_;
  ScopedComPtr<IDiaSession> dia_session_;
  ScopedComPtr<IDiaSymbol> global_;
};

}  // namespace pe

namespace pe {

class TestDiaBrowser : public DiaBrowser {
 public:
  using DiaBrowser::TestMatch;
};

TEST_F(PatternTest, NullMatchingPatternIsInvalid) {
  TestDiaBrowser dia_browser;

  // The pattern 'Compiland?' would match everything with a null match,
  // so it should be rejected.
  EXPECT_FALSE(dia_browser.AddPattern(Opt(SymTagCompiland), on_match_));
}

TEST_F(PatternTest, Wildcard) {
  TestDiaBrowser dia_browser;

  ASSERT_TRUE(dia_browser.AddPattern(Tag(SymTagNull), on_match_));

  // The wild-card pattern should match every sym tag.
  for (size_t i = kSymTagBegin; i < kSymTagEnd; ++i) {
    SymTag sym_tag = static_cast<SymTag>(i);
    std::vector<SymTag> sym_tags(1, sym_tag);
    EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));
  }
}

TEST_F(PatternTest, Seq) {
  TestDiaBrowser dia_browser;

  // Set up pattern 'Compiland.Function.Block.Data'.
  ASSERT_TRUE(dia_browser.AddPattern(
      Seq(SymTagCompiland, SymTagFunction, SymTagBlock, SymTagData),
      on_match_));

  // This exact pattern should match, but not any prefix of it, nor any
  // longer pattern containing it as a prefix.
  std::vector<SymTag> sym_tags;
  sym_tags.push_back(SymTagCompiland);
  EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));
  sym_tags.push_back(SymTagFunction);
  EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));
  sym_tags.push_back(SymTagBlock);
  EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));
  sym_tags.push_back(SymTagData);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));
  sym_tags.push_back(SymTagData);
  EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));
}

TEST_F(PatternTest, EmptySymTagBitSetRejected) {
  TestDiaBrowser dia_browser;

  // A pattern with an element that can't match anything should be rejected.
  EXPECT_FALSE(dia_browser.AddPattern(Not(SymTagNull), on_match_));
  EXPECT_FALSE(dia_browser.AddPattern(Tags(SymTagBitSet()), on_match_));
}

TEST_F(PatternTest, Not) {
  TestDiaBrowser dia_browser;

  // Set up pattern '[^Compiland]'
  ASSERT_TRUE(dia_browser.AddPattern(Not(SymTagCompiland), on_match_));

  // This should match every SymTag *except* Compiland.
  for (size_t i = kSymTagBegin; i < kSymTagEnd; ++i) {
    SymTag sym_tag = static_cast<SymTag>(i);
    std::vector<SymTag> sym_tags(1, sym_tag);
    if (i == SymTagCompiland)
      EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));
    else
      EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));
  }
}

TEST_F(PatternTest, MultiArgNot) {
  TestDiaBrowser dia_browser;

  // The multi-arg versions accept up to 8 inputs currently. Test
  // with a full set of inputs. The sym tags used here are consecutive
  // from kSymTagBegin.
  ASSERT_TRUE(dia_browser.AddPattern(Not(SymTagExe,
                                         SymTagCompiland,
                                         SymTagCompilandDetails,
                                         SymTagCompilandEnv,
                                         SymTagFunction,
                                         SymTagBlock,
                                         SymTagData,
                                         SymTagAnnotation),
                                     on_match_));

  // Ensure the pattern doesn't match the first 8 symtags, but matches all
  // the rest.
  for (size_t i = kSymTagBegin; i < kSymTagEnd; ++i) {
    SymTag sym_tag = static_cast<SymTag>(i);
    std::vector<SymTag> sym_tags(1, sym_tag);
    if (i <= SymTagAnnotation)
      EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));
    else
      EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));
  }
}

TEST_F(PatternTest, MultiArgTags) {
  TestDiaBrowser dia_browser;

  // The multi-arg versions accept up to 8 inputs currently. Test
  // with a full set of inputs. The sym tags used here are consecutive
  // from kSymTagBegin.
  ASSERT_TRUE(dia_browser.AddPattern(Tags(SymTagExe,
                                          SymTagCompiland,
                                          SymTagCompilandDetails,
                                          SymTagCompilandEnv,
                                          SymTagFunction,
                                          SymTagBlock,
                                          SymTagData,
                                          SymTagAnnotation),
                                     on_match_));

  // Ensure the pattern matches the first 8 symtags, but does not match all
  // the rest.
  for (size_t i = kSymTagBegin; i < kSymTagEnd; ++i) {
    SymTag sym_tag = static_cast<SymTag>(i);
    std::vector<SymTag> sym_tags(1, sym_tag);
    if (i <= SymTagAnnotation)
      EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));
    else
      EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));
  }
}

TEST_F(PatternTest, Opt) {
  TestDiaBrowser dia_browser;

  // Set up pattern 'Compiland?.Function'.
  ASSERT_TRUE(dia_browser.AddPattern(
      Seq(Opt(SymTagCompiland), SymTagFunction), on_match_));

  std::vector<SymTag> sym_tags;

  // 'Compiland' should not match.
  sym_tags.push_back(SymTagCompiland);
  EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));

  // 'Compiland.Function' should match.
  sym_tags.push_back(SymTagFunction);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));

  // 'Function' should match.
  sym_tags.clear();
  sym_tags.push_back(SymTagFunction);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));
}

TEST_F(PatternTest, Star) {
  TestDiaBrowser dia_browser;

  // Set up pattern 'Compiland.Block*.Data'.
  ASSERT_TRUE(dia_browser.AddPattern(
      Seq(SymTagCompiland, Star(SymTagBlock), SymTagData), on_match_));

  std::vector<SymTag> sym_tags;

  // 'Compiland' should not match.
  sym_tags.push_back(SymTagCompiland);
  EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));

  // 'Compiland.Data' should match.
  sym_tags.push_back(SymTagData);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));

  // 'Compiland.Block.Data' should match, with Block repeated
  // arbitrarily many times. We can only check a finite number, obviously.
  for (size_t i = 0; i < 10; ++i) {
    sym_tags.pop_back();
    sym_tags.push_back(SymTagBlock);
    sym_tags.push_back(SymTagData);
    EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));
  }
}

TEST_F(PatternTest, Plus) {
  TestDiaBrowser dia_browser;

  // Set up pattern 'Compiland.Block+.Data'.
  ASSERT_TRUE(dia_browser.AddPattern(
      Seq(SymTagCompiland, Plus(SymTagBlock), SymTagData), on_match_));

  std::vector<SymTag> sym_tags;

  // 'Compiland' should not match'.
  sym_tags.push_back(SymTagCompiland);
  EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));

  // 'Compiland.Data' should not match.
  sym_tags.push_back(SymTagData);
  EXPECT_EQ(0, dia_browser.TestMatch(sym_tags));

  // 'Compiland.Block.Data' should match, with Block repeated
  // arbitrarily many times. We can only check a finite number, obviously.
  for (size_t i = 0; i < 10; ++i) {
    sym_tags.pop_back();
    sym_tags.push_back(SymTagBlock);
    sym_tags.push_back(SymTagData);
    EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));
  }
}

TEST_F(PatternTest, Or) {
  TestDiaBrowser dia_browser;

  // Add an 'or' pattern that uses all 8 arguments.
  ASSERT_TRUE(dia_browser.AddPattern(
      Or(SymTagCompiland,
         Seq(SymTagData, SymTagCompiland, SymTagExe),
         Seq(SymTagExe, SymTagCompiland),
         Seq(SymTagExe, SymTagData),
         Seq(SymTagExe, SymTagExe),
         Seq(SymTagLabel, SymTagCompiland),
         Seq(SymTagLabel, SymTagLabel, SymTagLabel),
         SymTagVTable),
      on_match_));

  std::vector<SymTag> sym_tags;
  sym_tags.push_back(SymTagCompiland);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));

  sym_tags.clear();
  sym_tags.push_back(SymTagData);
  sym_tags.push_back(SymTagCompiland);
  sym_tags.push_back(SymTagExe);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));

  sym_tags.clear();
  sym_tags.push_back(SymTagExe);
  sym_tags.push_back(SymTagCompiland);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));

  sym_tags.back() = SymTagData;
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));

  sym_tags.back() = SymTagExe;
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));

  sym_tags.clear();
  sym_tags.push_back(SymTagLabel);
  sym_tags.push_back(SymTagCompiland);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));

  sym_tags.back() = SymTagLabel;
  sym_tags.push_back(SymTagLabel);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));

  sym_tags.clear();
  sym_tags.push_back(SymTagVTable);
  EXPECT_EQ(1, dia_browser.TestMatch(sym_tags));
}

TEST_F(DiaBrowserTest, AllCompilandSymbolsExplored) {
  TestDiaBrowser dia_browser;

  dia_browser.AddPattern(Tag(SymTagCompiland), on_full_match_);

  EXPECT_CALL(*this, OnFullMatch(_, _, _)).Times(154).
      WillRepeatedly(Return(DiaBrowser::kBrowserContinue));
  dia_browser.Browse(global_.get());
}

TEST_F(DiaBrowserTest, AllDataSymbolsExplored) {
  TestDiaBrowser dia_browser;

  // Search for (Wildcard)*.Data
  dia_browser.AddPattern(Seq(Star(SymTagNull), SymTagData),
                         on_full_match_);

  EXPECT_CALL(*this, OnFullMatch(_, _, _)).Times(2896).
      WillRepeatedly(Return(DiaBrowser::kBrowserContinue));
  dia_browser.Browse(global_.get());
}

TEST_F(DiaBrowserTest, AllDataSymbolsExploredWithPopCallbacks) {
  TestDiaBrowser dia_browser;

  // Search for (Wildcard)*.Data
  dia_browser.AddPattern(Seq(Star(SymTagNull), SymTagData),
                         on_full_match_, on_full_match_);

  EXPECT_CALL(*this, OnFullMatch(_, _, _)).Times(2 * 2896).
      WillRepeatedly(Return(DiaBrowser::kBrowserContinue));
  dia_browser.Browse(global_.get());
}

TEST_F(DiaBrowserTest, SomePathsTerminated) {
  TestDiaBrowser dia_browser;

  // Search for UDT.Data and Enum.Data. This will find:
  //    428 Enum.Data
  //   1077 UDT.Data
  // However, we terminate partial matches when they get to
  // UDT.
  dia_browser.AddPattern(Seq(Callback(Or(SymTagEnum, SymTagUDT),
                                      on_partial_match_term_),
                             SymTagData),
                         on_full_match_);

  // With VC++ 2010, OnPartialMatch hits 174 nodes.
  static const size_t kNumPartialMatches = 174;

  // Only the 428 Enum.Data full matches should be hit.
  static const size_t kNumFullMatches = 428;

  EXPECT_CALL(*this, OnPartialMatch(_, _, _)).Times(kNumPartialMatches).
      WillRepeatedly(Return(DiaBrowser::kBrowserContinue));
  EXPECT_CALL(*this, OnFullMatch(_, _, _)).Times(kNumFullMatches).
      WillRepeatedly(Return(DiaBrowser::kBrowserContinue));
  dia_browser.Browse(global_.get());
}

}  // namespace pe
