// Copyright 2015 Google Inc. All Rights Reserved.
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

#include "syzygy/pe/cvinfo_ext.h"

#include "gtest/gtest.h"

namespace pe {

namespace cci = Microsoft_Cci_Pdb;

// This macro checks that an unsigned bit field in a flag-converting union
// matches a mask. This is to validate that the physical layout of the union
// bitfields matches the masks that originally define these.
// @param fld the name of a field in an existing union named "inst".
// @param bit_size the bit size of @p fld.
// @param mask the mask to test the "raw" member of "inst" against.
#define TEST_BITFIELD(fld, bit_size, mask)  \
  inst.raw = 0;                             \
  ASSERT_EQ(0, inst.fld);                   \
  --inst.fld;                               \
  ASSERT_EQ((1 << bit_size) - 1, inst.fld); \
  ASSERT_EQ(0, inst.raw & ~mask)

TEST(CVInfoExtTest, LeafMemberAttributeFieldTest) {
  LeafMemberAttributeField inst = {};

  TEST_BITFIELD(access, 2, cci::access);
  TEST_BITFIELD(mprop, 3, cci::mprop);
  TEST_BITFIELD(pseudo, 1, cci::pseudo);
  TEST_BITFIELD(noinherit, 1, cci::noinherit);
  TEST_BITFIELD(noconstruct, 1, cci::noconstruct);
  TEST_BITFIELD(compgenx, 1, cci::compgenx);
}

TEST(CVInfoExtTest, LeafPropertyFieldTest) {
  LeafPropertyField inst = {};

  TEST_BITFIELD(packed, 1, cci::packed);
  TEST_BITFIELD(ctor, 1, cci::ctor);
  TEST_BITFIELD(ovlops, 1, cci::ovlops);
  TEST_BITFIELD(isnested, 1, cci::isnested);
  TEST_BITFIELD(cnested, 1, cci::cnested);
  TEST_BITFIELD(opassign, 1, cci::opassign);
  TEST_BITFIELD(opcast, 1, cci::opcast);
  TEST_BITFIELD(fwdref, 1, cci::fwdref);
  TEST_BITFIELD(scoped, 1, cci::scoped);
  TEST_BITFIELD(decorated_name_present, 1, 0x0200);
}

TEST(CVInfoExtTest, LeafPointerAttributeTest) {
  LeafPointerAttribute inst = {};

  TEST_BITFIELD(ptrtype, 5, cci::ptrtype);
  TEST_BITFIELD(ptrmode, 3, cci::ptrmode);
  TEST_BITFIELD(isflat32, 1, cci::isflat32);
  TEST_BITFIELD(isvolatile, 1, cci::isvolatile);
  TEST_BITFIELD(isconst, 1, cci::isconst);
  TEST_BITFIELD(isunaligned, 1, cci::isunaligned);
  TEST_BITFIELD(isrestrict, 1, cci::isrestrict);
}

TEST(CVInfoExtTest, LeafModifierAttributeTest) {
  LeafModifierAttribute inst = {};

  TEST_BITFIELD(mod_const, 1, cci::MOD_const);
  TEST_BITFIELD(mod_volatile, 1, cci::MOD_volatile);
  TEST_BITFIELD(mod_unaligned, 1, cci::MOD_unaligned);
}

TEST(CVInfoExtTest, CompileSymFlagsTest) {
  CompileSymFlags inst = {};

  TEST_BITFIELD(iLanguage, 8, cci::iLanguage);
  TEST_BITFIELD(fEC, 1, cci::fEC);
  TEST_BITFIELD(fNoDbgInfo, 1, cci::fNoDbgInfo);
  TEST_BITFIELD(fLTCG, 1, cci::fLTCG);
  TEST_BITFIELD(fNoDataAlign, 1, cci::fNoDataAlign);
  TEST_BITFIELD(fManagedPresent, 1, cci::fManagedPresent);
  TEST_BITFIELD(fSecurityChecks, 1, cci::fSecurityChecks);
  TEST_BITFIELD(fHotPatch, 1, cci::fHotPatch);
  TEST_BITFIELD(fCVTCIL, 1, cci::fCVTCIL);
  TEST_BITFIELD(fMSILModule, 1, cci::fMSILModule);
}

TEST(CVInfoExtTest, LocalVarFlagsTest) {
  LocalVarFlags inst = {};

  TEST_BITFIELD(fIsParam, 1, cci::fIsParam);
  TEST_BITFIELD(fAddrTaken, 1, cci::fAddrTaken);
  TEST_BITFIELD(fCompGenx, 1, cci::fCompGenx);
  TEST_BITFIELD(fIsAggregate, 1, cci::fIsAggregate);
  TEST_BITFIELD(fIsAggregated, 1, cci::fIsAggregated);
  TEST_BITFIELD(fIsAliased, 1, cci::fIsAliased);
  TEST_BITFIELD(fIsAlias, 1, cci::fIsAlias);
}

TEST(CVInfoExtTest, ExportVarFlagsTest) {
  ExportVarFlags inst = {};

  TEST_BITFIELD(fConstant, 1, cci::fConstant);
  TEST_BITFIELD(fData, 1, cci::fData);
  TEST_BITFIELD(fPrivate, 1, cci::fPrivate);
  TEST_BITFIELD(fNoName, 1, cci::fNoName);
  TEST_BITFIELD(fOrdinal, 1, cci::fOrdinal);
  TEST_BITFIELD(fForwarder, 1, cci::fForwarder);
}

TEST(CVInfoExtTest, FrameProcSymFlagsTest) {
  FrameProcSymFlags inst = {};

  TEST_BITFIELD(fHasAlloca, 1, cci::fHasAlloca);
  TEST_BITFIELD(fHasSetJmp, 1, cci::fHasSetJmp);
  TEST_BITFIELD(fHasLongJmp, 1, cci::fHasLongJmp);
  TEST_BITFIELD(fHasInlAsm, 1, cci::fHasInlAsm);
  TEST_BITFIELD(fHasEH, 1, cci::fHasEH);
  TEST_BITFIELD(fInlSpec, 1, cci::fInlSpec);
  TEST_BITFIELD(fHasSEH, 1, cci::fHasSEH);
  TEST_BITFIELD(fNaked, 1, cci::fNaked);
  TEST_BITFIELD(fSecurityChecks, 1, 0x100);  // No symbolic constant.
  TEST_BITFIELD(fAsyncEH, 1, cci::fAsyncEH);
  TEST_BITFIELD(fGSNoStackOrdering, 1, cci::fGSNoStackOrdering);
  TEST_BITFIELD(fWasInlined, 1, cci::fWasInlined);
}

}  // namespace pe
