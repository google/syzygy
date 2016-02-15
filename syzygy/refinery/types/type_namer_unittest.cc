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

#include "syzygy/refinery/types/type_namer.h"

#include <dia2.h>

#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_util.h"
#include "base/win/scoped_comptr.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pe/dia_util.h"
#include "syzygy/refinery/types/pdb_crawler.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

// Ensure type naming is identical, be it from the TypeRepository or from DIA.
class TypeNamerTest : public testing::Test {
 protected:
  void SetUp() override {
    testing::Test::SetUp();

    base::FilePath pdb_path = testing::GetSrcRelativePath(
        L"syzygy\\refinery\\test_data\\test_typenames.dll.pdb");

    // Create the type repository.
    PdbCrawler crawler;
    ASSERT_TRUE(crawler.InitializeForFile(pdb_path));
    repository_ = new TypeRepository();
    ASSERT_TRUE(crawler.GetTypes(repository_.get()));

    // Create the DIA access.
    ASSERT_TRUE(pe::CreateDiaSource(source_.Receive()));
    ASSERT_TRUE(
        pe::CreateDiaSession(pdb_path, source_.get(), session_.Receive()));
    ASSERT_EQ(S_OK, session_->get_globalScope(global_.Receive()));
  }

  // Find the first matching repository type based on name.
  // @note in the current state, it is possible for multiple types to get
  //     attributed the same name (eg function type names do not currently
  //     contain the function's name).
  TypePtr FindRepositoryTypeByName(const base::string16& name) {
    for (auto it : *repository_) {
      if (it->GetName() == name)
        return it;
    }
    return nullptr;
  }

  // Find the first matching DIA type of @p kind with @p name.
  // @note in the current state, it is possible for multiple DIA types to get
  //     attributed the same name (eg function type names do not currently
  //     contain the function's name).
  bool FindNamedDiaChild(IDiaSymbol* scope,
                         enum SymTagEnum kind,
                         const base::string16& name,
                         base::win::ScopedComPtr<IDiaSymbol>* type) {
    // Get types of desired kind.
    // Note: this assumes providing a name to findChildren only works for symbol
    // types that have names (eg base types, pointers and arrays do not).
    base::win::ScopedComPtr<IDiaEnumSymbols> matching_types;
    HRESULT hr =
        scope->findChildren(kind, nullptr, nsNone, matching_types.Receive());
    if (hr != S_OK)
      return false;

    // Iterate until we find a match on the name.
    base::win::ScopedComPtr<IDiaSymbol> symbol;
    base::string16 symbol_name;
    ULONG received = 0;
    hr = matching_types->Next(1, symbol.Receive(), &received);
    while (hr == S_OK) {
      if (DiaTypeNamer::GetTypeName(symbol.get(), &symbol_name)) {
        if (symbol_name == name) {
          *type = symbol;
          return true;
        }
      }
      // Note: not getting a name is ok as this function may process symbols for
      // which we do not support naming (eg SymTagData).

      symbol.Release();
      received = 0;
      hr = matching_types->Next(1, symbol.Receive(), &received);
    }

    return false;
  }

  // Many types seem not to make their way to the DIA session's global scope in
  // release mode. The way to retrieve then is through a UDT that wraps them
  // (UDTs seem to always make the global scope).
  bool GetUDTAttributeType(const base::string16& container_typename,
                           const base::string16& attribute_name,
                           base::win::ScopedComPtr<IDiaSymbol>* dia_type) {
    base::win::ScopedComPtr<IDiaSymbol> dia_udt_type;
    if (!FindNamedDiaChild(global_.get(), SymTagUDT, container_typename,
                           &dia_udt_type)) {
      return false;
    }

    base::win::ScopedComPtr<IDiaSymbol> dia_attribute;
    if (!FindNamedDiaChild(dia_udt_type.get(), SymTagData, attribute_name,
                           &dia_attribute)) {
      return false;
    }

    return pe::GetSymType(dia_attribute.get(), dia_type);
  }

  void PerformArrayNameTest(const base::string16& array_name);
  void PerformFunctionNameTest(const base::string16& function_name);

  // Access to types via TypeRepository.
  scoped_refptr<TypeRepository> repository_;

  // Access to types via DIA.
  base::win::ScopedComPtr<IDiaDataSource> source_;
  base::win::ScopedComPtr<IDiaSession> session_;
  base::win::ScopedComPtr<IDiaSymbol> global_;
};

}  // namespace

TEST_F(TypeNamerTest, UDTNameTest) {
  TypePtr type = FindRepositoryTypeByName(L"testing::TestUDT");
  ASSERT_TRUE(type);
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  base::win::ScopedComPtr<IDiaSymbol> dia_type;
  ASSERT_TRUE(
      FindNamedDiaChild(global_.get(), SymTagUDT, type->GetName(), &dia_type));
}

TEST_F(TypeNamerTest, EnumNameTest) {
  // TODO(manzagop): implement once PdbCrawler names enum types.
}

TEST_F(TypeNamerTest, TypedefNameTest) {
  // TODO(manzagop): implement once PdbCrawler names typedef types.
}

TEST_F(TypeNamerTest, BasicTypeNameTest) {
  // int32_t should be pulled in via TestSimpleUDT's one attribute.
  TypePtr type = FindRepositoryTypeByName(L"int32_t");
  ASSERT_TRUE(type);
  EXPECT_EQ(Type::BASIC_TYPE_KIND, type->kind());

  base::win::ScopedComPtr<IDiaSymbol> dia_type;
  ASSERT_TRUE(GetUDTAttributeType(L"testing::TestUDT", L"integer", &dia_type));

  base::string16 dia_type_name;
  ASSERT_TRUE(DiaTypeNamer::GetTypeName(dia_type.get(), &dia_type_name));
  ASSERT_EQ(L"int32_t", dia_type_name);
}

TEST_F(TypeNamerTest, PointerNameTest) {
  // Pointer
  TypePtr type = FindRepositoryTypeByName(L"testing::TestUDT const volatile*");
  ASSERT_TRUE(type);
  EXPECT_EQ(Type::POINTER_TYPE_KIND, type->kind());

  base::win::ScopedComPtr<IDiaSymbol> dia_type;
  ASSERT_TRUE(GetUDTAttributeType(L"testing::TestUDT", L"pointer", &dia_type));
  base::string16 dia_type_name;
  ASSERT_TRUE(DiaTypeNamer::GetTypeName(dia_type.get(), &dia_type_name));
  ASSERT_EQ(type->GetName(), dia_type_name);

  dia_type.Release();

  // Reference
  type = FindRepositoryTypeByName(L"int32_t const&");
  ASSERT_TRUE(type);
  EXPECT_EQ(Type::POINTER_TYPE_KIND, type->kind());

  ASSERT_TRUE(
      GetUDTAttributeType(L"testing::TestUDT", L"reference", &dia_type));
  ASSERT_TRUE(DiaTypeNamer::GetTypeName(dia_type.get(), &dia_type_name));
  ASSERT_EQ(type->GetName(), dia_type_name);
}

void TypeNamerTest::PerformArrayNameTest(const base::string16& array_typename) {
  TypePtr type = FindRepositoryTypeByName(array_typename);
  ASSERT_TRUE(type);
  ASSERT_EQ(Type::ARRAY_TYPE_KIND, type->kind());

  base::win::ScopedComPtr<IDiaSymbol> dia_type;
  ASSERT_TRUE(FindNamedDiaChild(global_.get(), SymTagArrayType, type->GetName(),
                                &dia_type));
}

TEST_F(TypeNamerTest, ArrayNameTest) {
  ASSERT_NO_FATAL_FAILURE(PerformArrayNameTest(L"char[5]"));
  ASSERT_NO_FATAL_FAILURE(PerformArrayNameTest(L"char volatile[5]"));
}

void TypeNamerTest::PerformFunctionNameTest(
    const base::string16& function_name) {
  TypePtr type = FindRepositoryTypeByName(function_name);
  ASSERT_TRUE(type);
  ASSERT_EQ(Type::FUNCTION_TYPE_KIND, type->kind());

  base::win::ScopedComPtr<IDiaSymbol> dia_type;
  ASSERT_TRUE(FindNamedDiaChild(global_.get(), SymTagFunctionType,
                                type->GetName(), &dia_type));
}

TEST_F(TypeNamerTest, FunctionNameTest) {
  ASSERT_NO_FATAL_FAILURE(
      PerformFunctionNameTest(L"void ()"));
  ASSERT_NO_FATAL_FAILURE(PerformFunctionNameTest(
      L"char const (testing::TestFunctions::)(int32_t const, char)"));
}

}  // namespace refinery
