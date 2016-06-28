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

#include "syzygy/refinery/types/pdb_crawler.h"

#include <unordered_map>
#include <vector>

#include "base/path_service.h"
#include "base/debug/alias.h"
#include "base/files/file_path.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string16.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_dbi_stream.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_stream_reader.h"
#include "syzygy/pdb/pdb_stream_record.h"
#include "syzygy/pdb/pdb_symbol_record.h"
#include "syzygy/pdb/pdb_util.h"
#include "syzygy/pe/cvinfo_ext.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"
#include "syzygy/refinery/types/unittest_util.h"

namespace refinery {

namespace {

std::vector<TypePtr> GetTypesBySuffix(TypeRepository* types,
                                      const base::string16& suffix) {
  DCHECK(types);
  std::vector<TypePtr> found_types;

  for (auto it : *types) {
    if (base::EndsWith(it->GetName(), suffix, base::CompareCase::SENSITIVE)) {
      found_types.push_back(it);
    }
  }

  return found_types;
}

TypePtr GetOneTypeBySuffix(TypeRepository* types,
                           const base::string16& suffix) {
  DCHECK(types);
  std::vector<TypePtr> results = GetTypesBySuffix(types, suffix);
  EXPECT_EQ(1U, results.size());
  return results[0];
}

// We use parameterized tests to test against both the 32-bit and 64-bit images.
class PdbCrawlerTest : public ::testing::TestWithParam<uint32_t> {
 protected:
  void SetUp() override {
    // Load the correct image and set the constants.
    if (GetParam() == 32) {
      test_types_file_ = testing::GetSrcRelativePath(
          L"syzygy\\refinery\\test_data\\test_types.dll.pdb");
    } else {
      test_types_file_ = testing::GetSrcRelativePath(
          L"syzygy\\refinery\\test_data\\test_types_x64.dll.pdb");
    }

    LoadTypes();
    LoadUnsignedConstantsFromSymbolStream();
  }

  void LoadTypes() {
    ASSERT_TRUE(crawler_.InitializeForFile(test_types_file_));

    types_ = new TypeRepository();
    ASSERT_TRUE(crawler_.GetTypes(types_.get()));
    ASSERT_LE(1U, types_->size());
  }

  // For a given type name, this function returns size of the type as encoded in
  // the symbol stream. On failure the maximum possible value of size_t gets
  // returned which would cause failure of the test using this function.
  size_t LookupSizeOf(const base::string16& name) {
    const auto it = constants_.find(name + L"Size");
    if (it != constants_.end()) {
      return it->second;
    } else {
      return static_cast<size_t>(-1);
    }
  }

  // For a given type and field name, this function returns offset of the field
  // as encoded in the symbol stream. On failure the maximum possible value of
  // size_t gets returned which would cause failure of the test using this
  // function.
  size_t LookupOffsetOf(const base::string16& type,
                        const base::string16& field) {
    const auto it = constants_.find(field + L"In" + type + L"Offset");
    if (it != constants_.end()) {
      return it->second;
    } else {
      return static_cast<size_t>(-1);
    }
  }

  // This function reads all unsigned constants from the symbol stream. We use
  // this to find the const static variables containing sizes of member
  // pointers.
  void LoadUnsignedConstantsFromSymbolStream() {
    pdb::PdbReader reader;
    pdb::PdbFile pdb_file;
    pdb::DbiStream dbi_stream;

    ASSERT_TRUE(reader.Read(test_types_file_, &pdb_file));
    dbi_stream.Read(pdb_file.GetStream(pdb::kDbiStream).get());

    ASSERT_NE(-1, dbi_stream.header().symbol_record_stream);
    scoped_refptr<pdb::PdbStream> sym_record_stream =
        pdb_file.GetStream(dbi_stream.header().symbol_record_stream).get();

    ASSERT_NE(nullptr, sym_record_stream);
    pdb::SymbolRecordVector symbol_vector;
    ASSERT_TRUE(pdb::ReadSymbolRecord(sym_record_stream.get(), 0,
                                      sym_record_stream->length(),
                                      &symbol_vector));

    const base::string16 kPrefix = L"kPdbCrawler";

    pdb::SymbolRecordVector::const_iterator symbol_iter = symbol_vector.begin();
    for (; symbol_iter != symbol_vector.end(); ++symbol_iter) {
      // We are interested only in constants.
      if (symbol_iter->type != Microsoft_Cci_Pdb::S_CONSTANT)
        continue;

      pdb::PdbStreamReaderWithPosition reader(symbol_iter->start_position,
                                              symbol_iter->len,
                                              sym_record_stream.get());
      common::BinaryStreamParser parser(&reader);

      // Read the type index it points to.
      uint32_t type_index = 0;
      ASSERT_TRUE(parser.Read(&type_index));

      // Read the value, we are not interested in signed values.
      uint64_t value;
      if (!pdb::ReadUnsignedNumeric(&parser, &value))
        continue;

      // And its name.
      base::string16 name;
      ASSERT_TRUE(pdb::ReadWideString(&parser, &name));

      // We want to save only our own constants.
      if (!base::StartsWith(name, kPrefix, base::CompareCase::SENSITIVE))
        continue;

      // Strip the prefix from the constant name and save.
      name = name.substr(kPrefix.length(), base::string16::npos);
      constants_.insert(std::make_pair(name, value));
    }
  }

  std::vector<TypePtr> FindTypesBySuffix(const base::string16& suffix) {
    return GetTypesBySuffix(types_.get(), suffix);
  }

  TypePtr FindOneTypeBySuffix(const base::string16& suffix) {
    return GetOneTypeBySuffix(types_.get(), suffix);
  }

  PdbCrawler crawler_;
  base::FilePath test_types_file_;
  std::unordered_map<base::string16, size_t> constants_;
  scoped_refptr<TypeRepository> types_;
};

void ValidateMemberField(FieldPtr field,
                         size_t offset,
                         size_t bit_pos,
                         size_t bit_len,
                         bool is_const,
                         bool is_volatile,
                         const base::string16& name) {
  EXPECT_EQ(offset, field->offset());
  // Note: type_id is not validated.
  MemberFieldPtr member;
  ASSERT_TRUE(field->CastTo(&member));  // implicitely validates kind.

  EXPECT_EQ(name, member->name());
  EXPECT_EQ(is_const, member->is_const());
  EXPECT_EQ(is_volatile, member->is_volatile());
  EXPECT_EQ(bit_pos, member->bit_pos());
  EXPECT_EQ(bit_len, member->bit_len());
}

void ValidateBasicType(TypePtr type, size_t size, const base::string16& name) {
  EXPECT_EQ(Type::BASIC_TYPE_KIND, type->kind());
  EXPECT_EQ(size, type->size());
  EXPECT_EQ(name, type->GetName());
}

void ValidateWildcardType(TypePtr type,
                          size_t size,
                          const base::string16& name) {
  EXPECT_EQ(Type::WILDCARD_TYPE_KIND, type->kind());
  EXPECT_EQ(size, type->size());
  EXPECT_EQ(name, type->GetName());
}

void ValidatePointerType(TypePtr type,
                         PointerType::Mode ptrmode,
                         bool is_const,
                         bool is_volatile,
                         size_t size,
                         const base::string16& name) {
  EXPECT_EQ(Type::POINTER_TYPE_KIND, type->kind());
  PointerTypePtr ptr;
  ASSERT_TRUE(type->CastTo(&ptr));
  EXPECT_EQ(is_const, ptr->is_const());
  EXPECT_EQ(is_volatile, ptr->is_volatile());
  EXPECT_EQ(ptrmode, ptr->ptr_mode());
  EXPECT_EQ(size, type->size());
  EXPECT_EQ(name, type->GetName());
}

void ValidateArrayType(TypePtr type,
                       bool is_const,
                       bool is_volatile,
                       size_t size,
                       size_t num_elements,
                       const base::string16& name) {
  EXPECT_EQ(Type::ARRAY_TYPE_KIND, type->kind());
  ArrayTypePtr array_type;
  ASSERT_TRUE(type->CastTo(&array_type));
  EXPECT_EQ(is_const, array_type->is_const());
  EXPECT_EQ(is_volatile, array_type->is_volatile());
  EXPECT_EQ(size, type->size());
  EXPECT_EQ(num_elements, array_type->num_elements());
  EXPECT_EQ(name, type->GetName());
}

// Constants for better readability.
const size_t kBitPosZero = 0;
const size_t kBitLenZero = 0;
const bool kIsConst = true;
const bool kIsVolatile = true;

}  // namespace

TEST_P(PdbCrawlerTest, TestSimpleUDT) {
  TypePtr type = FindOneTypeBySuffix(L"::TestSimpleUDT");
  ASSERT_TRUE(type);

  EXPECT_EQ(LookupSizeOf(L"TestSimpleUDT"), type->size());
  EXPECT_TRUE(EndsWith(type->GetName(), L"::TestSimpleUDT",
                       base::CompareCase::SENSITIVE));
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  EXPECT_FALSE(udt->is_fwd_decl());
  EXPECT_EQ(UserDefinedType::UDT_STRUCT, udt->udt_kind());

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(6U, fields.size());

  size_t offset = 0;

  // Test field: int one.
  ValidateMemberField(fields[0], offset, kBitPosZero, kBitLenZero, !kIsConst,
                      !kIsVolatile, L"one");
  ValidateBasicType(udt->GetFieldType(0), sizeof(int32_t), L"int32_t");
  offset += sizeof(int32_t);

  // Test field: const char two.
  ValidateMemberField(fields[1], offset, kBitPosZero, kBitLenZero, kIsConst,
                      !kIsVolatile, L"two");
  ValidateBasicType(udt->GetFieldType(1), sizeof(char), L"char");
  offset += sizeof(int32_t);

  // Test field: short const* volatile* three.
  ValidateMemberField(fields[2], offset, kBitPosZero, kBitLenZero, !kIsConst,
                      !kIsVolatile, L"three");
  ValidatePointerType(udt->GetFieldType(2), PointerType::PTR_MODE_PTR,
                      !kIsConst, kIsVolatile, LookupSizeOf(L"Pointer"),
                      L"int16_t const* volatile*");

  PointerTypePtr ptr;
  ASSERT_TRUE(udt->GetFieldType(2)->CastTo(&ptr));
  ValidatePointerType(ptr->GetContentType(), PointerType::PTR_MODE_PTR,
                      kIsConst, !kIsVolatile, LookupSizeOf(L"Pointer"),
                      L"int16_t const*");
  offset += LookupSizeOf(L"Pointer");

  ASSERT_TRUE(ptr->GetContentType()->CastTo(&ptr));
  ValidateBasicType(ptr->GetContentType(), sizeof(int16_t), L"int16_t");

  // Test field: const volatile unsigned short four.
  ValidateMemberField(fields[3], offset, kBitPosZero, kBitLenZero, kIsConst,
                      kIsVolatile, L"four");
  ValidateBasicType(udt->GetFieldType(3), sizeof(int16_t), L"uint16_t");
  offset += sizeof(uint16_t);

  // Test field: unsigned short five : 3.
  ValidateMemberField(fields[4], offset, 0, 3, !kIsConst, !kIsVolatile,
                      L"five");
  ValidateBasicType(udt->GetFieldType(4), sizeof(uint16_t), L"uint16_t");

  // Test field: unsigned short six : 5.
  ValidateMemberField(fields[5], offset, 3, 5, !kIsConst, !kIsVolatile, L"six");
  ValidateBasicType(udt->GetFieldType(5), sizeof(uint16_t), L"uint16_t");
}

TEST_P(PdbCrawlerTest, TestAllInOneUDT) {
  TypePtr type = FindOneTypeBySuffix(L"::TestAllInOneUDT");
  ASSERT_TRUE(type);

  EXPECT_EQ(LookupSizeOf(L"TestAllInOneUDT"), type->size());
  EXPECT_TRUE(EndsWith(type->GetName(), L"::TestAllInOneUDT",
                       base::CompareCase::SENSITIVE));
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  UserDefinedType::Members members;
  udt->GetFieldsOfKind(&members);
  ASSERT_EQ(1U, members.size());

  ValidateMemberField(
      members[0], LookupOffsetOf(L"TestAllInOneUDT", L"regular_member"),
      kBitPosZero, kBitLenZero, !kIsConst, !kIsVolatile, L"regular_member");
  ValidateBasicType(members[0]->GetType(), sizeof(int32_t), L"int32_t");
}

TEST_P(PdbCrawlerTest, TestCollidingUDTs) {
  std::vector<TypePtr> colliding_types =
      FindTypesBySuffix(L"::TestCollidingUDT");

  ASSERT_EQ(2U, colliding_types.size());
  TypePtr type1 = colliding_types[0];
  TypePtr type2 = colliding_types[1];

  ASSERT_TRUE(type1);
  ASSERT_TRUE(type2);

  EXPECT_EQ(type1->GetName(), type2->GetName());
  EXPECT_NE(type1->GetDecoratedName(), type2->GetDecoratedName());

  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type1->kind());
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type2->kind());

  UserDefinedTypePtr udt1;
  UserDefinedTypePtr udt2;

  ASSERT_TRUE(type1->CastTo(&udt1));
  ASSERT_TRUE(udt1);
  ASSERT_TRUE(type2->CastTo(&udt2));
  ASSERT_TRUE(udt2);

  EXPECT_NE(udt1->fields().size(), udt2->fields().size());
}

TEST_P(PdbCrawlerTest, TestRecursiveUDTs) {
  TypePtr type = FindOneTypeBySuffix(L"::TestRecursiveUDT");

  ASSERT_TRUE(type);
  EXPECT_EQ(LookupSizeOf(L"TestRecursiveUDT"), type->size());
  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  EXPECT_EQ(2, udt->fields().size());
  ASSERT_EQ(Type::POINTER_TYPE_KIND, udt->GetFieldType(0)->kind());
  ASSERT_EQ(Type::POINTER_TYPE_KIND, udt->GetFieldType(1)->kind());

  PointerTypePtr ptr1;
  PointerTypePtr ptr2;

  ASSERT_TRUE(udt->GetFieldType(0)->CastTo(&ptr1));
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&ptr2));

  EXPECT_EQ(udt, ptr1->GetContentType());
  EXPECT_EQ(udt, ptr2->GetContentType());
}

TEST_P(PdbCrawlerTest, TestMemberPointerSizes) {
  TypePtr type = FindOneTypeBySuffix(L"::TestMemberPointersUDT");
  ASSERT_TRUE(type);

  EXPECT_EQ(LookupSizeOf(L"TestMemberPointersUDT"), type->size());
  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  EXPECT_EQ(8, udt->fields().size());

  for (size_t i = 0; i < udt->fields().size(); ++i) {
    ASSERT_EQ(Type::POINTER_TYPE_KIND, udt->GetFieldType(i)->kind());

    PointerTypePtr pointer;
    ASSERT_TRUE(udt->GetFieldType(i)->CastTo(&pointer));
    ASSERT_TRUE(pointer);

    MemberFieldPtr member;
    ASSERT_TRUE(udt->fields()[i]->CastTo(&member));
    const base::string16& member_name = member->name();

    // Test that the name starts with "test" and then use the rest for lookup.
    ASSERT_TRUE(
        base::StartsWith(member_name, L"test", base::CompareCase::SENSITIVE));
    EXPECT_EQ(
        LookupSizeOf(member_name.substr(strlen("test"), base::string16::npos)),
        pointer->size());
  }
}

TEST_P(PdbCrawlerTest, TestBaseClasses) {
  // ::A has no base classes.
  {
    TypePtr type = FindOneTypeBySuffix(L"::A");
    ASSERT_TRUE(type);
    UserDefinedTypePtr udt;
    ASSERT_TRUE(type->CastTo(&udt));
    ASSERT_TRUE(udt);
    UserDefinedType::BaseClasses base_classes;
    udt->GetFieldsOfKind(&base_classes);
    EXPECT_EQ(0, base_classes.size());
  }

  // ::Single has one base class.
  {
    TypePtr type = FindOneTypeBySuffix(L"::Single");
    ASSERT_TRUE(type);
    UserDefinedTypePtr udt;
    ASSERT_TRUE(type->CastTo(&udt));
    ASSERT_TRUE(udt);
    UserDefinedType::BaseClasses base_classes;
    udt->GetFieldsOfKind(&base_classes);
    ASSERT_EQ(1, base_classes.size());

    // Validate the details of the base class.
    EXPECT_EQ(UserDefinedType::Field::BASE_CLASS_KIND, base_classes[0]->kind());
    TypePtr base_type = FindOneTypeBySuffix(L"::A");
    EXPECT_EQ(base_type->type_id(), base_classes[0]->type_id());
    EXPECT_EQ(0, base_classes[0]->offset());
  }

  // ::Multi has two base classes.
  {
    TypePtr type = FindOneTypeBySuffix(L"::Multi");
    ASSERT_TRUE(type);
    UserDefinedTypePtr udt;
    ASSERT_TRUE(type->CastTo(&udt));
    ASSERT_TRUE(udt);
    UserDefinedType::BaseClasses base_classes;
    udt->GetFieldsOfKind(&base_classes);
    EXPECT_EQ(2, base_classes.size());
  }
}

TEST(PdbCrawlerVfptrFieldTest, BasicTest) {
  // Crawl for types.
  PdbCrawler crawler;
  ASSERT_TRUE(crawler.InitializeForFile(testing::GetSrcRelativePath(
    L"syzygy\\refinery\\test_data\\test_vtables.dll.pdb")));
  scoped_refptr<TypeRepository> types = new TypeRepository();
  ASSERT_TRUE(crawler.GetTypes(types.get()));
  ASSERT_LE(1U, types->size());

  // NoVirtualMethodUDT.
  {
    TypePtr type = GetOneTypeBySuffix(types.get(), L"::NoVirtualMethodUDT");
    ASSERT_TRUE(type);
    UserDefinedTypePtr udt;
    ASSERT_TRUE(type->CastTo(&udt));
    ASSERT_TRUE(udt);
    UserDefinedType::Vfptrs vfptrs;
    udt->GetFieldsOfKind(&vfptrs);
    EXPECT_EQ(0, vfptrs.size());
  }

  // VirtualMethodUDT.
  {
    TypePtr type = GetOneTypeBySuffix(types.get(), L"::VirtualMethodUDT");
    ASSERT_TRUE(type);
    UserDefinedTypePtr udt;
    ASSERT_TRUE(type->CastTo(&udt));
    ASSERT_TRUE(udt);
    UserDefinedType::Vfptrs vfptrs;
    udt->GetFieldsOfKind(&vfptrs);
    EXPECT_EQ(1, vfptrs.size());

    // Validate the kind / offset of the vfptr.
    EXPECT_EQ(UserDefinedType::Field::VFPTR_KIND, vfptrs[0]->kind());
    EXPECT_EQ(0, vfptrs[0]->offset());
  }

  // ChildUDT: we expect no vfptr (it's in the base class).
  {
    TypePtr type = GetOneTypeBySuffix(types.get(), L"::ChildUDT");
    ASSERT_TRUE(type);
    UserDefinedTypePtr udt;
    ASSERT_TRUE(type->CastTo(&udt));
    ASSERT_TRUE(udt);
    UserDefinedType::Vfptrs vfptrs;
    udt->GetFieldsOfKind(&vfptrs);
    EXPECT_EQ(0, vfptrs.size());
  }

  // TODO(manzagop): figure out how to generate and test for vfptr at non-0
  // offset.
}

TEST_P(PdbCrawlerTest, TestMFunction) {
  TypePtr type =
      FindOneTypeBySuffix(L"char const (testing::TestAllInOneUDT::)(int32_t)");
  ASSERT_TRUE(type);

  FunctionTypePtr function;
  ASSERT_EQ(Type::FUNCTION_TYPE_KIND, type->kind());
  ASSERT_TRUE(type->CastTo(&function));
  ASSERT_TRUE(function);

  const FunctionType::Arguments& args = function->argument_types();

  EXPECT_EQ(1U, args.size());

  EXPECT_TRUE(function->IsMemberFunction());
  EXPECT_TRUE(function->return_type().is_const());
  EXPECT_FALSE(function->return_type().is_volatile());
  ValidateBasicType(function->GetReturnType(), sizeof(char), L"char");

  EXPECT_FALSE(args[0].is_const());
  EXPECT_FALSE(args[0].is_volatile());
  ValidateBasicType(function->GetArgumentType(0), sizeof(int32_t), L"int32_t");

  // Find the containing class.
  type = FindOneTypeBySuffix(L"::TestAllInOneUDT");
  ASSERT_TRUE(type);

  // Check that the function points to its containing class.
  EXPECT_EQ(function->containing_class_id(), type->type_id());

  EXPECT_EQ(function->GetName(),
            L"char const (" + type->GetName() + L"::)(int32_t)");
  EXPECT_EQ(function->GetDecoratedName(),
            L"char const (" + type->GetDecoratedName() + L"::)(int32_t)");
}

TEST_P(PdbCrawlerTest, TestProcedure) {
  std::vector<TypePtr> type_vector = FindTypesBySuffix(L"void ()");

  // There could be more than one procedure  with different calling conventions.
  ASSERT_LE(1U, type_vector.size());

  TypePtr type = type_vector[0];
  ASSERT_TRUE(type);

  FunctionTypePtr function;
  ASSERT_EQ(Type::FUNCTION_TYPE_KIND, type->kind());
  ASSERT_TRUE(type->CastTo(&function));
  ASSERT_TRUE(function);

  const FunctionType::Arguments& args = function->argument_types();

  EXPECT_EQ(0, args.size());

  EXPECT_FALSE(function->IsMemberFunction());
  EXPECT_EQ(kNoTypeId, function->containing_class_id());

  EXPECT_FALSE(function->return_type().is_const());
  EXPECT_FALSE(function->return_type().is_volatile());
  ValidateBasicType(function->GetReturnType(), 0, L"void");
}

TEST_P(PdbCrawlerTest, TestReference) {
  TypePtr type = FindOneTypeBySuffix(L"::TestReference");
  ASSERT_TRUE(type);

  EXPECT_TRUE(EndsWith(type->GetName(), L"::TestReference",
                       base::CompareCase::SENSITIVE));
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(2U, fields.size());

  MemberFieldPtr member;
  ASSERT_TRUE(fields[0]->CastTo(&member));
  EXPECT_EQ(L"value", member->name());
  ValidateBasicType(udt->GetFieldType(0), sizeof(int32_t), L"int32_t");

  ASSERT_TRUE(fields[1]->CastTo(&member));
  EXPECT_EQ(L"reference", member->name());
  EXPECT_FALSE(member->is_const());
  EXPECT_FALSE(member->is_volatile());
  ValidatePointerType(udt->GetFieldType(1), PointerType::PTR_MODE_REF, kIsConst,
                      !kIsVolatile, LookupSizeOf(L"Pointer"),
                      L"int32_t const&");
}

TEST_P(PdbCrawlerTest, TestArray) {
  TypePtr type = FindOneTypeBySuffix(L"::TestArrays");
  ASSERT_TRUE(type);

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  ASSERT_EQ(2U, udt->fields().size());

  ArrayTypePtr int_array;
  ASSERT_TRUE(udt->GetFieldType(0)->CastTo(&int_array));
  ASSERT_TRUE(int_array);

  ValidateArrayType(int_array, kIsConst, !kIsVolatile, sizeof(int32_t) * 30, 30,
                    L"int32_t const[30]");

  TypePtr index_type = int_array->GetIndexType();

  const size_t kIndexTypeSize = LookupSizeOf(L"IndexingType");
  const base::string16 kIndexTypeName =
      base::StringPrintf(L"uint%d_t", kIndexTypeSize * 8);

  ValidateBasicType(index_type, kIndexTypeSize, kIndexTypeName);

  TypePtr element_type = int_array->GetElementType();
  ValidateBasicType(element_type, sizeof(int32_t), L"int32_t");

  PointerTypePtr array_ptr;
  ASSERT_TRUE(udt->GetFieldType(1)->CastTo(&array_ptr));

  ArrayTypePtr ptr_array;
  ASSERT_TRUE(array_ptr->GetContentType()->CastTo(&ptr_array));

  ValidateArrayType(ptr_array, !kIsConst, kIsVolatile,
                    LookupSizeOf(L"Pointer") * 32, 32,
                    L"testing::TestRecursiveUDT* volatile[32]");

  index_type = ptr_array->GetIndexType();
  ValidateBasicType(index_type, kIndexTypeSize, kIndexTypeName);

  element_type = ptr_array->GetElementType();
  ValidatePointerType(element_type, PointerType::PTR_MODE_PTR, !kIsConst,
                      !kIsVolatile, LookupSizeOf(L"Pointer"),
                      L"testing::TestRecursiveUDT*");
  EXPECT_EQ(L"testing::TestRecursiveUDT*", element_type->GetName());
}

TEST_P(PdbCrawlerTest, TestFunctions) {
  TypePtr type = FindOneTypeBySuffix(L"::TestFunctions");
  ASSERT_TRUE(type);

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  ASSERT_EQ(0U, udt->fields().size());
  ASSERT_EQ(4U, udt->functions().size());

  const UserDefinedType::Functions& functions = udt->functions();
  FunctionTypePtr function;

  // First function is a constructor.
  EXPECT_EQ(L"TestFunctions", functions[0].name());
  EXPECT_TRUE(udt->GetFunctionType(0)->CastTo(&function));
  EXPECT_EQ(0U, function->argument_types().size());
  ValidateBasicType(function->GetReturnType(), 0, L"void");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());

  EXPECT_EQ(L"NonOverloadedFunction", functions[1].name());
  EXPECT_TRUE(udt->GetFunctionType(1)->CastTo(&function));
  EXPECT_EQ(0U, function->argument_types().size());
  ValidateBasicType(function->GetReturnType(), 0, L"void");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());

  EXPECT_EQ(L"OverloadedFunction", functions[2].name());
  EXPECT_TRUE(udt->GetFunctionType(2)->CastTo(&function));
  EXPECT_EQ(1U, function->argument_types().size());
  ValidateBasicType(function->GetArgumentType(0), sizeof(int32_t), L"int32_t");
  ValidateBasicType(function->GetReturnType(), 0, L"void");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());

  EXPECT_EQ(L"OverloadedFunction", functions[3].name());
  EXPECT_TRUE(udt->GetFunctionType(3)->CastTo(&function));
  EXPECT_EQ(0U, function->argument_types().size());
  ValidateBasicType(function->GetReturnType(), sizeof(int32_t), L"int32_t");
  EXPECT_EQ(udt->type_id(), function->containing_class_id());
}

TEST_P(PdbCrawlerTest, TestComplicatedTypeGraph) {
  TypePtr type = FindOneTypeBySuffix(L"::ComplicatedTypeA");
  ASSERT_TRUE(type);

  UserDefinedTypePtr class_a;
  ASSERT_TRUE(type->CastTo(&class_a));

  type = FindOneTypeBySuffix(L"::ComplicatedTypeB");
  ASSERT_TRUE(type);

  UserDefinedTypePtr class_b;
  ASSERT_TRUE(type->CastTo(&class_b));

  // Correct name of the function
  EXPECT_EQ(L"void (testing::ComplicatedTypeB::)(testing::ComplicatedTypeA)",
            class_b->GetFunctionType(0)->GetName());

  // And also correct name of the pointer. This wasn't possible to populate with
  // only one traversal through the type stream.
  EXPECT_EQ(L"void (testing::ComplicatedTypeB::)(testing::ComplicatedTypeA)*",
            class_a->GetFieldType(0)->GetName());
}

TEST_P(PdbCrawlerTest, TestNullptrType) {
  TypePtr type = FindOneTypeBySuffix(L"::TestNullptrType");
  ASSERT_TRUE(type);

  UserDefinedTypePtr nullptr_struct;
  ASSERT_TRUE(type->CastTo(&nullptr_struct));

  EXPECT_EQ(1U, nullptr_struct->fields().size());
  ValidateBasicType(nullptr_struct->GetFieldType(0), 0, L"nullptr_t");
}

TEST_P(PdbCrawlerTest, TestBitfields) {
  TypePtr type = FindOneTypeBySuffix(L"::TestBitfields");
  ASSERT_TRUE(type);
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(4U, fields.size());

  ValidateMemberField(fields[0], 0, 0, 1, !kIsConst, !kIsVolatile,
                      L"bool_bitfield");
  ValidateBasicType(udt->GetFieldType(0), sizeof(bool), L"bool");

  ValidateMemberField(fields[1], 4, 0, 1, !kIsConst, !kIsVolatile,
                      L"int_bitfield");
  ValidateBasicType(udt->GetFieldType(1), sizeof(int32_t), L"int32_t");

  // TODO(mopler): Once we parse enum types, change this.
  ValidateMemberField(fields[2], 8, 0, 1, !kIsConst, !kIsVolatile,
                      L"enum_bitfield");
  ValidateWildcardType(udt->GetFieldType(2), 0, L"LF_ENUM");

  ValidateMemberField(fields[3], 8, 1, 1, kIsConst, !kIsVolatile,
                      L"const_enum_bitfield");
  ValidateWildcardType(udt->GetFieldType(3), 0, L"LF_ENUM");
}

TEST_P(PdbCrawlerTest, TestLongFieldlist) {
  TypePtr type = FindOneTypeBySuffix(L"::TestStructWithLongFieldlist");
  ASSERT_TRUE(type);

  UserDefinedTypePtr long_fieldlist;
  ASSERT_TRUE(type->CastTo(&long_fieldlist));

  // We should have read all of the fieldlist parts.
  EXPECT_EQ(765U, long_fieldlist->fields().size());
}

TEST_P(PdbCrawlerTest, TestForwardDeclaredClass) {
  TypePtr type = FindOneTypeBySuffix(L"::Unknown");
  ASSERT_TRUE(type);

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  EXPECT_EQ(0, udt->fields().size());
  EXPECT_EQ(0, udt->functions().size());
  EXPECT_TRUE(udt->is_fwd_decl());
  EXPECT_EQ(UserDefinedType::UDT_CLASS, udt->udt_kind());
}

TEST_P(PdbCrawlerTest, TestUnion) {
  TypePtr type = FindOneTypeBySuffix(L"::TestUnion");
  ASSERT_TRUE(type);

  ASSERT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  EXPECT_EQ(0, udt->functions().size());
  EXPECT_FALSE(udt->is_fwd_decl());
  EXPECT_EQ(UserDefinedType::UDT_UNION, udt->udt_kind());

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(2U, fields.size());

  ValidateMemberField(fields[0], 0, 0, 0, !kIsConst, !kIsVolatile,
                      L"signed_int");
  ValidateBasicType(udt->GetFieldType(0), sizeof(int32_t), L"int32_t");

  ValidateMemberField(fields[1], 0, 0, 0, !kIsConst, !kIsVolatile,
                      L"unsigned_int");
  ValidateBasicType(udt->GetFieldType(1), sizeof(uint32_t), L"uint32_t");
}

// Run both the 32-bit and 64-bit tests.
INSTANTIATE_TEST_CASE_P(InstantiateFor32and64,
                        PdbCrawlerTest,
                        ::testing::Values(32, 64));


class PdbCrawlerVTableTest : public testing::PdbCrawlerVTableTestBase {
 protected:
  void GetVFTableRVAs(const wchar_t* pdb_path_str,
                      base::hash_set<Address>* vftable_rvas) override {
    DCHECK(pdb_path_str);  DCHECK(vftable_rvas);

    PdbCrawler crawler;
    ASSERT_TRUE(
        crawler.InitializeForFile(testing::GetSrcRelativePath(pdb_path_str)));
    ASSERT_TRUE(crawler.GetVFTableRVAs(vftable_rvas));
  }
};

TEST_F(PdbCrawlerVTableTest, TestGetVFTableRVAs) {
  // A pdb without OMAP.
  ASSERT_NO_FATAL_FAILURE(PerformGetVFTableRVAsTest(
      L"syzygy\\refinery\\test_data\\test_vtables.dll.pdb",
      L"syzygy\\refinery\\test_data\\test_vtables.dll"));

  // A pdb with OMAP.
  ASSERT_NO_FATAL_FAILURE(PerformGetVFTableRVAsTest(
      L"syzygy\\refinery\\test_data\\test_vtables_omap.dll.pdb",
      L"syzygy\\refinery\\test_data\\test_vtables_omap.dll"));
}

}  // namespace refinery
