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

#include "base/path_service.h"
#include "base/debug/alias.h"
#include "base/files/file_path.h"
#include "base/strings/string_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/pdb_dbi_stream.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_stream_record.h"
#include "syzygy/pdb/pdb_symbol_record.h"
#include "syzygy/pe/cvinfo_ext.h"
#include "syzygy/refinery/types/type.h"
#include "syzygy/refinery/types/type_repository.h"

namespace refinery {

namespace {

class PdbCrawlerTest : public testing::Test {
 protected:
  void SetUp() override {
    test_types_file_ = testing::GetSrcRelativePath(
        L"syzygy\\refinery\\test_data\\test_types.dll.pdb");
    LoadTypes();
  }

  void LoadTypes() {
    ASSERT_TRUE(crawler_.InitializeForFile(test_types_file_));

    ASSERT_TRUE(crawler_.GetTypes(&types_));
    ASSERT_LE(1U, types_.size());
  }

  // This function reads all the constants from the symbol stream. We use this
  // to find the const static variables containing sizes of member pointers.
  void LoadConstantsFromSymbolStream() {
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
    ASSERT_TRUE(pdb::ReadSymbolRecord(
        sym_record_stream.get(), sym_record_stream->length(), &symbol_vector));

    pdb::SymbolRecordVector::const_iterator symbol_iter = symbol_vector.begin();
    for (; symbol_iter != symbol_vector.end(); ++symbol_iter) {
      ASSERT_TRUE(sym_record_stream->Seek(symbol_iter->start_position));

      // We are interested only in constants.
      if (symbol_iter->type != Microsoft_Cci_Pdb::S_CONSTANT)
        continue;

      // Read the type index it points to.
      uint32_t type_index = 0;
      ASSERT_TRUE(sym_record_stream->Read(&type_index, 1));

      // Read the value.
      uint64_t value;
      ASSERT_TRUE(pdb::ReadUnsignedNumeric(sym_record_stream.get(), &value));

      // And its name.
      base::string16 name;
      ASSERT_TRUE(pdb::ReadWideString(sym_record_stream.get(), &name));

      constants_.insert(std::make_pair(name, value));
    }
  }

  std::vector<TypePtr> FindTypesBySuffix(const base::string16& suffix) {
    std::vector<TypePtr> found_types;
    for (auto it = types_.begin(); it != types_.end(); ++it) {
      if (base::EndsWith((*it)->name(), suffix, base::CompareCase::SENSITIVE)) {
        found_types.push_back(*it);
      }
    }
    return found_types;
  }

  PdbCrawler crawler_;
  base::FilePath test_types_file_;
  base::hash_map<base::string16, size_t> constants_;
  TypeRepository types_;
};

void ValidateField(const UserDefinedType::Field& field,
                   size_t offset,
                   size_t bit_pos,
                   size_t bit_len,
                   bool is_const,
                   bool is_volatile,
                   const base::string16& name) {
  EXPECT_EQ(offset, field.offset());
  EXPECT_EQ(name, field.name());
  EXPECT_EQ(is_const, field.is_const());
  EXPECT_EQ(is_volatile, field.is_volatile());
  EXPECT_EQ(bit_pos, field.bit_pos());
  EXPECT_EQ(bit_len, field.bit_len());
}

void ValidateBasicType(TypePtr type, size_t size, const base::string16& name) {
  EXPECT_EQ(Type::BASIC_TYPE_KIND, type->kind());
  EXPECT_EQ(size, type->size());
  EXPECT_EQ(name, type->name());
}

void ValidatePointerType(TypePtr type,
                         bool is_const,
                         bool is_volatile,
                         size_t size,
                         const base::string16& name) {
  EXPECT_EQ(Type::POINTER_TYPE_KIND, type->kind());
  PointerTypePtr ptr;
  ASSERT_TRUE(type->CastTo(&ptr));
  EXPECT_EQ(is_const, ptr->is_const());
  EXPECT_EQ(is_volatile, ptr->is_volatile());
  EXPECT_EQ(size, type->size());
  EXPECT_EQ(name, type->name());
}

}  // namespace

TEST_F(PdbCrawlerTest, TestSimpleUDT) {
  std::vector<TypePtr> simple_udt = FindTypesBySuffix(L"::TestSimpleUDT");

  ASSERT_EQ(1U, simple_udt.size());

  TypePtr type = simple_udt[0];

  const size_t kBitPosZero = 0;
  const size_t kBitLenZero = 0;
  const bool kIsConst = true;
  const bool kIsVolatile = true;

  ASSERT_TRUE(type);

  EXPECT_EQ(16, type->size());
  EXPECT_TRUE(
      EndsWith(type->name(), L"::TestSimpleUDT", base::CompareCase::SENSITIVE));
  EXPECT_EQ(Type::USER_DEFINED_TYPE_KIND, type->kind());

  UserDefinedTypePtr udt;
  ASSERT_TRUE(type->CastTo(&udt));
  ASSERT_TRUE(udt);

  const UserDefinedType::Fields& fields = udt->fields();
  ASSERT_EQ(6U, fields.size());

  // Test field: int one.
  ValidateField(fields[0], 0, kBitPosZero, kBitLenZero, !kIsConst, !kIsVolatile,
                L"one");
  ValidateBasicType(udt->GetFieldType(0), 4, L"int32_t");

  // Test field: const char two.
  ValidateField(fields[1], 4, kBitPosZero, kBitLenZero, kIsConst, !kIsVolatile,
                L"two");
  ValidateBasicType(udt->GetFieldType(1), 1, L"char");

  // Test field: short const* volatile* three.
  ValidateField(fields[2], 8, kBitPosZero, kBitLenZero, !kIsConst, !kIsVolatile,
                L"three");
  ValidatePointerType(udt->GetFieldType(2), !kIsConst, kIsVolatile, 4,
                      L"int16_t const* volatile*");

  PointerTypePtr ptr;
  ASSERT_TRUE(udt->GetFieldType(2)->CastTo(&ptr));
  ValidatePointerType(ptr->GetContentType(), kIsConst, !kIsVolatile, 4,
                      L"int16_t const*");

  ASSERT_TRUE(ptr->GetContentType()->CastTo(&ptr));
  ValidateBasicType(ptr->GetContentType(), 2, L"int16_t");

  // Test field: const volatile unsigned short four.
  ValidateField(fields[3], 12, kBitPosZero, kBitLenZero, kIsConst, kIsVolatile,
                L"four");
  ValidateBasicType(udt->GetFieldType(3), 2, L"uint16_t");

  // Test field: unsigned short five : 3.
  ValidateField(fields[4], 14, 0, 3, !kIsConst, !kIsVolatile, L"five");
  ValidateBasicType(udt->GetFieldType(4), 2, L"uint16_t");

  // Test field: unsigned short six : 5.
  ValidateField(fields[5], 14, 3, 5, !kIsConst, !kIsVolatile, L"six");
  ValidateBasicType(udt->GetFieldType(5), 2, L"uint16_t");
}

TEST_F(PdbCrawlerTest, TestCollidingUDTs) {
  std::vector<TypePtr> colliding_types =
      FindTypesBySuffix(L"::TestCollidingUDT");

  ASSERT_EQ(2U, colliding_types.size());
  TypePtr type1 = colliding_types[0];
  TypePtr type2 = colliding_types[1];

  ASSERT_TRUE(type1);
  ASSERT_TRUE(type2);

  EXPECT_EQ(type1->name(), type2->name());
  EXPECT_NE(type1->decorated_name(), type2->decorated_name());

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

TEST_F(PdbCrawlerTest, TestRecursiveUDTs) {
  std::vector<TypePtr> recursive_udt = FindTypesBySuffix(L"::TestRecursiveUDT");

  ASSERT_EQ(1U, recursive_udt.size());

  TypePtr type = recursive_udt[0];

  ASSERT_TRUE(type);

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

// TODO(mopler): Test also against 64-bit images.
TEST_F(PdbCrawlerTest, TestMemberPointerSizes) {
  ASSERT_NO_FATAL_FAILURE(LoadConstantsFromSymbolStream());

  std::vector<TypePtr> member_data_udt =
      FindTypesBySuffix(L"::TestMemberPointersUDT");

  ASSERT_EQ(1U, member_data_udt.size());

  TypePtr type = member_data_udt[0];

  ASSERT_TRUE(type);
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

    const base::string16& member_name = udt->fields()[i].name();
    ASSERT_TRUE(
        base::StartsWith(member_name, L"test", base::CompareCase::SENSITIVE));
    base::string16 const_name =
        L"k" + member_name.substr(4, base::string16::npos);

    const auto it = constants_.find(const_name);
    ASSERT_NE(constants_.end(), it);
    EXPECT_EQ(pointer->size(), it->second);
  }
}

}  // namespace refinery
