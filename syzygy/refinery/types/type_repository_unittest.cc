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

#include "syzygy/refinery/types/type_repository.h"

#include "base/memory/ref_counted.h"
#include "gtest/gtest.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/refinery/types/type.h"

namespace refinery {

TEST(TypeRepositoryTest, AddType) {
  scoped_refptr<TypeRepository> repo = new TypeRepository();
  EXPECT_EQ(0U, repo->size());

  // Returns a NULL type for unknown TypeId.
  EXPECT_FALSE(repo->GetType(1));

  for (auto type : *repo)
    FAIL() << "Non-empty enumeration in an empty TypeRepository";

  TypePtr t1 = new BasicType(L"uint", 4);
  TypePtr t2 = new BasicType(L"int", 4);
  EXPECT_EQ(nullptr, t1->repository());
  EXPECT_EQ(nullptr, t2->repository());

  TypeId id1 = repo->AddType(t1);
  TypeId id2 = repo->AddType(t2);
  EXPECT_EQ(2U, repo->size());

  EXPECT_NE(id1, id2);

  EXPECT_EQ(repo.get(), t1->repository());
  EXPECT_EQ(repo.get(), t2->repository());

  EXPECT_EQ(t1, repo->GetType(id1));
  EXPECT_EQ(t2, repo->GetType(id2));
}

TEST(TypeRepositoryTest, AddTypeWithId) {
  scoped_refptr<TypeRepository> repo = new TypeRepository();
  EXPECT_EQ(0U, repo->size());

  // Returns a NULL type for unknown TypeId.
  EXPECT_FALSE(repo->GetType(1));

  for (auto type : *repo)
    FAIL() << "Non-empty enumeration in an empty TypeRepository";

  TypePtr t1 = new BasicType(L"uint", 4);
  TypePtr t2 = new BasicType(L"int", 4);
  TypePtr t3 = new BasicType(L"char", 1);

  const TypeId kId1 = 42;
  const TypeId kId2 = 31;
  EXPECT_EQ(nullptr, t1->repository());
  EXPECT_EQ(nullptr, t2->repository());

  EXPECT_TRUE(repo->AddTypeWithId(t1, kId1));
  EXPECT_TRUE(repo->AddTypeWithId(t2, kId2));
  EXPECT_EQ(2U, repo->size());

  EXPECT_EQ(repo.get(), t1->repository());
  EXPECT_EQ(repo.get(), t2->repository());

  // There is still no object with id 1.
  EXPECT_FALSE(repo->GetType(1));

  // This index is already taken.
  EXPECT_FALSE(repo->AddTypeWithId(t3, kId1));

  EXPECT_EQ(t1, repo->GetType(kId1));
  EXPECT_EQ(t2, repo->GetType(kId2));
}

TEST(TypeRepositoryTest, GetSignature) {
  pe::PEFile::Signature retrieved_sig;

  scoped_refptr<TypeRepository> repo = new TypeRepository();
  ASSERT_FALSE(repo->GetModuleSignature(&retrieved_sig));

  pe::PEFile::Signature sig(L"Path", core::AbsoluteAddress(1U), 2, 3, 4);
  repo = new TypeRepository(sig);
  ASSERT_TRUE(repo->GetModuleSignature(&retrieved_sig));
  ASSERT_EQ(sig, retrieved_sig);
}

TEST(TypeRepositoryTest, Iteration) {
  scoped_refptr<TypeRepository> repo = new TypeRepository();

  repo->AddType(new BasicType(L"one", 4));
  repo->AddType(new BasicType(L"two", 4));
  repo->AddType(new BasicType(L"three", 4));
  EXPECT_EQ(3U, repo->size());

  size_t iterated = 0;
  for (auto type : *repo) {
    ++iterated;

    ASSERT_TRUE(type);
    EXPECT_EQ(Type::BASIC_TYPE_KIND, type->kind());
    EXPECT_TRUE(type->GetName() == L"one" || type->GetName() == L"two" ||
                type->GetName() == L"three");
  }

  EXPECT_EQ(3U, iterated);
}

TEST(TypeNameIndexTest, BasicTest) {
  const wchar_t kNotATypeName[] = L"not";
  const wchar_t kTypeNameOne[] = L"one";
  const wchar_t kTypeNameTwo[] = L"two";

  // Create a TypeRepository.
  scoped_refptr<TypeRepository> repo = new TypeRepository();
  TypePtr one = new BasicType(kTypeNameOne, 4);
  repo->AddType(one);
  TypePtr other_one = new BasicType(kTypeNameOne, 4);
  repo->AddType(other_one);
  TypePtr two = new BasicType(kTypeNameTwo, 4);
  repo->AddType(two);

  // Create index.
  scoped_refptr<TypeNameIndex> index = new TypeNameIndex(repo);

  // No match when not a type name.
  std::vector<TypePtr> matching_types;
  index->GetTypes(kNotATypeName, &matching_types);
  ASSERT_EQ(0, matching_types.size());

  // Match with multiple hits.
  index->GetTypes(kTypeNameOne, &matching_types);
  ASSERT_EQ(2, matching_types.size());

  // Match with single hit.
  matching_types.clear();
  index->GetTypes(kTypeNameTwo, &matching_types);
  ASSERT_EQ(1, matching_types.size());
  ASSERT_EQ(two.get(), matching_types[0].get());
}

}  // namespace refinery
