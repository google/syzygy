// Copyright 2013 Google Inc. All Rights Reserved.
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

#include "syzygy/agent/profiler/symbol_map.h"

#include "gmock/gmock.h"
#include "gtest/gtest.h"

namespace agent {
namespace profiler {

namespace {

class TestingSymbolMap : public SymbolMap {
 public:
  // Expose the address space for testing.
  using SymbolMap::addr_space_;
  typedef SymbolMap::SymbolAddressSpace SymbolAddressSpace;
};

const uint8* ToPtr(intptr_t number) {
  return reinterpret_cast<const uint8*>(number);
}

class SymbolMapTest : public testing::Test {
 protected:
  TestingSymbolMap symbol_map_;
};

}  // namespace

TEST_F(SymbolMapTest, AddSymbol) {
  // Insert a symbol.
  symbol_map_.AddSymbol(ToPtr(0x1011), 0x22, "foo");

  // Reach into the privates of the symbol map and test it's as we expect.
  ASSERT_EQ(1, symbol_map_.addr_space_.size());
  TestingSymbolMap::SymbolAddressSpace::iterator it =
      symbol_map_.addr_space_.begin();
  ASSERT_TRUE(it != symbol_map_.addr_space_.end());

  EXPECT_EQ(it->first.start(), ToPtr(0x1011));
  EXPECT_EQ(it->first.size(), 0x22);

  // Test that the new symbol is correctly initialized.
  scoped_refptr<SymbolMap::Symbol> symbol = it->second;
  ASSERT_TRUE(symbol != NULL);
  EXPECT_EQ("foo", symbol->name());
  EXPECT_FALSE(symbol->invalid());
  EXPECT_EQ(0, symbol->id());
  EXPECT_EQ(0, symbol->move_count());
}

TEST_F(SymbolMapTest, EnsureHasId) {
  const uint8* const kStart = ToPtr(0x1023);

  // Insert a symbol.
  symbol_map_.AddSymbol(kStart, 0x22, "foo");

  scoped_refptr<SymbolMap::Symbol> symbol = symbol_map_.FindSymbol(kStart);

  // The symbol should not have an ID yet.
  EXPECT_EQ(0, symbol->id());

  // Assign it one.
  EXPECT_TRUE(symbol->EnsureHasId());
  uint32 id = symbol->id();
  EXPECT_NE(0U, id);

  // We should only get a true return once from EnsureHasId.
  EXPECT_FALSE(symbol->EnsureHasId());
  // And the symbol's ID should not change after initial assignment.
  EXPECT_EQ(id, symbol->id());
}

TEST_F(SymbolMapTest, AddMoveSymbol) {
  // Insert & move a symbol.
  symbol_map_.AddSymbol(ToPtr(0x1011), 0x22, "foo");
  symbol_map_.MoveSymbol(ToPtr(0x1011), ToPtr(0x2000));

  // Reach into the privates of the symbol map and test it's as we expect.
  ASSERT_EQ(1, symbol_map_.addr_space_.size());
  TestingSymbolMap::SymbolAddressSpace::iterator it =
      symbol_map_.addr_space_.begin();
  ASSERT_TRUE(it != symbol_map_.addr_space_.end());

  EXPECT_EQ(it->first.start(), ToPtr(0x2000));
  EXPECT_EQ(it->first.size(), 0x22);

  // Test that the new symbol is correctly initialized.
  scoped_refptr<SymbolMap::Symbol> symbol = it->second;
  ASSERT_TRUE(symbol != NULL);
  EXPECT_EQ("foo", symbol->name());
  EXPECT_FALSE(symbol->invalid());
  EXPECT_EQ(0, symbol->id());

  // It should have accrued one move.
  EXPECT_EQ(1, symbol->move_count());
}

TEST_F(SymbolMapTest, FindSymbol) {
  const uint8* const kStart = ToPtr(0x1023);
  ASSERT_TRUE(symbol_map_.FindSymbol(kStart) == NULL);

  symbol_map_.AddSymbol(kStart, 0x22, "foo");

  scoped_refptr<SymbolMap::Symbol> symbol = symbol_map_.FindSymbol(kStart);
  ASSERT_TRUE(symbol != NULL);
  ASSERT_EQ(symbol, symbol_map_.FindSymbol(kStart + 1));
  ASSERT_EQ(symbol, symbol_map_.FindSymbol(kStart + 0x21));

  ASSERT_TRUE(symbol_map_.FindSymbol(kStart + 0x22) == NULL);
}

TEST_F(SymbolMapTest, SymbolLifeCycle) {
  // Insert a symbol.
  symbol_map_.AddSymbol(ToPtr(0x1011), 0x22, "foo");

  // Find the symbol through the public symbol map interface.
  scoped_refptr<SymbolMap::Symbol> symbol =
      symbol_map_.FindSymbol(ToPtr(0x1026));

  ASSERT_TRUE(symbol != NULL);
  EXPECT_EQ("foo", symbol->name());
  EXPECT_FALSE(symbol->invalid());

  EXPECT_EQ(0, symbol->id());
  EXPECT_EQ(0, symbol->move_count());

  // Assign an ID to the symbol.
  EXPECT_TRUE(symbol->EnsureHasId());
  uint32 id = symbol->id();
  EXPECT_NE(0U, id);

  // We should only return true on first assigning an id to the symbol.
  EXPECT_FALSE(symbol->EnsureHasId());
  EXPECT_EQ(id, symbol->id());

  // Move "foo".
  symbol_map_.MoveSymbol(ToPtr(0x1011), ToPtr(0x2000));
  EXPECT_EQ(1, symbol->move_count());

  // Nothing should be at the original location.
  EXPECT_TRUE(symbol_map_.FindSymbol(ToPtr(0x1026)) == NULL);
  // And we should find the same symbol at the new one.
  EXPECT_EQ(symbol, symbol_map_.FindSymbol(ToPtr(0x2014)));
  EXPECT_FALSE(symbol->invalid());
  EXPECT_EQ(id, symbol->id());

  // Add a new symbol, overlapping "foo", this should invalidate the symbol.
  symbol_map_.AddSymbol(ToPtr(0x2010), 0x20, "overlapping");
  EXPECT_TRUE(symbol->invalid());
  EXPECT_EQ(id, symbol->id());
  EXPECT_EQ(1, symbol->move_count());
}

}  // namespace profiler
}  // namespace agent
