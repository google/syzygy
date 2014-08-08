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

#ifndef SYZYGY_AGENT_PROFILER_SYMBOL_MAP_H_
#define SYZYGY_AGENT_PROFILER_SYMBOL_MAP_H_

#include "base/atomicops.h"
#include "base/basictypes.h"
#include "base/memory/ref_counted.h"
#include "base/strings/string_piece.h"
#include "base/synchronization/lock.h"
#include "syzygy/core/address_space.h"

namespace agent {
namespace profiler {

// The symbol map maintains a map from address range to "symbol" to allow
// resolving addresses of dynamically generated, garbage collected code, to
// names in a profiler. This is geared to allow entry/exit processing in a
// profiler to execute as quickly as possible.
class SymbolMap {
 public:
  class Symbol;

  SymbolMap();
  ~SymbolMap();

  // Adds a new symbol to the symbol map.
  // @param start_addr the starting address of the new symbol.
  // @param length the length of the new symbol.
  // @param name the name of the new symbol.
  void AddSymbol(const void* start_addr,
                 size_t length,
                 const base::StringPiece& name);

  // Move an existing symbol.
  // @param old_addr the previous address of the symbol.
  // @param new_addr the new address of the symbol.
  void MoveSymbol(const void* old_addr, const void* new_addr);

  // Find the symbol covering @p addr, if any.
  // @param addr an address to query.
  // @returns the symbol covering @p addr, if any, or NULL otherwise.
  scoped_refptr<Symbol> FindSymbol(const void* addr);

 protected:
  typedef core::AddressSpace<const uint8*, size_t, scoped_refptr<Symbol>>
      SymbolAddressSpace;
  typedef SymbolAddressSpace::Range Range;

  // Retire any symbols overlapping @p range.
  void RetireRangeUnlocked(const Range& range);

  base::Lock lock_;
  SymbolAddressSpace addr_space_;  // Under lock_.

 private:
  DISALLOW_COPY_AND_ASSIGN(SymbolMap);
};

class SymbolMap::Symbol : public base::RefCountedThreadSafe<Symbol> {
 public:
  class AutoLock;

  explicit Symbol(const base::StringPiece& name, const void* address);

  // Name this symbol by assigning it an id, if it doesn't already have one.
  // @returns true iff the symbol did not already have an id.
  bool EnsureHasId();

  // @name Accessors.
  // @{
  const std::string& name() const { return name_; }
  bool invalid() const { return address_ == NULL; }
  int32 id() const { return id_; }
  int32 move_count() const { return base::subtle::Acquire_Load(&move_count_); }
  const void* address() const { return address_; }
  // @}

 protected:
  friend class SymbolMap;

  // Invalidate this symbol.
  void Invalidate();
  // Move this symbol.
  void Move(const void* address);

  std::string name_;

  // Incremented each time the symbol moves.
  base::subtle::Atomic32 move_count_;

  // Non-zero after first call to EnsureHasId.
  base::subtle::Atomic32 id_;

  // The current address of this symbol.
  const void* address_;

 private:
  friend class base::RefCountedThreadSafe<Symbol>;
  ~Symbol() {}

  static base::subtle::Atomic32 next_symbol_id_;

 private:
  DISALLOW_COPY_AND_ASSIGN(Symbol);
};

}  // namespace profiler
}  // namespace agent

#endif  // SYZYGY_AGENT_PROFILER_SYMBOL_MAP_H_
