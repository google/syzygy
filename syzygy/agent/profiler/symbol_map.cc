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

namespace agent {
namespace profiler {

base::subtle::Atomic32 SymbolMap::Symbol::next_symbol_id_ = 0;

SymbolMap::SymbolMap() {
}

SymbolMap::~SymbolMap() {
}

void SymbolMap::AddSymbol(const void* start_addr,
                          size_t length,
                          const base::StringPiece& name) {
  base::AutoLock hold(lock_);

  scoped_refptr<Symbol> symbol = new Symbol(name, start_addr);
  // TODO(siggi): Perhaps this should be an error?
  if (!symbol)
    return;

  Range range(reinterpret_cast<const uint8_t*>(start_addr), length);
  RetireRangeUnlocked(range);

  bool inserted = addr_space_.Insert(
      Range(reinterpret_cast<const uint8_t*>(start_addr), length), symbol);
  DCHECK(inserted);
}

void SymbolMap::MoveSymbol(const void* old_addr, const void* new_addr) {
  base::AutoLock hold(lock_);

  SymbolAddressSpace::RangeMapIter found = addr_space_.FindFirstIntersection(
      Range(reinterpret_cast<const uint8_t*>(old_addr), 1));

  // If we don't have a record of the original symbol, then we can't move it.
  // This may occur if a symbol provider starts pushing events only after its
  // address space has been stocked.
  if (found == addr_space_.end() || found->first.start() != old_addr)
    return;

  scoped_refptr<Symbol> symbol = found->second;

  // Note the fact that it's been moved.
  symbol->Move(new_addr);

  size_t length = found->first.size();
  addr_space_.Remove(found);

  RetireRangeUnlocked(
      Range(reinterpret_cast<const uint8_t*>(new_addr), length));

  bool inserted = addr_space_.Insert(
      Range(reinterpret_cast<const uint8_t*>(new_addr), length), symbol);
  DCHECK(inserted);
}

scoped_refptr<SymbolMap::Symbol> SymbolMap::FindSymbol(const void* addr) {
  base::AutoLock hold(lock_);

  SymbolAddressSpace::RangeMapIter found = addr_space_.FindFirstIntersection(
      Range(reinterpret_cast<const uint8_t*>(addr), 1));

  if (found == addr_space_.end())
    return NULL;

  return found->second;
}

void SymbolMap::RetireRangeUnlocked(const Range& range) {
  lock_.AssertAcquired();

  SymbolAddressSpace::RangeMapIterPair found =
      addr_space_.FindIntersecting(range);
  SymbolAddressSpace::iterator it = found.first;
  for (; it != found.second; ++it)
    found.first->second->Invalidate();

  addr_space_.Remove(found);
}

SymbolMap::Symbol::Symbol(const base::StringPiece& name, const void* address)
    : name_(name.begin(), name.end()),
      move_count_(0),
      id_(0),
      address_(address) {
}

bool SymbolMap::Symbol::EnsureHasId() {
  DCHECK(!invalid());
  if (base::subtle::Acquire_Load(&id_) != 0)
    return false;

  // Allocate a new symbol ID. Note that we may be racing against other
  // threads to assign this ID to the symbol, hence the compare-and-swap
  // below. In the case of a race, this ID may not get allocated to any
  // symbol.
  base::subtle::Atomic32 next_id = 0;
  do {
    next_id = base::subtle::NoBarrier_AtomicIncrement(&next_symbol_id_, 1);
  } while (next_id == 0);

  return base::subtle::NoBarrier_CompareAndSwap(&id_, 0, next_id) == 0;
}

void SymbolMap::Symbol::Invalidate() {
  DCHECK(!invalid());
  Move(NULL);
}

void SymbolMap::Symbol::Move(const void* new_address) {
  DCHECK(!invalid());
  // TODO(siggi): The intent here is to make sure other cores see the new
  //     value without delay. The barrier may not be what's needed to do that?
  address_ = new_address;
  base::subtle::Barrier_AtomicIncrement(&move_count_, 1);
}

}  // namespace profiler
}  // namespace agent
