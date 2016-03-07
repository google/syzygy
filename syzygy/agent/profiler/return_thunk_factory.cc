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

#include "syzygy/agent/profiler/return_thunk_factory.h"

#include "base/logging.h"
#include "syzygy/assm/assembler.h"
#include "syzygy/assm/buffer_serializer.h"

namespace agent {
namespace profiler {

ReturnThunkFactoryBase::ReturnThunkFactoryBase(ThunkMainFunc main_func)
    : main_func_(main_func),
      first_free_thunk_(NULL) {
  DCHECK(main_func_ != NULL);
}

ReturnThunkFactoryBase::~ReturnThunkFactoryBase() {
  DCHECK(first_free_thunk_ == NULL)
      << "Destroying a factory that was not uninitialized.";
}

void ReturnThunkFactoryBase::Initialize() {
  DCHECK(first_free_thunk_ == NULL);
  AddPage();
}

void ReturnThunkFactoryBase::Uninitialize() {
  // Walk to the head of the page list, then release to the tail.
  Page* current_page = PageFromThunk(first_free_thunk_);

  while (current_page->previous_page)
    current_page = current_page->previous_page;

  while (current_page) {
    Page* page_to_free = current_page;
    current_page = current_page->next_page;

    // Notify our subclasses of the release.
    // We do this before freeing the memory to make sure we don't
    // open a race where a new thread could sneak a stack into
    // the page allocation.
    OnPageRemoved(page_to_free);

    ThunkData* data = DataFromThunk(&page_to_free->thunks[0]);
    delete [] data;
    ::VirtualFree(page_to_free, 0, MEM_RELEASE);
  }

  first_free_thunk_ = NULL;
}

ReturnThunkFactoryBase::ThunkData* ReturnThunkFactoryBase::MakeThunk(
    RetAddr real_ret) {
  Thunk* thunk = first_free_thunk_;
  ThunkData* data = DataFromThunk(thunk);
  data->caller = real_ret;

  Page* current_page = PageFromThunk(first_free_thunk_);
  if (first_free_thunk_ != LastThunk(current_page)) {
    first_free_thunk_++;
  } else if (current_page->next_page) {
    first_free_thunk_ = &current_page->next_page->thunks[0];
  } else {
    AddPage();
  }

  return data;
}

ReturnThunkFactoryBase::Thunk* ReturnThunkFactoryBase::CastToThunk(
    RetAddr ret) {
  Thunk* thunk = const_cast<Thunk*>(reinterpret_cast<const Thunk*>(ret));
  Page* thunk_page = PageFromThunk(thunk);
  Page* page = PageFromThunk(first_free_thunk_);

  for (; page != NULL; page = page->previous_page) {
    if (page == thunk_page)
      return thunk;
  }

  return NULL;
}

// static.
ReturnThunkFactoryBase::ThunkData* ReturnThunkFactoryBase::DataFromThunk(
    Thunk* thunk) {
  return *reinterpret_cast<ThunkData**>(&thunk->instr[1]);
}

void ReturnThunkFactoryBase::AddPage() {
  Page* previous_page = PageFromThunk(first_free_thunk_);
  DCHECK(previous_page == NULL || previous_page->next_page == NULL);

  // TODO(joi): This may be consuming 64K of memory, in which case it would
  // be more efficient to reserve a larger block at a time if we think we
  // normally need more than 4K of thunks.
  Page* new_page = reinterpret_cast<Page*>(::VirtualAlloc(
      NULL, kPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
  CHECK(new_page != NULL);

  // Allocate the data associated with each thunk.
  ThunkData* data = new ThunkData[kNumThunksPerPage];
  CHECK(data != NULL);

  // Insert the page into our page list.
  new_page->previous_page = previous_page;
  new_page->next_page = NULL;
  new_page->factory = this;

  if (previous_page)
    previous_page->next_page = new_page;

  typedef assm::AssemblerImpl::Immediate Immediate;
  typedef assm::AssemblerImpl Assembler;
  using assm::kSize32Bit;

  // Initialize the thunks.
  uint32_t start_addr = reinterpret_cast<uint32_t>(&new_page->thunks[0]);
  assm::BufferSerializer serializer(
      reinterpret_cast<uint8_t*>(new_page->thunks),
      kNumThunksPerPage * sizeof(Thunk));
  Assembler assm(start_addr, &serializer);
  for (size_t i = 0; i < kNumThunksPerPage; ++i) {
    DCHECK_EQ(0U, (assm.location() - start_addr) % sizeof(Thunk));
    // Check that there's sufficient room for one more thunk.
    DCHECK_GE((kNumThunksPerPage - 1) * sizeof(Thunk),
              assm.location() - start_addr);
    // Set data up to point to thunk.
    data[i].thunk = &new_page->thunks[i];
    data[i].self = this;

    // Note that the size of the thunk must match the assembly code below.
    static_assert(sizeof(ReturnThunkFactoryBase::Thunk) == 10,
                  "Wonky return thunk size.");

    // Initialize the thunk itself.
    assm.push(Immediate(reinterpret_cast<uint32_t>(&data[i]), kSize32Bit));
    assm.jmp(Immediate(reinterpret_cast<uint32_t>(main_func_), kSize32Bit));
  }

  first_free_thunk_ = &new_page->thunks[0];

  // Notify subclass that the page has been allocated.
  OnPageAdded(new_page);
}

// static
ReturnThunkFactoryBase::Page* ReturnThunkFactoryBase::PageFromThunk(
    Thunk* thunk) {
  return reinterpret_cast<Page*>(reinterpret_cast<DWORD>(thunk) & kPageMask);
}

// static
ReturnThunkFactoryBase::Thunk* ReturnThunkFactoryBase::LastThunk(Page* page) {
  return &page->thunks[kNumThunksPerPage - 1];
}

}  // namespace profiler
}  // namespace agent
