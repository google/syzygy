// Copyright 2012 Google Inc.
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
#include "syzygy/agent/profiler/scoped_last_error_keeper.h"
#include "syzygy/core/assembler.h"

namespace {

// Static assembly function called by all thunks.  It ends up calling to
// ReturnThunkFactory::ThunkMain.
extern "C" void __declspec(naked) thunk_main_asm() {
  __asm {
    // Stash volatile registers.
    push eax
    push edx

    // Get the current cycle time ASAP.
    rdtsc

    push ecx
    pushfd

    // Push the cycle time arg for the ThunkMain function.
    push edx
    push eax

    // Get the thunk address and push it to the top of the stack.
    mov eax, DWORD PTR[esp + 0x18]
    push eax

    call agent::profiler::ReturnThunkFactory::ThunkMain

    // Restore volatile registers, except eax.
    popfd
    pop ecx
    pop edx

    // At this point we have:
    //   EAX: real ret-address
    //   stack:
    //     pushed EAX
    //     ret-address to thunk
    push eax
    mov eax, DWORD PTR[esp+4]

    // Return and discard the stored eax and discarded thunk address.
    ret 8
  }
}

class Serializer : public core::AssemblerImpl::InstructionSerializer {
 public:
  virtual void AppendInstruction(uint32 location,
                                 const uint8* bytes,
                                 size_t num_bytes,
                                 const size_t *ref_locations,
                                 const void* const* refs,
                                 size_t num_refs) {
    memcpy(static_cast<uint8*>(0) + location, bytes, num_bytes);
  }
};

}  // namespace

namespace agent {
namespace profiler {

ReturnThunkFactory::ReturnThunkFactory(Delegate* delegate)
    : delegate_(delegate),
      first_free_thunk_(NULL) {
  DCHECK(delegate_ != NULL);
  AddPage();
}

ReturnThunkFactory::~ReturnThunkFactory() {
  // Walk to the head of the page list, then release to the tail.
  Page* current_page = PageFromThunk(first_free_thunk_);

  while (current_page->previous_page)
    current_page = current_page->previous_page;

  while (current_page) {
    Page* page_to_free = current_page;
    current_page = current_page->next_page;

    // Notify the delegate of the release. We do this before freeing the memory
    // to make sure we don't open a race where a new thread could sneak a stack
    // into the page allocation.
    delegate_->OnPageRemoved(page_to_free);

    ThunkData* data = DataFromThunk(&page_to_free->thunks[0]);
    delete [] data;
    ::VirtualFree(page_to_free, 0, MEM_RELEASE);
  }
}

ReturnThunkFactory::ThunkData* ReturnThunkFactory::MakeThunk(RetAddr real_ret) {
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

ReturnThunkFactory::Thunk* ReturnThunkFactory::CastToThunk(RetAddr ret) {
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
ReturnThunkFactory::ThunkData* ReturnThunkFactory::DataFromThunk(Thunk* thunk) {
  return *reinterpret_cast<ThunkData**>(&thunk->instr[1]);
}

void ReturnThunkFactory::AddPage() {
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

  typedef core::ImmediateImpl Immediate;
  typedef core::AssemblerImpl Assembler;
  using core::kSize32Bit;

  // Initialize the thunks.
  uint32 start_addr = reinterpret_cast<uint32>(&new_page->thunks[0]);
  Serializer serializer;
  Assembler assm(start_addr, &serializer);
  for (size_t i = 0; i < kNumThunksPerPage; ++i) {
    DCHECK_EQ(0U, (assm.location() - start_addr) % sizeof(Thunk));
    // Check that there's sufficient room for one more thunk.
    DCHECK_GE((kNumThunksPerPage - 1) * sizeof(ThunkData),
              assm.location() - start_addr);
    // Set data up to point to thunk.
    data[i].thunk = &new_page->thunks[i];

    // Note that the size of the thunk must match the assembly code below.
    COMPILE_ASSERT(sizeof(ReturnThunkFactory::Thunk) == 10,
                   wonky_return_thunk_size);

    // Initialize the thunk itself.
    assm.push(Immediate(reinterpret_cast<uint32>(&data[i]), kSize32Bit));
    assm.jmp(Immediate(reinterpret_cast<uint32>(thunk_main_asm), kSize32Bit));
  }

  first_free_thunk_ = &new_page->thunks[0];

  // Notify the delegate that the page has been allocated.
  delegate_->OnPageAdded(new_page);
}

// static
ReturnThunkFactory::Page* ReturnThunkFactory::PageFromThunk(Thunk* thunk) {
  return reinterpret_cast<Page*>(reinterpret_cast<DWORD>(thunk) & kPageMask);
}

// static
ReturnThunkFactory::Thunk* ReturnThunkFactory::LastThunk(Page* page) {
  return &page->thunks[kNumThunksPerPage - 1];
}

// static
RetAddr WINAPI ReturnThunkFactory::ThunkMain(ThunkData* data, uint64 cycles) {
  ScopedLastErrorKeeper keep_last_error;

  ReturnThunkFactory* factory = PageFromThunk(data->thunk)->factory;
  factory->first_free_thunk_ = data->thunk;

  factory->delegate_->OnFunctionExit(data, cycles);

  return data->caller;
}

}  // namespace profiler
}  // namespace agent
