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

#include "syzygy/agent/profiler/scoped_last_error_keeper.h"

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

    // Calculate a pointer to the start of the thunk object as
    // the return address pushed by the caller, subtracting 5 (the
    // size of the E8 call instruction) to get a pointer to the
    // start of the thunk object.
    mov eax, DWORD PTR[esp + 0x18]
    sub eax, 5
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

    // Return and discard the stored eax and discarded return address.
    ret 8
  }
}

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

    ::VirtualFree(page_to_free, 0, MEM_RELEASE);
  }
}

ReturnThunkFactory::Thunk* ReturnThunkFactory::MakeThunk(RetAddr real_ret) {
  Thunk* thunk = first_free_thunk_;
  thunk->caller = real_ret;

  Page* current_page = PageFromThunk(first_free_thunk_);
  if (first_free_thunk_ != LastThunk(current_page)) {
    first_free_thunk_++;
  } else if (current_page->next_page) {
    first_free_thunk_ = &current_page->next_page->thunks[0];
  } else {
    AddPage();
  }

  return thunk;
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

void ReturnThunkFactory::AddPage() {
  Page* previous_page = PageFromThunk(first_free_thunk_);
  DCHECK(previous_page == NULL || previous_page->next_page == NULL);

  // TODO(joi): This may be consuming 64K of memory, in which case it would
  // be more efficient to reserve a larger block at a time if we think we
  // normally need more than 4K of thunks.
  Page* new_page = reinterpret_cast<Page*>(::VirtualAlloc(
      NULL, kPageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
  CHECK(new_page);
  new_page->previous_page = previous_page;
  new_page->next_page = NULL;
  new_page->factory = this;

  if (previous_page)
    previous_page->next_page = new_page;

  // Since thunks get reused a lot, we optimize a bit by filling in the
  // static part of all thunks when each page is allocated.
  for (size_t i= 0; i < kNumThunksPerPage; ++i) {
    Thunk* thunk = &new_page->thunks[i];
    thunk->call = 0xE8;  // call
    thunk->func_addr = reinterpret_cast<DWORD>(thunk_main_asm) -
        reinterpret_cast<DWORD>(&thunk->caller);
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
RetAddr WINAPI ReturnThunkFactory::ThunkMain(Thunk* thunk, uint64 cycles) {
  DCHECK(*reinterpret_cast<BYTE*>(thunk) == 0xE8);

  ScopedLastErrorKeeper keep_last_error;

  ReturnThunkFactory* factory = PageFromThunk(thunk)->factory;
  factory->first_free_thunk_ = thunk;

  factory->delegate_->OnFunctionExit(thunk, cycles);

  return thunk->caller;
}

}  // namespace profiler
}  // namespace agent
