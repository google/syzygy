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

#ifndef SYZYGY_AGENT_PROFILER_RETURN_THUNK_FACTORY_H_
#define SYZYGY_AGENT_PROFILER_RETURN_THUNK_FACTORY_H_

#include "syzygy/common/assertions.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace agent {
namespace profiler {

// A factory for return thunks as used by the profiler.  These are
// packed as tight as possible into whole pages of memory.  All pages
// are freed on destruction, but currently-unused pages are not freed
// in between times, on the assumption that the call stack will grow
// as deep again as it has before.
//
// This class is currently somewhat specific to profiling, as it
// calls rdtsc in the return hook and stores data needed for profiling,
// but it could be generalized if needed.
class ReturnThunkFactoryBase {
 public:
  struct Thunk;
  struct ThunkData;

  // Provides a pointer to the thunk data associated with a thunk that,
  // when called, will invoke OnFunctionExit and then return
  // to |real_ret|.
  //
  // Ownership of the data and thunk remains with the factory, which
  // reuses it only after it, or the return thunk of a function below
  // it on the stack, has been returned to.
  ThunkData* MakeThunk(RetAddr real_ret);

  // If @p ret is a thunk belonging to this factory, return that thunk,
  // or NULL otherwise.
  Thunk* CastToThunk(RetAddr ret);

  // Returns the thunk data corresponding to a thunk.
  static ThunkData* DataFromThunk(Thunk* thunk);

  // The thunk itself is opaque, but must be declared here
  // for the size calculations below.
  struct Thunk {
    // This must match the size of the code generated for the thunk.
    // Currently the code is:
    //   push <address of thunk>
    //   call thunk_main_asm
    // each of which consumes 5 bytes on x86.
    uint8_t instr[10];
  };
  COMPILE_ASSERT_IS_POD(Thunk);

  // The data associated with each thunk.
  struct ThunkData {
    // A pointer to the thunk that owns us.
    Thunk* thunk;

    // A back-pointer to the return thunk factory.
    ReturnThunkFactoryBase* self;

    // The caller and the function invoked.
    RetAddr caller;
    FuncAddr function;

    // The time of entry.
    uint64_t cycles_entry;
  };
  COMPILE_ASSERT_IS_POD(ThunkData);

 protected:
  // Thunk function type.
  typedef void (*ThunkMainFunc)();

  explicit ReturnThunkFactoryBase(ThunkMainFunc main_func);
  ~ReturnThunkFactoryBase();

  // Must be called after construction of this class to
  // initialize it for use.
  // @note Calling from a subclass constructor is fine.
  void Initialize();
  // Must be called before destruction of this class to
  // free all resources.
  // @note Calling from a subclass destructor is fine.
  void Uninitialize();

  // @name To be implemented by subclasses.
  // @{
  // Invoked after the factory has allocated a new page of thunks.
  // @param page the page of thunks, @p page is 4K and aligned on a
  //    4K boundary.
  virtual void OnPageAdded(const void* page) = 0;

  // Invoked before the factory deallocates a page of thunks.
  // @param page the page of thunks, @p page is 4K in size and aligned on a
  //    4K boundary.
  virtual void OnPageRemoved(const void* page) = 0;
  // @}

  struct Page {
    Page* previous_page;
    Page* next_page;
    ReturnThunkFactoryBase* factory;
    Thunk thunks[1];  // In fact, as many as fit.
  };

  static const size_t kPageSize = 0x00001000;  // 4096
  static const size_t kPageMask = 0xFFFFF000;
  static const size_t kNumThunksPerPage =
      (kPageSize - offsetof(Page, thunks)) / sizeof(Thunk);

  void AddPage();
  static Page* PageFromThunk(Thunk* thunk);
  static Thunk* LastThunk(Page* page);

  // The thunk main function we delegate to.
  ThunkMainFunc main_func_;

  // At all times, this points to the memory area we can use the next time
  // we need a thunk.
  //
  // Thunks form a stack since they correspond to stack invocations.  When
  // a thunk is invoked on, it means a stack frame is being returned from,
  // so we know that all thunks above it are now free.  This is true even
  // in the context of an exception handler, since the stack has been unwound.
  //
  // We can get the Page* for this Thunk by finding the page boundary,
  // and pages are linked together, so this is all we need to store.
  Thunk* first_free_thunk_;

  DISALLOW_COPY_AND_ASSIGN(ReturnThunkFactoryBase);
};

// The ImplClass must derive from the return factory base, and implement
// a member function with the following signature:
// void OnFunctionExit(const ThunkData* data, uint64_t cycles);
template <typename ImplClass> class ReturnThunkFactoryImpl
    : public ReturnThunkFactoryBase {
 public:
  ReturnThunkFactoryImpl()
      : ReturnThunkFactoryBase(thunk_main_asm) {
  }

 protected:
  // Static assembly function called by all thunks.  It ends up calling to
  // ReturnThunkFactoryImpl::ThunkMain, which in turn calls
  // ImpClass::OnFunctionExit.
  static void thunk_main_asm();

  static RetAddr WINAPI ThunkMain(ThunkData* thunk, uint64_t cycles);
};

template <class ImplClass> void __declspec(naked)
ReturnThunkFactoryImpl<ImplClass>::thunk_main_asm() {
  __asm {
    // Stash volatile registers.
    push eax
    push edx

    // Get the current cycle time ASAP.
    rdtsc

    push ecx

    // Save eax, we need the register to grab the flags.
    mov ecx, eax

    // Save the low byte of the flags into AH.
    lahf
    // Save the overflow flag into AL.
    seto al

    // Stash the flags to stack.
    push eax

    // Push the cycle time arg for the ThunkMain function.
    push edx
    push ecx

    // Get the thunk address and push it to the top of the stack.
    push DWORD PTR[esp + 0x18]

    call ThunkMain

    // Save eax, we need it for later.
    mov ecx, eax
    pop eax

    // AL is set to 1 if the overflow flag was set before the call to
    // our hook, 0 otherwise. We add 0x7f to it so it'll restore the
    // flag.
    add al, 0x7f
    // Restore the low byte of the flags.
    sahf

    // Restore eax.
    mov eax, ecx

    // Restore volatile registers, except eax.
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

template <class ImplClass>
RetAddr WINAPI
ReturnThunkFactoryImpl<ImplClass>::ThunkMain(ThunkData* data, uint64_t cycles) {
  ImplClass* factory = static_cast<ImplClass*>(data->self);
  factory->first_free_thunk_ = data->thunk;

  factory->OnFunctionExit(data, cycles);

  return data->caller;
}

}  // namespace profiler
}  // namespace agent

#endif  // SYZYGY_AGENT_PROFILER_RETURN_THUNK_FACTORY_H_
