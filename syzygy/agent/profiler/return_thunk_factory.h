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

#ifndef SYZYGY_AGENT_PROFILER_RETURN_THUNK_FACTORY_H_
#define SYZYGY_AGENT_PROFILER_RETURN_THUNK_FACTORY_H_

#include "base/basictypes.h"
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
class ReturnThunkFactory {
 public:
  struct Thunk;
  struct ThunkData;

  class Delegate {
   public:
    Delegate() {}
    virtual ~Delegate() {}

    // Invoked on function exit.
    // @param thunk is the invoked thunk.
    // @param cycles is the performance counter recorded.
    virtual void OnFunctionExit(const ThunkData* data, uint64 cycles) = 0;

    // Invoked after the factory has allocated a new page of thunks.
    // @param page the page of thunks, @p page is 4K and aligned on a
    //    4K boundary.
    virtual void OnPageAdded(const void* page) = 0;

    // Invoked before the factory deallocates a page of thunks.
    // @param page the page of thunks, @p page is 4K in size and aligned on a
    //    4K boundary.
    virtual void OnPageRemoved(const void* page) = 0;

   private:
    DISALLOW_COPY_AND_ASSIGN(Delegate);
  };

  explicit ReturnThunkFactory(Delegate* delegate);
  ~ReturnThunkFactory();

  // Provides a pointer to the thunk data associated with a thunk that,
  // when called, will invoke Delegate::OnFunctionExit and then return
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
    uint8 instr[10];
  };

  // The data associated with each thunk.
  struct ThunkData {
    // A pointer to the thunk that owns us.
    Thunk* thunk;

    // The caller and the function invoked.
    RetAddr caller;
    FuncAddr function;

    // The time of entry.
    uint64 cycles_entry;
  };

 protected:
  struct Page {
    Page* previous_page;
    Page* next_page;
    ReturnThunkFactory* factory;
    Thunk thunks[1];  // In fact, as many as fit.
  };

  static const size_t kPageSize = 0x00001000;  // 4096
  static const size_t kPageMask = 0xFFFFF000;
  static const size_t kNumThunksPerPage =
      (kPageSize - offsetof(Page, thunks)) / sizeof(Thunk);

  void AddPage();
  static Page* PageFromThunk(Thunk* thunk);
  static Thunk* LastThunk(Page* page);
  static RetAddr WINAPI ThunkMain(ThunkData* thunk, uint64 cycles);

  // Always valid, used to call back on function exit.
  Delegate* delegate_;

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

  DISALLOW_COPY_AND_ASSIGN(ReturnThunkFactory);
};

}  // namespace profiler
}  // namespace agent

#endif  // SYZYGY_AGENT_PROFILER_RETURN_THUNK_FACTORY_H_
