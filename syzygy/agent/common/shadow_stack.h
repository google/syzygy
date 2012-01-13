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
//
// The implementation of a class to implement a shadow stack to the machine
// stack, to allow hooking function exit, by swizzling return addresses.
//
// An exit hook can be implemented by swizzling return addresses on the machine
// stack while maintaining a per-thread shadow stack of return addresses.
// If exit logging is requested on entry to a function, the shadow stack is
// pushed with the current return address, and the return address on the machine
// stack can be overwritten with the address of the exit hook function.
// On subsequent return to exit hook function, the exit event can be recorded,
// the shadow stack popped, and the exit hook function will subsequently
// return to the address from the shadow stack.
//
// This simple implementation works fine in the absence of nonlocal gotos,
// exceptions and the like. However, on such events, some portion of the machine
// stack is discarded, which puts the shadow stack out of synchronization with
// the machine stack. This in turn will cause a subsequent return to the exit
// hook to pop the wrong entry off the shadow stack, and a return to the wrong
// address.
//
// To avoid this, we note that:
//
// * On exit, the stack pointer must be strictly greater than the entry frame
//   that the shadow stack entry was created from (as the return address as well
//   as the arguments - in the case of __stdcall - have been popped off the
//   stack in preparation for the return).
//   Also, the second non-orphaned shadow stack entry's entry frame pointer must
//   be equal or greater than the stack pointer (and its return address must be
//   pexit or pexit_dllmain).
//
// * An exception to the above is multiple entries with the same entry address,
//   which occur in the cases of tail call & recursion elimination.
//
// * On entry, any shadow stack entry whose entry frame pointer is less than
//   the current entry frame is orphaned. Note that equal entry frame pointers
//   occur in the case of tail call & recursion elimination.
//
// By discarding orphaned shadow stack entries on entry and exit, we can ensure
// that we never return to an orphaned entry. This class takes care of the
// grungy details, but must be invoked appropriately by the user.

#ifndef SYZYGY_AGENT_COMMON_SHADOW_STACK_H_
#define SYZYGY_AGENT_COMMON_SHADOW_STACK_H_

#include <vector>

#include "base/basictypes.h"
#include "base/logging.h"
#include "syzygy/trace/protocol/call_trace_defs.h"

namespace call_trace {

// This structure is overlaid on the entry frame by the entry hook, to allow
// to the user to access and modify the entry frame.
struct EntryFrame {
  RetAddr retaddr;
  ArgumentWord args[4];
};

// The minimal information we need to implement a shadow stack. It is expected
// that users of ShadowStackImpl will subclass this structure to extend it with
// the additional data they need per entry.
struct StackEntryBase {
  // The original return address we replaced.
  RetAddr return_address;
  // The address of the entry frame associated with this shadow entry.
  EntryFrame* entry_frame;
};

template <typename StackEntry>
class ShadowStackImpl {
 public:
  // Push a new stack entry and return it.
  // This takes care of initializing the entry_frame and return_address.
  StackEntry& Push(EntryFrame* frame);

  // Pops the top entry off the shadow stack and returns it.
  // @pre stack.size() > 0 - the stack must not be empty.
  StackEntry Pop();

  // Peeks at the top entry on the stack.
  // @pre stack.size() > 0 - the stack must not be empty.
  const StackEntry& Peek() const;

  // Corrects any entry in trace that points to one of the exit_fns to
  // the corresponding return address from the shadow stack.
  void FixBackTrace(size_t num_exit_fns, const RetAddr* exit_fns,
                    size_t depth, RetAddr* trace) const;

  // Trims orphaned shadow stack frames on entry to a function.
  // @param entry_frame the current functions entry frame.
  // @note this must be called at every function entry, prior to pushing the
  //     stack. Failure to trim orphans can lead to the shadow stack drifting
  //     out of alignment with the machine stack.
  void TrimOrphansOnEntry(const EntryFrame* entry_frame);

  // Trims orphaned shadow stack frames on exit from a function.
  // @param stack_pointer the stack pointer value immediately prior to entering
  //      the exit hook.
  // @note this must be called at every call to the exit hook, prior to popping
  //     the stack. Failure to trim orphans can lead to the shadow stack
  //     drifting out of alignment with the machine stack.
  void TrimOrphansOnExit(const void* stack_pointer);

  // Accessor for the stack size.
  size_t size() const { return stack_.size(); }

 private:
  typedef std::vector<StackEntry> EntryVector;

  std::vector<StackEntry> stack_;
};

template <typename StackEntry>
StackEntry& ShadowStackImpl<StackEntry>::Push(EntryFrame* frame) {
  // The top entry on the stack must not be above us on the stack.
  // It can however be equal in the case of tail call elimination,
  // or other cases where a stack frame is reused.
  DCHECK(stack_.empty() ||
      reinterpret_cast<const uint8*>(stack_.back().entry_frame) >=
      reinterpret_cast<const uint8*>(frame));

  stack_.push_back(StackEntry());
  StackEntry &entry = stack_.back();
  // Record the frame for use in trimming.
  entry.entry_frame = frame;
  // Record the return address to allow the exit
  // hook to return to the original caller.
  entry.return_address = frame->retaddr;
  return entry;
}

template <typename StackEntry>
StackEntry ShadowStackImpl<StackEntry>::Pop() {
  DCHECK(!stack_.empty());
  StackEntry ret = stack_.back();
  stack_.pop_back();
  return ret;
}

template <typename StackEntry>
const StackEntry& ShadowStackImpl<StackEntry>::Peek() const {
  DCHECK(!stack_.empty());
  return stack_.back();
}

template <typename StackEntry>
void ShadowStackImpl<StackEntry>::TrimOrphansOnEntry(
    const EntryFrame* entry_frame) {
  // On entry, any shadow stack entry whose entry frame pointer
  // is less than the current entry frame hass been orphaned.
  //
  while (!stack_.empty() &&
         reinterpret_cast<const uint8*>(stack_.back().entry_frame) <
         reinterpret_cast<const uint8*>(entry_frame)) {
    stack_.pop_back();
  }
}

template <typename StackEntry>
void ShadowStackImpl<StackEntry>::TrimOrphansOnExit(
    const void* stack_pointer) {
  DCHECK(!stack_.empty()) << "Shadow stack out of whack!";
  DCHECK(reinterpret_cast<const uint8*>(stack_pointer) >
         reinterpret_cast<const uint8*>(stack_.back().entry_frame))
      << "Invalid entry on shadow stack";

  // Find the first entry (if any) that has an entry pointer greater or equal
  // to the stack pointer. This entry is the second non-orphaned entry on the
  // stack, or the Nth entry behind N-1 entries with identical entry_frames in
  // case of tail call & recursion.
  EntryVector::reverse_iterator it(stack_.rbegin());
  EntryVector::reverse_iterator end(stack_.rend());
  for (; it != end; ++it) {
    if (reinterpret_cast<const uint8*>(it->entry_frame) >=
        reinterpret_cast<const uint8*>(stack_pointer)) {
      break;
    }
  }

  // Now "it" points to the entry preceding the entry to pop, or the first of
  // many entries with identical entry_frame pointers.
  EntryVector::reverse_iterator begin(stack_.rbegin());
  --it;
  EntryFrame* entry_frame = it->entry_frame;
  for (; it != begin; --it) {
    if (it->entry_frame != entry_frame) {
      // Slice the extra entries off the shadow stack_.
      stack_.resize(end - it - 1);
      break;
    }
  }
}

template <typename StackEntry>
void ShadowStackImpl<StackEntry>::FixBackTrace(
    size_t num_exit_fns, const RetAddr* exit_fns,
    size_t depth, RetAddr* trace) const {
  DCHECK(num_exit_fns > 0);
  DCHECK(exit_fns != NULL);
  DCHECK(trace != NULL);

  // TODO(siggi): This needs work to do the right thing by
  //     the tail recursion case.
  EntryVector::const_reverse_iterator it(stack_.rbegin());
  EntryVector::const_reverse_iterator end(stack_.rend());
  for (size_t i = 0; i < depth && it != end; ++i) {
    for (size_t j = 0; j < num_exit_fns; ++j) {
      if (exit_fns[j] == trace[i]) {
        trace[i] = it->return_address;
        ++it;
        break;
      }
    }
  }
}

}  // namespace call_trace

#endif  // SYZYGY_AGENT_COMMON_SHADOW_STACK_H_
