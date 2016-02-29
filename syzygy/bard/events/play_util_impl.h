// Copyright 2016 Google Inc. All Rights Reserved.
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
// Implementation details for play_util.h

#ifndef SYZYGY_BARD_EVENTS_PLAY_UTIL_IMPL_H_
#define SYZYGY_BARD_EVENTS_PLAY_UTIL_IMPL_H_

#include <cinttypes>
#include <utility>

#include "base/logging.h"
#include "syzygy/trace/common/clock.h"

namespace bard {
namespace detail {

// This warnings relates to optimizations and manually injected assembly code.
#pragma warning(disable: 4740)

// Turn off all optimizations. These functions need to be distinct so they
// each generate a unique stack frame.
#pragma optimize("", off)

// Helper for extracting the return type of a function.
// @tparam FunctionType The type of the function to be called.
// @tparam ParamTypes The types of the function parameters.
template<typename FunctionType, typename ...ParamTypes>
struct GetReturnType {
  using type =
      decltype(std::declval<FunctionType>()(std::declval<ParamTypes>()...));
};

// A testing seam that allows having the InvokeFunctionWithStackIdHelper
// report its function extents.
enum : uint32_t { kGetFunctionExtentsDepth = 0xFFFFFFFF };
extern const void* kInvokeFunctionBegin;
extern const void* kInvokeFunctionEnd;

// Workhorse for InvokeFunctionWithStackId.
template<uint32_t kInvokeValue,
         typename FunctionType,
         typename ReturnType,
         typename ...ParamTypes>
struct InvokeFunctionWithStackIdHelper {
  template<uint32_t kChildInvokerValue>
  using Invoke = InvokeFunctionWithStackIdHelper<kChildInvokerValue,
      FunctionType, ReturnType, ParamTypes...>;

  static __declspec(noinline) ReturnType Do(uint32_t depth, uint32_t stack_id,
      FunctionType& function, ParamTypes... params) {
    function_start:

    // Special case for testing. This gets the extents of this function as
    // actually laid out in memory.
    if (depth == kGetFunctionExtentsDepth) {
      __asm {
        push eax
        mov eax, function_start
        mov kInvokeFunctionBegin, eax
        mov eax, function_end
        mov kInvokeFunctionEnd, eax
        pop eax
      }
      return function(params...);
    }

    // Outside of testing the depth should never be more than 8, as there are
    // only 8 nibbles in a 32-bit int.
    DCHECK_GE(8u, depth);

    // Handle the base case.
    if (depth == 0) {
      DCHECK_EQ(0u, stack_id);
      return function(params...);
    }

    // Get the lowest nibble, shift it out, and decrement the depth.
    uint32_t invoke_id = stack_id & 0xF;
    stack_id >>= 4;
    --depth;

    // Dispatch to the appropriate child invoker, based on the bottom nibble
    // of the stack ID.
    switch (invoke_id) {
      case 0x0: return Invoke<0x0>().Do(depth, stack_id, function, params...);
      case 0x1: return Invoke<0x1>().Do(depth, stack_id, function, params...);
      case 0x2: return Invoke<0x2>().Do(depth, stack_id, function, params...);
      case 0x3: return Invoke<0x3>().Do(depth, stack_id, function, params...);
      case 0x4: return Invoke<0x4>().Do(depth, stack_id, function, params...);
      case 0x5: return Invoke<0x5>().Do(depth, stack_id, function, params...);
      case 0x6: return Invoke<0x6>().Do(depth, stack_id, function, params...);
      case 0x7: return Invoke<0x7>().Do(depth, stack_id, function, params...);
      case 0x8: return Invoke<0x8>().Do(depth, stack_id, function, params...);
      case 0x9: return Invoke<0x9>().Do(depth, stack_id, function, params...);
      case 0xA: return Invoke<0xA>().Do(depth, stack_id, function, params...);
      case 0xB: return Invoke<0xB>().Do(depth, stack_id, function, params...);
      case 0xC: return Invoke<0xC>().Do(depth, stack_id, function, params...);
      case 0xD: return Invoke<0xD>().Do(depth, stack_id, function, params...);
      case 0xE: return Invoke<0xE>().Do(depth, stack_id, function, params...);
      case 0xF: return Invoke<0xF>().Do(depth, stack_id, function, params...);
      default: break;
    }

    function_end:
    NOTREACHED();
    return function(params...);
  }
};

// Implementation of InvokeOnBackdrop.
template<typename BackdropType, typename ReturnType, typename ...ParamTypes>
struct InvokeOnBackdropHelper {
  static ReturnType DoImpl(uint64_t* timing,
                           BackdropType* backdrop,
                           ReturnType (BackdropType::*function)(ParamTypes...),
                           ParamTypes... params) {
    uint64_t t0 = ::trace::common::GetTsc();
    ReturnType ret = (backdrop->*function)(params...);
    uint64_t t1 = ::trace::common::GetTsc();
    *timing = t1 - t0;
    return ret;
  }

  static ReturnType Do(uint32_t stack_id,
                       uint64_t* timing,
                       BackdropType* backdrop,
                       ReturnType (BackdropType::*function)(ParamTypes...),
                       ParamTypes... params) {
    return InvokeFunctionWithStackId(
        stack_id, DoImpl, timing, backdrop, function, params...);
  }
};

#pragma optimize("", on)

}  // namespace detail
}  // namespace bard

#endif  // SYZYGY_BARD_EVENTS_PLAY_UTIL_IMPL_H_
