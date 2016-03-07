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

#ifndef SYZYGY_TRACE_COMMON_CLOCK_H_
#define SYZYGY_TRACE_COMMON_CLOCK_H_

#include <intrin.h>
#include <stdint.h>
#include <windows.h>

#include "syzygy/common/assertions.h"

namespace trace {
namespace common {

// A structure representing information about a timer. This can be used
// (along with reference times) to translate between timers and clocks.
// Both values will be set to zero for a timer that is not valid on a given
// system.
// NOTE: This is meant to be POD so that it can be written directly as is to and
//     from disk.
struct TimerInfo {
  // The frequency of this timer, in counts per second.
  uint64_t frequency;
  // The resolution of this timer, in counts.
  uint64_t resolution;
};
COMPILE_ASSERT_IS_POD(TimerInfo);

// Gets timer information about the various timers. A timer whose information
// can not be found will have the frequency set to 0.
// @param timer_info Will be populated with the information about the timer.
void GetTickTimerInfo(TimerInfo* timer_info);
void GetTscTimerInfo(TimerInfo* timer_info);

// @returns the current value of the ticks timer.
uint64_t GetTicks();

// @returns the current value of the TSC register using RDTSC.
inline uint64_t GetTsc() {
  return ::__rdtsc();
}

// Given a file time, a reference time and TimerInfo, convert the given
// timer value to the corresponding file time. This can fail if the timer
// info is invalid (frequency is 0, ie: unknown).
// @param file_time_ref A reference file time.
// @param timer_info Information regarding the timer frequency.
// @param timer_ref The corresponding reference timer value.
// @param timer_value The timer value to be converted.
// @param file_time The file time to be populated.
// @returns true on success, false otherwise.
bool TimerToFileTime(const FILETIME& file_time_ref,
                     const TimerInfo& timer_info,
                     const uint64_t& timer_ref,
                     const uint64_t& timer_value,
                     FILETIME* file_time);

// Information about the system clock and various timers.
// NOTE: This is meant to be POD so that it can be written directly as is to and
//     from disk.
struct ClockInfo {
  // Reference times. Used for converting between time formats.
  FILETIME file_time;
  uint64_t ticks_reference;
  uint64_t tsc_reference;

  // Information about the timers at our disposal.
  TimerInfo ticks_info;
  TimerInfo tsc_info;
};
COMPILE_ASSERT_IS_POD(ClockInfo);

// Populates a ClockInfo struct with information about the system clock and
// timers.
// NOTE: This requires read access to the registry to get full information, and
//     is intended to be run from a process that has no restrictions. For
//     example, if this is run from a sandboxed process the TSC timer
//     information will be incomplete. A warning will be logged if this is the
//     case.
// @param clock_info The struct to be populated.
void GetClockInfo(ClockInfo* clock_info);

// Converts a timer value to a file time given the clock info. This can fail if
// the given timer has an invalid corresponding TimerInfo in @p clock_info.
// @param clock_info The system clock information.
// @param ticks The value of the tick counter.
// @param tsc The value of the TSC counter.
// @param file_time The file time to be populated.
// @returns true on success, false otherwise.
bool TicksToFileTime(const ClockInfo& clock_info,
                     uint64_t ticks,
                     FILETIME* file_time);
bool TscToFileTime(const ClockInfo& clock_info,
                   uint64_t tsc,
                   FILETIME* file_time);

}  // namespace common
}  // namespace trace

#endif  // SYZYGY_TRACE_COMMON_CLOCK_H_
