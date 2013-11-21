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
//
// This file declares the HeatMapSimulation class.


#ifndef SYZYGY_SIMULATE_HEAT_MAP_SIMULATION_H_
#define SYZYGY_SIMULATE_HEAT_MAP_SIMULATION_H_

#include <map>

#include "base/string_piece.h"
#include "syzygy/core/json_file_writer.h"
#include "syzygy/simulate/simulation_event_handler.h"
#include "syzygy/trace/parse/parser.h"

namespace simulate {

// An implementation of SimulationEventHandler.
// HeatMapSimulation parses trace events, gathers the code blocks from them,
// and organizes those by the number of times each memory slice of a given
// size, in bytes, was called during a time slice of a given size,
// in microseconds.
//
// HeatMapSimulation simulation;
//
// simulation.set_time_slice_usecs(5);
// simulation.set_memory_slice_bytes(0x4000);
// simulation.OnProcessStarted(time, 0);
// simulation.OnFunctionEntry(times[0], 0, 5);
// simulation.OnFunctionEntry(times[1], 3, 200);
// simulation.SerializeToJSON(file, pretty_print);
//
// If the time slice size or the memory slice size are not set, the default
// values of 1 and 0x8000, respectively, are used.
class HeatMapSimulation : public SimulationEventHandler {
 public:
  class TimeSlice;

  typedef block_graph::BlockGraph::Block Block;
  typedef time_t TimeSliceId;
  typedef std::map<TimeSliceId, TimeSlice> TimeMemoryMap;
  typedef uint32 MemorySliceId;

  // The default time and memory slice sizes.
  static const uint32 kDefaultTimeSliceSize = 1;
  static const uint32 kDefaultMemorySliceSize = 0x8000;

  // Construct a new HeatMapSimulation instance.
  HeatMapSimulation();

  // @name Accessors.
  // @{
  const TimeMemoryMap& time_memory_map() const { return time_memory_map_; }
  uint32 time_slice_usecs() const { return time_slice_usecs_; }
  uint32 memory_slice_bytes() const { return memory_slice_bytes_; }
  TimeSliceId max_time_slice_usecs() const { return max_time_slice_usecs_; }
  MemorySliceId max_memory_slice_bytes() const {
    return max_memory_slice_bytes_;
  }
  // @}

  // @name Mutators.
  // @{
  // Set the size of time slices used in the heat map.
  // @param time_slice_usecs The size used, in microseconds.
  void set_time_slice_usecs(uint32 time_slice_usecs) {
    DCHECK_LT(0u, time_slice_usecs);
    time_slice_usecs_ = time_slice_usecs;
  }
  // Set the size of the memory slices used in the heat map.
  // @param memory_slice_bytes The size used, in bytes.
  void set_memory_slice_bytes(uint32 memory_slice_bytes) {
    DCHECK_LT(0u, memory_slice_bytes);
    memory_slice_bytes_ = memory_slice_bytes;
  }
  // Set whether SerializeToJSON outputs information about each individual
  // function in each time/memory block.
  // @param print_output_individual_functions true for saving the names of each
  //     function, false otherwise.
  void set_output_individual_functions(bool output_individual_functions) {
    output_individual_functions_ = output_individual_functions;
  }
  // @}

  // @name SimulationEventHandler implementation
  // @{
  // Sets the entry time of the trace file.
  // @param time The startup time of the execution.
  void OnProcessStarted(base::Time time, size_t default_page_size) OVERRIDE;

  // Adds a group of code blocks corresponding to one function
  // to time_memory_map_.
  // @param time The entry time of the function.
  // @param block_start The start start of the function.
  // @param size The size of the function.
  void OnFunctionEntry(base::Time time, const Block* block) OVERRIDE;

  // Serializes the data to JSON.
  // The serialization consists of a list containing a dictionary of each
  // timestamp, and the total number of memory slices used, during that
  // time slice, and of another list with dictionaries containing each
  // separate memory slice, the number of times it was used, and a list
  // of all the used functions and the number of times they were used in that
  // memory slice in descending order. If output_individual_functions is true,
  // then the list of function for each memory slice isn't printed. Example:
  // {
  //   "time_slice_usecs": 1,
  //   "memory_slice_bytes": 32768,
  //   "time_slice_list": [
  //     {
  //       "timestamp": 31,
  //       "total_memory_slices": 1052,
  //       "memory_slice_list": [
  //         {
  //           "memory_slice": 4,
  //           "quantity": 978,
  //           "functions": [
  //             {
  //               "name": "_flush",
  //               "quantity": 561
  //             },
  //             {
  //               "name": "flsall",
  //               "quantity": 417
  //             }
  //           ]
  //         },
  //         {
  //           "memory_slice": 13,
  //           "quantity": 74,
  //           "functions": [
  //             {
  //               "name": "_RTC_Terminate",
  //               "quantity": 38
  //             },
  //             {
  //              "name": "_CrtDefaultAllocHook",
  //              "quantity": 36
  //             }
  //           ]
  //         }
  //       ]
  //     },
  //     {
  //       "timestamp": 33,
  //       "total_memory_slices": 105,
  //       "memory_slice_list": [
  //         {
  //           "memory_slice": 0,
  //           "quantity": 105,
  //           "functions": [
  //             {
  //               "name": "rand",
  //               "quantity": 105
  //             }
  //           ]
  //         }
  //       ]
  //     }
  //   ]
  // }
  // @param output the file to be written to.
  // @param pretty_print enables or disables pretty printing.
  // @returns true on success, false on failure.
  bool SerializeToJSON(FILE* output, bool pretty_print);
  // @}

 protected:
  // The size of each time block on the heat map, in microseconds.
  uint32 time_slice_usecs_;

  // The size of each memory block on the heat map, in bytes.
  uint32 memory_slice_bytes_;

  // A map which contains the density of each pair of time and memory slices.
  // TODO(fixman): If there aren't many possible relative times,
  // this will probably be better off as a vector.
  TimeMemoryMap time_memory_map_;

  // The time when the process was started. Used to convert absolute function
  // entry times to relative times since start of process.
  base::Time process_start_time_;

  // The number of the last time and memory slice, respectively.
  TimeSliceId max_time_slice_usecs_;
  MemorySliceId max_memory_slice_bytes_;

  // If set to true, SerializeToJSON outputs information about each function
  // in each time/memory block. This gives more information and is useful
  // for analysis, but may make the output files excessively big.
  bool output_individual_functions_;
};

// Stores the respective memory slices of a particular time slice in a map.
class HeatMapSimulation::TimeSlice {
 public:
  typedef std::map<std::string, uint32> FunctionMap;

  struct MemorySlice {
    FunctionMap functions;
    uint32 total;

    MemorySlice() : total(0) {
    }
  };
  typedef std::map<MemorySliceId, MemorySlice> MemorySliceMap;

  TimeSlice() : total_(0) {
  }

  // Add a quantity of bytes to a memory slice to the counter.
  // @param slice The relative code block number.
  // @param name The name of the function which uses the memory slice.
  // @param num_bytes The value to be added, in bytes.
  void AddSlice(MemorySliceId slice,
                const base::StringPiece& name,
                uint32 num_bytes) {
    slices_[slice].functions[name.as_string()] += num_bytes;
    slices_[slice].total += num_bytes;
    total_ += num_bytes;
  }

  // @name Accessors.
  // @{
  const MemorySliceMap& slices() const { return slices_; }
  uint32 total() const { return total_; }
  // @}

  // Serialize a FunctionMap to a JSON file, sorted by bytes occupied by
  // each function.
  // @param json_file The file where the functions will be serialized.
  // @param functions The given functions.
  // @returns true on success, false on failure.
  static bool PrintJSONFunctions(core::JSONFileWriter& json_file,
                                 const FunctionMap& functions);

 protected:
  // The slices that were accumulated at this time, and how many times
  // they were called.
  MemorySliceMap slices_;

  // The total number of blocks that were called at this time.
  uint32 total_;
};

}  // namespace simulate

#endif  // SYZYGY_SIMULATE_HEAT_MAP_SIMULATION_H_
