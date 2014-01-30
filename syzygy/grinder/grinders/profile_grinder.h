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
#ifndef SYZYGY_GRINDER_GRINDERS_PROFILE_GRINDER_H_
#define SYZYGY_GRINDER_GRINDERS_PROFILE_GRINDER_H_

#include <dia2.h>
#include <iostream>
#include <map>

#include "base/files/file_path.h"
#include "base/win/scoped_comptr.h"
#include "syzygy/grinder/grinder.h"

namespace grinder {
namespace grinders {

typedef uint32 RVA;

// A worker class to sink profile trace events and output the aggregate data in
// KCacheGrind-compatible format.
//
// The profiler instrumentation captures the wall-clock time from entry to exit
// for each pair of caller/function for each invocation. This is termed
// "inclusive" time, as it includes the time spent in other functions called.
//
// The KCacheGrind file format also requires listing "exclusive" time for each
// function, where exclusive time is the amount of time spent executing the
// function itself, e.g. exclusive of the time spent calling other functions.
//
// The profile data is captured in a trace log. The trace log is a run of
// records where each record in the log is associated with a particular thread
// (and process), and contains a set of invocation records.
// Each invocation record contains inclusive wall-clock time (and potentially
// other inclusive metrics) for one or more invocations from a particular
// caller address, to a particular function.
// Note that the same caller/function pair may occur multiple times in a trace
// log, even for the same thread, as the profile instrumentation spills a trace
// record to the log when the number of caller/function pairs it's seen exceeds
// the size of the thread-local buffer used to aggregate the data.
//
// This class aggregates the data from a trace log, and builds a graph of
// function nodes and call edges. For each call edge, it aggregates the data
// from one or more log records, by summing up the call counts and inclusive
// metrics. For each function node, it also computes the exclusive cost, by
// summing up the cost of the incoming edges, and subtracting the cost of the
// outgoing edges.
//
// For information on the KCacheGrind file format, see:
// http://kcachegrind.sourceforge.net/cgi-bin/show.cgi/KcacheGrindCalltreeFormat
class ProfileGrinder : public GrinderInterface {
 public:
  ProfileGrinder();
  ~ProfileGrinder();

  // @name Accessors and mutators.
  // @{
  // If thread_parts is true, the grinder will aggregate and output
  // separate parts for each thread seen in the trace file(s).
  bool thread_parts() const { return thread_parts_; }
  void set_thread_parts(bool thread_parts) { thread_parts_ = thread_parts; }
  // @}

  // @name GrinderInterface implementation.
  // @{
  virtual bool ParseCommandLine(const CommandLine* command_line) OVERRIDE;
  virtual void SetParser(Parser* parser) OVERRIDE;
  virtual bool Grind() OVERRIDE;
  virtual bool OutputData(FILE* file) OVERRIDE;
  // @}

  // @name ParseEventHandler overrides.
  // @{
  virtual void OnInvocationBatch(
      base::Time time,
      DWORD process_id,
      DWORD thread_id,
      size_t num_invocations,
      const TraceBatchInvocationInfo* data) OVERRIDE;
  virtual void OnThreadName(base::Time time,
                            DWORD process_id,
                            DWORD thread_id,
                            const base::StringPiece& thread_name) OVERRIDE;
  virtual void OnDynamicSymbol(DWORD process_id,
                               uint32 symbol_id,
                               const base::StringPiece& symbol_name) OVERRIDE;
  // @}

 protected:
  Parser* parser_;

  typedef pe::ModuleInformation ModuleInformation;

  // Forward declarations.
  struct PartData;
  class CodeLocation;

  // Represents the caller of a caller/callee pair.
  struct CallerLocation;
  // Represents the function of a caller/callee pair.
  struct FunctionLocation;

  struct Metrics;
  struct InvocationNode;
  struct InvocationEdge;

  // The key to the dynamic symbol map i
  typedef std::pair<uint32, uint32> DynamicSymbolKey;
  typedef std::map<DynamicSymbolKey, std::string> DynamicSymbolMap;
  typedef std::set<ModuleInformation,
      bool (*)(const ModuleInformation& a, const ModuleInformation& b)>
          ModuleInformationSet;
  typedef std::map<FunctionLocation, InvocationNode> InvocationNodeMap;
  typedef std::pair<FunctionLocation, CallerLocation> InvocationEdgeKey;
  typedef std::map<InvocationEdgeKey, InvocationEdge> InvocationEdgeMap;

  typedef base::win::ScopedComPtr<IDiaSession> SessionPtr;
  typedef std::map<const ModuleInformation*, SessionPtr> ModuleSessionMap;

  bool GetSessionForModule(const ModuleInformation* module,
                           IDiaSession** session_out);

  // Finds or creates the part data for the given @p thread_id.
  PartData* FindOrCreatePart(DWORD process_id, DWORD thread_id);

  // Retrieves the function containing @p address.
  // @param symbol on success returns the function's private symbol, or
  //     public symbol if no private symbol is available.
  // @returns true on success.
  bool GetFunctionSymbolByRVA(IDiaSession* session,
                              RVA address,
                              IDiaSymbol** symbol);

  // Resolves the function and line number a particular caller belongs to.
  // @param caller the location of the caller.
  // @param function on success returns the caller's function location.
  // @param line on success returns the caller's line number in @p function.
  bool GetFunctionForCaller(const CallerLocation& caller,
                            FunctionLocation* function,
                            size_t* line);

  bool GetInfoForFunction(const FunctionLocation& function,
                          std::wstring* function_name,
                          std::wstring* file_name,
                          size_t* line);

  // Converts an absolute address to an RVA.
  void ConvertToModuleRVA(uint32 process_id,
                          trace::parser::AbsoluteAddress64 addr,
                          CodeLocation* rva);

  // Aggregates a single invocation info and/or creates a new node and edge.
  void AggregateEntryToPart(const FunctionLocation& function,
                            const CallerLocation& caller,
                            const InvocationInfo& info,
                            PartData* part);

  // This functions adds all caller edges to each function node's linked list of
  // callers. In so doing, it also computes each function node's inclusive cost.
  // @returns true on success, false on failure.
  bool ResolveCallers();

  // Resolves callers for @p part.
  bool ResolveCallersForPart(PartData* part);

  // Outputs data for @p part to @p file.
  bool OutputDataForPart(const PartData& part, FILE* file);

  // Keeps track of the dynamic symbols seen.
  DynamicSymbolMap dynamic_symbols_;

  // Stores the modules we encounter.
  ModuleInformationSet modules_;

  // Stores the DIA session objects we have going for each module.
  ModuleSessionMap module_sessions_;

  // The parts we store. If thread_parts_ is false, we store only a single
  // part with id 0. The parts are keyed on process id/thread id.
  typedef std::pair<uint32, uint32> PartKey;
  typedef std::map<PartKey, PartData> PartDataMap;
  PartDataMap parts_;

  // If true, data is aggregated and output per-thread.
  bool thread_parts_;
};

// The data we store for each part.
struct ProfileGrinder::PartData {
  PartData();

  // The thread name for this part.
  std::string thread_name_;

  // The process ID for this part.
  uint32 process_id_;

  // The thread ID for this part.
  uint32 thread_id_;

  // Stores the invocation nodes, aka the functions.
  InvocationNodeMap nodes_;

  // Stores the invocation edges.
  InvocationEdgeMap edges_;
};

// A code location is one of two things:
//
// 1. An RVA in a module, e.g. a module + offset.
// 2. A ProcessId/SymbolId pair with an optional offset.
//
// The first represents native code, where module/RVA makes a canonical "name"
// for a code location (whether function or call site) across multiple
// processes. Note that the module should be a canonical pointer to the module
// information to make this comparable against other RVAs in the same module.
//
// The second represents a dynamic symbol, which is always scoped by process
// here represented by process id.
class ProfileGrinder::CodeLocation {
 public:
  // Initializes an empty code location.
  CodeLocation();

  // Set to a symbol location with @p process_id, @p symbol_id and
  // @p symbol_offset.
  void Set(uint32 process_id, uint32 symbol_id, size_t symbol_offset);
  // Set to a module/rva location with @p module and @p rva.
  void Set(const pe::ModuleInformation* module, RVA rva);

  // Returns true iff the code location is valid.
  bool IsValid() { return is_symbol_ || (rva_ != 0 && module_ != NULL); }

  // Returns a human-readable string representing this instance.
  std::string ToString() const;

  // @name Accessors
  // @{
  bool is_symbol() const { return is_symbol_; }

  // @name Only valid when is_symbol() == true.
  uint32 process_id() const { return process_id_; }
  uint32 symbol_id() const { return symbol_id_; }
  size_t symbol_offset() const { return symbol_offset_; }

  // @name Only valid when is_symbol() == false.
  const pe::ModuleInformation* module() const { return module_; }
  RVA rva() const { return rva_; }
  // @}

  bool operator<(const CodeLocation& o) const;
  void operator=(const CodeLocation& o);

  bool operator>(const CodeLocation& o) const {
    return o < *this;
  }
  bool operator==(const CodeLocation& o) const {
    return !(o < *this || *this < o);
  }
  bool operator!=(const CodeLocation& o) const {
    return !(*this == o);
  }

 private:
  union {
    uint32 process_id_;
    const pe::ModuleInformation* module_;
  };
  union {
    RVA rva_;
    uint32 symbol_id_;
  };
  size_t symbol_offset_;
  bool is_symbol_;
};

// Reprents the address of a function.
struct ProfileGrinder::FunctionLocation : public ProfileGrinder::CodeLocation {
};

// Reprents the address of a caller.
struct ProfileGrinder::CallerLocation : public ProfileGrinder::CodeLocation {
};

// The metrics we capture per function and per caller.
struct ProfileGrinder::Metrics {
  Metrics() : num_calls(0), cycles_min(0), cycles_max(0), cycles_sum(0) {
  }

  uint64 num_calls;
  uint64 cycles_min;
  uint64 cycles_max;
  uint64 cycles_sum;
};

// An invocation node represents a function.
struct ProfileGrinder::InvocationNode {
  InvocationNode() : first_call(NULL) {
  }

  // Location of the function this instance represents.
  FunctionLocation function;

  // The metrics we've aggregated for this function.
  Metrics metrics;

  // Linked list of all the edges where the caller resolves to us.
  InvocationEdge* first_call;
};

// An invocation edge represents a caller->function pair.
struct ProfileGrinder::InvocationEdge {
  InvocationEdge() : caller_function(NULL), line(0), next_call(NULL) {
  }

  // The function/caller pair we denote.
  FunctionLocation function;
  CallerLocation caller;

  // Line number of the caller.
  size_t line;
  Metrics metrics;

  // The calling function - resolved from caller.
  InvocationNode* caller_function;
  // Chains to the next edge resolving to the
  // same calling function.
  InvocationEdge* next_call;
};

}  // namespace grinders
}  // namespace grinder

#endif  // SYZYGY_GRINDER_GRINDERS_PROFILE_GRINDER_H_
