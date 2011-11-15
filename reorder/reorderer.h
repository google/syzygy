// Copyright 2011 Google Inc.
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
// This defines the pure virtual Reorderer base class. This class abstracts
// away the ETW log parsing, decomposition, Block lookup, etc, that is a routine
// part of producing a new ordering. Derived classes are to implement actual
// order generation.
#ifndef SYZYGY_REORDER_REORDERER_H_
#define SYZYGY_REORDER_REORDERER_H_

#include <windows.h>
#include <dbghelp.h>

#include <map>
#include <set>
#include <string>
#include <vector>

#include "base/win/event_trace_consumer.h"
#include "sawbuck/log_lib/kernel_log_consumer.h"
#include "syzygy/call_trace/parser.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/image_layout.h"

// Forward declaration.
namespace core {
class JSONFileWriter;
}  // namespace core

namespace reorder {

typedef uint64 AbsoluteAddress64;
typedef uint64 Size64;

using call_trace::parser::ModuleInformation;
using call_trace::parser::ParseEventHandler;
using call_trace::parser::Parser;
using core::AddressSpace;
using core::BlockGraph;
using core::RelativeAddress;
using pe::Decomposer;
using pe::ImageLayout;
using pe::PEFile;

// This class can consume a set of call-trace logs captured for a PE image
// while driving an OrderGenerator instance to produce an ordering file.
class Reorderer : public ParseEventHandler {
 public:
  struct Order;
  class OrderGenerator;
  class UniqueTime;
  typedef std::vector<FilePath> TraceFileList;
  typedef TraceFileList::iterator TraceFileIter;

  // A bit flag of directives that the derived reorderer should attempt
  // to satisfy.
  // TODO(chrisha): Basic block reordering.
  enum FlagsEnum {
    kFlagReorderCode = 1 << 0,
    kFlagReorderData = 1 << 1,
  };
  typedef uint32 Flags;

  // Construct a new reorder instance.
  Reorderer(const FilePath& module_path,
            const FilePath& instrumented_path,
            const TraceFileList& trace_files,
            Flags flags);

  virtual ~Reorderer();

  // Runs the reorderer, parsing the call-trace logs and generating an
  // ordering using the given order generation strategy.
  //
  // @note This function cannot be called concurrently across Reorderer
  //     instances because the ETW parser must be a singleton due to the
  //     way the Windows ETW API is structured. This is enforced in debug
  //     builds.
  //
  // Returns true on success, false otherwise. @p order must not be NULL.
  bool Reorder(OrderGenerator* order_generator,
               Order* order,
               PEFile* pe_file,
               ImageLayout* image);

  // Returns the reorderer directives provided at Init time.
  Flags flags() const { return flags_; }

 protected:
  typedef std::set<uint32> ProcessSet;

  // The actual implementation of Reorder.
  bool ReorderImpl(Order* order);

  // The following functions represented the workflow of ReorderImpl.

  // Loads information from the instrumented and original modules.
  bool LoadModuleInformation();
  // Initializes the parser.
  bool InitializeParser();
  // Loads OMAP information for the instrumented module.
  bool LoadInstrumentedOmap();
  // Decomposes the original image.
  bool DecomposeImage();
  // Consumes the events from the call-tracer parser.
  bool ConsumeCallTraceEvents();
  // Calculates the actual reordering.
  bool CalculateReordering(Order* order);

  // Parses the instrumented DLL headers, validating that it was produced
  // by a compatible version of the toolchain, and extracting signature
  // information and metadata. Returns true on success, false otherwise.
  bool ValidateInstrumentedModuleAndParseSignature(
      PEFile::Signature* orig_signature);

  // Returns true if the given ModuleInformation matches the instrumented
  // module signature, false otherwise.
  bool MatchesInstrumentedModuleSignature(
      const ModuleInformation& module_info) const;

  // @name ParseEventHandler Implementation
  // @{
  virtual void OnProcessStarted(base::Time time, DWORD process_id) OVERRIDE;
  virtual void OnProcessEnded(base::Time time, DWORD process_id) OVERRIDE;
  virtual void OnFunctionEntry(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceEnterExitEventData* data) OVERRIDE;
  virtual void OnFunctionExit(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceEnterExitEventData* data) OVERRIDE;
  virtual void OnBatchFunctionEntry(base::Time time,
                                    DWORD process_id,
                                    DWORD thread_id,
                                    const TraceBatchEnterData* data) OVERRIDE;
  virtual void OnProcessAttach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) OVERRIDE;
  virtual void OnProcessDetach(base::Time time,
                               DWORD process_id,
                               DWORD thread_id,
                               const TraceModuleData* data) OVERRIDE;
  virtual void OnThreadAttach(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceModuleData* data) OVERRIDE;
  virtual void OnThreadDetach(base::Time time,
                              DWORD process_id,
                              DWORD thread_id,
                              const TraceModuleData* data) OVERRIDE;
  // @}

  FilePath module_path_;
  FilePath instrumented_path_;
  TraceFileList trace_files_;

  // Signature of the instrumented DLL. Used for filtering call-trace events.
  PEFile::Signature instr_signature_;
  // A set of flags controlling the reorderer behaviour.
  Flags flags_;
  // Number of CodeBlockEntry events processed.
  size_t code_block_entry_events_;

  // The following three variables are only valid while Reorder is executing.
  // A pointer to our order generator delegate.
  OrderGenerator* order_generator_;

  // A pointer to the PE file info for the module we're reordering. This
  // is actually a pointer to a part of the output structure, but several
  // internals make use of it during processing.
  PEFile* pe_;

  // The decomposed image of the module we're reordering. This is actually
  // a pointer to an image in the output structure, but several internals
  // make use of it during processing.
  ImageLayout* image_;

  // The OMAP info from the instrumented module's PDB. Used for mapping
  // addresses back and forth between the instrumented DLL and the original DLL.
  std::vector<OMAP> omap_to_;
  std::vector<OMAP> omap_from_;

  // The call-trace log file parser. This can be preset to a custom parser
  // prior to calling Reorder, but said parser must not already be initialized.
  // Since the parser is one-time-use, it must also be replaced prior to any
  // repeated calls to the Reorder. This muchanism is only intended for unit
  // testing.
  Parser* parser_;

  // The set of processes of interest. That is, those that have had code
  // run in the instrumented module. These are the only processes for which
  // we are interested in OnProcessEnded events.
  ProcessSet matching_process_ids_;

  // A cache for whether or not to reorder each section.
  typedef std::vector<bool> SectionReorderabilityCache;
  SectionReorderabilityCache section_reorderability_cache_;

  DISALLOW_COPY_AND_ASSIGN(Reorderer);
};

// Stores order information. An order may be serialized to and from JSON,
// in the following format:
//
// {
//   'metadata': {
//     this contains toolchain information, command-line info, etc
//   },
//   'sections': {
//     'section_id': <INTEGER SECTION ID>,
//     'blocks': [
//       list of integer block addresses
//     ]
//   ]
// }
struct Reorderer::Order {
  Order() {}

  // A comment describing the ordering.
  std::string comment;

  // An ordering of blocks. This list need not be exhaustive, but each
  // block should only appear once within it. We currently constrain ourselves
  // to keep blocks in the same section from which they originate. Thus, we
  // separate the order information per section, with the section IDs coming
  // from the ImageLayout of the original module.
  typedef std::vector<const BlockGraph::Block*> BlockList;
  typedef std::map<size_t, BlockList> BlockListMap;
  BlockListMap section_block_lists;

  // Serializes the order to JSON. Returns true on success, false otherwise.
  // The serialization simply consists of the start addresses of each block
  // in a JSON list. Pretty-printing adds further information from the
  // BlockGraph via inline comments.
  bool SerializeToJSON(const PEFile& pe,
                       const FilePath& path,
                       bool pretty_print) const;
  bool SerializeToJSON(const PEFile& pe,
                       core::JSONFileWriter* json_file) const;

  // Loads an ordering from a JSON file. 'pe' and 'image' must already be
  // populated prior to calling this.
  bool LoadFromJSON(const PEFile& pe,
                    const ImageLayout& image,
                    const FilePath& path);

  // Extracts the name of the original module from an order file. This is
  // used to guess the value of --input-dll.
  static bool GetOriginalModulePath(const FilePath& path, FilePath* module);

 private:
  DISALLOW_COPY_AND_ASSIGN(Order);
};

// The actual class that does the work, an order generator. It receives
// call trace events (already mapped to blocks in a disassembled image),
// and is asked to build an ordering.
class Reorderer::OrderGenerator {
 public:
  explicit OrderGenerator(const char* name) : name_(name) {}

  virtual ~OrderGenerator() {}

  // Accessor.
  const std::string& name() const { return name_; }

  // The derived class may implement this callback, which indicates when a
  // process invoking the instrumented module was started.
  virtual bool OnProcessStarted(uint32 process_id,
                                const UniqueTime& time) { return true; }

  // The derived class may implement this callback, which provides
  // information on the end of processes invoking the instrumented module.
  // Processes whose lifespan exceed the logging period will not receive
  // OnProcessEnded events.
  virtual bool OnProcessEnded(uint32 process_id,
                              const UniqueTime& time) { return true; }

  // The derived class shall implement this callback, which receives
  // TRACE_ENTRY events for the module that is being reordered. Returns true
  // on success, false on error. If this returns false, no further callbacks
  // will be processed.
  virtual bool OnCodeBlockEntry(const BlockGraph::Block* block,
                                RelativeAddress address,
                                uint32 process_id,
                                uint32 thread_id,
                                const UniqueTime& time) = 0;

  // The derived class shall implement this function, which actually produces
  // the reordering. When this is called, the callee can be assured that the
  // ImageLayout is populated and all traces have been parsed. This must
  // return true on success, false otherwise.
  virtual bool CalculateReordering(const PEFile& pe_file,
                                   const ImageLayout& image,
                                   bool reorder_code,
                                   bool reorder_data,
                                   Order* order) = 0;

 private:
  const std::string name_;

  DISALLOW_COPY_AND_ASSIGN(OrderGenerator);
};

// A unique time class. No two instances of this class will ever be equal
// This allows events that map to the same time (down to the resolution reported
// to us) to still maintain a unique temporal ordering. This is done by using
// a secondary counter value. It is necessary because we often get buffers full
// of events that have the same time indicated, but that we know to be in the
// temporal order in which they are stored in the buffer.
class Reorderer::UniqueTime {
 public:
  // This class has a copy-constructor and is assignable in order to be STL
  // container compatible.
  UniqueTime();
  UniqueTime(const UniqueTime& other);
  explicit UniqueTime(const base::Time& time);

  UniqueTime& operator=(const UniqueTime& rhs);

  const base::Time& time() const { return time_; }
  size_t id() const { return id_; }

  // Compares two UniqueTime objects, returning a value from the set {-1, 0, 1}.
  int compare(const UniqueTime& rhs) const;

  // Standard comparison operators.
  bool operator<(const UniqueTime& rhs) const { return compare(rhs) < 0; }
  bool operator>(const UniqueTime& rhs) const { return compare(rhs) > 0; }
  bool operator<=(const UniqueTime& rhs) const { return compare(rhs) <= 0; }
  bool operator>=(const UniqueTime& rhs) const { return compare(rhs) >= 0; }
  bool operator==(const UniqueTime& rhs) const { return compare(rhs) == 0; }
  bool operator!=(const UniqueTime& rhs) const { return compare(rhs) != 0; }

 private:
  base::Time time_;
  size_t id_;

  // Stores the next id that will be used in constructing a unique time object.
  static size_t next_id_;
};

}  // namespace reorder

#endif  // SYZYGY_REORDER_REORDERER_H_
