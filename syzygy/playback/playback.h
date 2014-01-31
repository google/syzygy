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
// This defines the playback class. The class encapsulates the workflow
// associated with parsing a trace file with respect to an original module.
// It takes care of  validating that all data sources match (trace files,
// instrumented module, original module), decomposing the original module,
// and provides functionality for mapping trace events back to
// addresses/blocks in the original module.
//
// Playback playback(module_path, instrumented_path, trace_files);
// playback.Init(pe_file, image, parser)
// playback.ConsumeCallTraceEvents()

#ifndef SYZYGY_PLAYBACK_PLAYBACK_H_
#define SYZYGY_PLAYBACK_PLAYBACK_H_

#include <windows.h>

#include "base/win/event_trace_consumer.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/pdb/omap.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/image_layout.h"
#include "syzygy/trace/parse/parser.h"

namespace playback {

class Playback {
 public:
  typedef block_graph::BlockGraph BlockGraph;
  typedef pe::ImageLayout ImageLayout;
  typedef pe::PEFile PEFile;
  typedef std::vector<base::FilePath> TraceFileList;
  typedef trace::parser::ModuleInformation ModuleInformation;
  typedef trace::parser::Parser Parser;

  // Construct a new Playback instance.
  // @param module_path The path of the module dll.
  // @param instrumented_path The path of the instrumented dll.
  // @param trace_files A list of the trace files to analyze.
  Playback(const base::FilePath& module_path,
           const base::FilePath& instrumented_path,
           const TraceFileList& trace_files);

  ~Playback();

  // Initializes the playback class and decomposes the given image.
  // This function is virtual to aid testing of classes that may own Playback.
  // @param pe_file The PE file to be initialized.
  // @param image The image that will receive the decomposed module.
  // @param parser The parser to be used.
  // @returns true on success, false on failure.
  virtual bool Init(PEFile* pe_file, ImageLayout* image, Parser* parser);

  // @returns true if the given ModuleInformation matches the instrumented
  // module signature, false otherwise.
  bool MatchesInstrumentedModuleSignature(
      const ModuleInformation& module_info) const;

  // Gets a code block from our image from its function address and process id.
  // @param process_id The process id of the module where the function resides.
  // @param function The relative address of the function we are searching.
  // @param error Will be set to true if an error occurs.
  // @returns The code block @p function and @p process_id refer to, or NULL if
  //     no such block can be found (this can occur if events for multiple
  //     instrumented modules occur in the same trace file, and we are
  //     processing an event from a module that is not our module of interest.)
  //     If an error occurs this will also return NULL.
  const BlockGraph::Block* FindFunctionBlock(DWORD process_id,
                                             FuncAddr function,
                                             bool* error);

  // @name Accessors
  // @{
  const PEFile* pe_file() const { return pe_file_; }
  const ImageLayout* image() const { return image_; }
  const TraceFileList& trace_files() const { return trace_files_; }
  const std::vector<OMAP>& omap_to() const { return omap_to_; }
  const std::vector<OMAP>& omap_from() const { return omap_from_; }
  const PEFile::Signature& instr_signature() const { return instr_signature_; }
  // @}

 protected:
  typedef pe::Decomposer Decomposer;
  typedef TraceFileList::iterator TraceFileIter;
  typedef uint64 AbsoluteAddress64;
  typedef uint64 Size64;

  // Loads information from the instrumented and original modules.
  bool LoadModuleInformation();
  // Initializes the parser.
  bool InitializeParser();
  // Loads OMAP information for the instrumented module.
  bool LoadInstrumentedOmap();
  // Decomposes the original image.
  bool DecomposeImage();

  // Parses the instrumented DLL headers, validating that it was produced
  // by a compatible version of the toolchain, and extracting signature
  // information and metadata.
  // @returns true on success, false otherwise.
  bool ValidateInstrumentedModuleAndParseSignature(
      PEFile::Signature* orig_signature);

  // The paths of the test module, instrumented module, and trace files.
  base::FilePath module_path_;
  base::FilePath instrumented_path_;
  TraceFileList trace_files_;

  // This is a copy of the parser used to decompose the image, which needs
  // to be initialized with a ParseEventHandler before being used.
  Parser* parser_;

  // A pointer to the PE file info for the module we're analyzing. This
  // is actually a pointer to a part of the output structure, but several
  // internals make use of it during processing.
  PEFile* pe_file_;

  // The decomposed image of the module we're analyzing. This is actually
  // a pointer to an image in the output structure, but several internals
  // make use of it during processing.
  ImageLayout* image_;

  // The OMAP info from the instrumented module's PDB. Used for mapping
  // addresses back and forth between the instrumented DLL and the original DLL.
  std::vector<OMAP> omap_to_;
  std::vector<OMAP> omap_from_;

  // Signature of the instrumented DLL. Used for filtering call-trace events.
  PEFile::Signature instr_signature_;
};

}  // namespace playback

#endif  // SYZYGY_PLAYBACK_PLAYBACK_H_
