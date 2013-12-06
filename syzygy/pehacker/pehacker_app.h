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
//
// Defines the PEHackerApp class, which implements the command-line
// "pehacker" tool.

#ifndef SYZYGY_PEHACKER_PEHACKER_APP_H_
#define SYZYGY_PEHACKER_PEHACKER_APP_H_

#include "base/command_line.h"
#include "base/string_piece.h"
#include "base/time.h"
#include "base/values.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_vector.h"
#include "syzygy/block_graph/block_graph.h"
#include "syzygy/common/application.h"
#include "syzygy/pe/pe_file.h"
#include "syzygy/pe/pe_transform_policy.h"

namespace pehacker {

// Implements the "pehacker" command-line application.
//
// Refer to kUsageFormatStr (referenced from PEHackerApp::Usage()) for
// usage information.
class PEHackerApp : public common::AppImplBase {
 public:
  PEHackerApp()
      : common::AppImplBase("PEHacker"), overwrite_(false) {
  }

  // @name Implementation of the AppImplBase interface.
  // @{
  bool ParseCommandLine(const CommandLine* command_line);
  int Run();
  // @}

 protected:
  typedef block_graph::BlockGraph BlockGraph;

  // Modules being maintained by the pipeline are uniquely identified by
  // their input and output names. This allows the same module to be processed
  // multiple times by the pipeline, being written to different destinations.
  struct ImageId {
    base::FilePath input_module;
    base::FilePath output_module;
    bool operator<(const ImageId& rhs) const;
  };

  // This maintains information about a module that is being processed by
  // the pipeline.
  struct ImageInfo {
    ImageInfo() : header_block(NULL) { }
    base::FilePath input_module;
    base::FilePath output_module;
    base::FilePath input_pdb;
    base::FilePath output_pdb;
    pe::PEFile pe_file;
    BlockGraph block_graph;
    BlockGraph::Block* header_block;
  };

  typedef std::map<ImageId, ImageInfo*> ImageInfoMap;

  // @name Utility members.
  // @{
  bool Usage(const CommandLine* command_line,
             const base::StringPiece& message) const;
  // @}

  // Sets built-in variables. This is run by ParseCommandLine, prior to parsing
  // variables passed on the command-line.
  // @returns true on success, false otherwise.
  bool SetBuiltInVariables();

  // Loads, parses and validates the configuration file. This is called as
  // part of Run(), but is exposed for unittesting.
  bool LoadAndValidateConfigurationFile();

  // Parses the configuration file, populating config_. This is called from
  // LoadAndValidateConfiguration.
  // @returns true on success, false otherwise.
  bool ParseConfigFile();

  // Updates the variables dictionary with values parsed from the configuration
  // file. This is called from LoadAndValidateConfiguration.
  // @returns true on success, false otherwise.
  bool UpdateVariablesFromConfig();

  // @name For processing the configuration file.
  // @{
  // @param dry_run If this is true then no actual work is done, but the
  //     configuration file is validated.
  // @param targets A list of targets to process.
  // @param target A target to process.
  // @param operations A list of operations to process.
  // @param operation An operation to process.
  // @param image_info Information about the image being transformed.
  // @returns true on success, false otherwise.
  bool ProcessConfigurationFile(bool dry_run);
  bool ProcessTargets(bool dry_run, base::ListValue* targets);
  bool ProcessTarget(bool dry_run, base::DictionaryValue* target);
  bool ProcessOperations(bool dry_run,
                         base::ListValue* operations,
                         ImageInfo* image_info);
  bool ProcessOperation(bool dry_run,
                        base::DictionaryValue* operation,
                        ImageInfo* image_info);
  // @}

  // Looks up the already decomposed image, or loads and decomposes it for the
  // first time.
  // @param input_module The path to the input module.
  // @param output_module The path to the output module.
  // @param input_pdb The path to the input PDB.
  // @param output_pdb The path to the output PDB.
  // @returns a pointer to the ImageInfo for the requested image. Returns NULL
  //     on failure.
  ImageInfo* GetImageInfo(const base::FilePath& input_module,
                          const base::FilePath& output_module,
                          const base::FilePath& input_pdb,
                          const base::FilePath& output_pdb);

  // Writes any transformed images back to disk.
  // @returns true on success, false otherwise.
  bool WriteImages();

  // @name Command-line parameters.
  base::FilePath config_file_;
  bool overwrite_;
  // @}

  // Dictionary of variables. We use a JSON dictionary so that it can easily
  // represent doubles, integers, strings, etc.
  base::DictionaryValue variables_;

  // The configuration file is parsed as a JSON file and stored here.
  scoped_ptr<base::DictionaryValue> config_;

  // These house the modules that are being transformed by the pipeline.
  ScopedVector<ImageInfo> image_infos_;
  ImageInfoMap image_info_map_;

  // The policy object used by the various transforms.
  pe::PETransformPolicy policy_;
};

}  // namespace pehacker

#endif  // SYZYGY_PEHACKER_PEHACKER_APP_H_
