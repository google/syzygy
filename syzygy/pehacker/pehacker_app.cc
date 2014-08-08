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

#include "syzygy/pehacker/pehacker_app.h"

#include "base/file_util.h"
#include "base/json/json_reader.h"
#include "base/strings/string_split.h"
#include "base/strings/stringprintf.h"
#include "base/strings/utf_string_conversions.h"
#include "syzygy/block_graph/orderers/original_orderer.h"
#include "syzygy/pdb/pdb_reader.h"
#include "syzygy/pdb/pdb_writer.h"
#include "syzygy/pe/decomposer.h"
#include "syzygy/pe/pe_file_writer.h"
#include "syzygy/pe/pe_relinker_util.h"
#include "syzygy/pehacker/operation.h"
#include "syzygy/pehacker/variables.h"
#include "syzygy/pehacker/operations/add_imports_operation.h"
#include "syzygy/pehacker/operations/redirect_imports_operation.h"

namespace pehacker {

namespace {

using block_graph::BlockGraph;

static const char kUsageFormatStr[] = "Usage: %ls [options]\n"
    "  Required Options:\n"
    "    --config-file=<path>  Path to the configuration file to be used.\n"
    "  Options:\n"
    "    -Dvar=val             Defines variable 'var' with value 'val'.\n"
    "                          Variable names defined on the command-line\n"
    "                          will be normalized to all lowercase. Values\n"
    "                          will be parsed as JSON.\n"
    "    --overwrite           Allow output files to be overwritten.\n"
    "    --verbose             Log verbosely.\n"
    "\n";

// Gets the value under key |name| in |dictionary|, performing variable
// expansion using |variables|, and finally converting it to a normalized path
// in |path|. If |optional| this will return true if the key doesn't exist
// and leave |path| unchanged. Returns true on success, false otherwise.
bool GetFilePath(bool optional,
                 const base::DictionaryValue& dictionary,
                 const base::DictionaryValue& variables,
                 const std::string& name,
                 base::FilePath* path) {
  DCHECK_NE(reinterpret_cast<base::FilePath*>(NULL), path);

  const base::Value* value;
  if (!dictionary.Get(name, &value)) {
    if (optional)
      return true;

    LOG(ERROR) << "Dictionary does not contain key \"" << name << "\".";
    return false;
  }

  std::string s;
  if (!ConvertVariableToString(*value, &s))
    return false;

  if (!ExpandVariables(variables, s, &s))
    return false;

  *path = base::FilePath(base::UTF8ToWide(s)).NormalizePathSeparators();
  VLOG(1) << "Parsed \"" << name << "\" as \"" << path->value() << "\".";
  return true;
}

void RemovePaddingBlocks(BlockGraph* block_graph) {
  DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
  BlockGraph::BlockMap::iterator it = block_graph->blocks_mutable().begin();
  while (it != block_graph->blocks_mutable().end()) {
    BlockGraph::BlockMap::iterator it_next = it;
    ++it_next;

    BlockGraph::Block* block = &it->second;
    if (block->attributes() & BlockGraph::PADDING_BLOCK)
      block_graph->RemoveBlock(block);

    it = it_next;
  }
}

}  // namespace

bool PEHackerApp::ImageId::operator<(const ImageId& rhs) const {
  if (input_module.value() < rhs.input_module.value())
    return true;
  if (input_module.value() > rhs.input_module.value())
    return false;
  return output_module.value() < rhs.output_module.value();
}

bool PEHackerApp::ParseCommandLine(const CommandLine* cmd_line) {
  DCHECK_NE(reinterpret_cast<const CommandLine*>(NULL), cmd_line);

  if (cmd_line->HasSwitch("help"))
    return Usage(cmd_line, "");

  if (cmd_line->HasSwitch("verbose")) {
    logging::SetMinLogLevel(logging::LOG_VERBOSE);
    VLOG(1) << "Parsed --verbose switch.";
  }

  config_file_ = cmd_line->GetSwitchValuePath("config-file").
      NormalizePathSeparators();
  if (config_file_.empty()) {
    LOG(ERROR) << "Must specify --config-file!";
    return false;
  }

  overwrite_ = cmd_line->HasSwitch("overwrite");
  if (overwrite_) {
    VLOG(1) << "Parsed --overwrite switch.";
  }

  // Set built-in variables.
  if (!SetBuiltInVariables())
    return false;

  // Parse any variables defined as arguments.
  VLOG(1) << "Parsing command-line variables.";
  const CommandLine::SwitchMap& switches = cmd_line->GetSwitches();
  CommandLine::SwitchMap::const_iterator it = switches.begin();
  for (; it != switches.end(); ++it) {
    if (it->first[0] != 'd')
      continue;
    const std::wstring wname(it->first.begin() + 1, it->first.end());
    std::string name = base::WideToUTF8(wname);
    std::string value = base::WideToUTF8(it->second);
    if (!ParseVariable(name, value, &variables_))
      return false;
  }

  return true;
}

int PEHackerApp::Run() {
  if (!LoadAndValidateConfigurationFile())
    return 1;

  if (!ProcessConfigurationFile(false))
    return 1;

  if (!WriteImages())
    return 1;

  return 0;
}

bool PEHackerApp::Usage(const CommandLine* cmd_line,
                        const base::StringPiece& message) const {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), err());
    ::fprintf(err(), "\n\n");
  }

  ::fprintf(err(),
            kUsageFormatStr,
            cmd_line->GetProgram().BaseName().value().c_str());

  return false;
}

bool PEHackerApp::SetBuiltInVariables() {
  VLOG(1) << "Setting built-in variables.";
  std::wstring wroot = config_file_.DirName().value();
  std::string root = base::WideToUTF8(wroot);
  variables_.Set("ROOT", new base::StringValue(root));
  return true;
}

bool PEHackerApp::LoadAndValidateConfigurationFile() {
  // Parse the configuration file.
  if (!ParseConfigFile())
    return false;

  // Build the variables dictionary.
  if (!UpdateVariablesFromConfig())
    return false;

  // If we're logging verbosely then dump the variables for debugging.
  if (logging::LOG_VERBOSE >= logging::GetMinLogLevel()) {
    base::DictionaryValue::Iterator it(variables_);
    for (; !it.IsAtEnd(); it.Advance()) {
      std::string value;
      ConvertVariableToJson(it.value(), &value);
      VLOG(1) << "Have variable \"" << it.key() << "\" with value "
              << value << ".";
    }
  }

  // Process the configuration in dry-run mode. This doesn't do any work, but
  // validates that the configuration makes sense and can be run.
  if (!ProcessConfigurationFile(true))
    return false;

  return true;
}

bool PEHackerApp::ParseConfigFile() {
  LOG(INFO) << "Loading configuration file \"" << config_file_.value()
            << "\".";

  VLOG(1) << "Reading configuration file from disk.";
  std::string json;
  if (!base::ReadFileToString(config_file_, &json)) {
    LOG(ERROR) << "Unable to read configuration file \""
               << config_file_.value() << "\".";
    return false;
  }

  VLOG(1) << "Parsing configuration file contents.";
  scoped_ptr<base::Value> config;
  int error_code = 0;
  std::string error_message;
  config.reset(base::JSONReader::ReadAndReturnError(
      json,
      base::JSON_ALLOW_TRAILING_COMMAS,
      &error_code,
      &error_message));
  if (config.get() == NULL) {
    LOG(ERROR) << "Failed to parse configuration file: "
               << error_message << "(" << error_code << ").";
    return false;
  }

  // Ensure the configuration is a dictionary, and transfer ownership to
  // config_ if it is.
  base::DictionaryValue* dict = NULL;
  if (!config->GetAsDictionary(&dict)) {
    LOG(ERROR) << "Configuration must be a dictionary.";
    return false;
  }
  config_.reset(dict);
  config.release();

  return true;
}

bool PEHackerApp::UpdateVariablesFromConfig() {
  base::Value* value = NULL;
  if (!config_->Get("variables", &value))
    return true;

  base::DictionaryValue* variables = NULL;
  if (!value->GetAsDictionary(&variables)) {
    LOG(ERROR) << "Expect a dictionary for \"variables\".";
    return false;
  }

  VLOG(1) << "Merging configuration variables with command-line variables.";
  if (!MergeVariables(*variables, &variables_))
    return false;
  return true;
}

bool PEHackerApp::ProcessConfigurationFile(bool dry_run) {
  if (dry_run) {
    VLOG(1) << "Validating configuration file.";
  }

  base::ListValue* targets = NULL;
  if (!config_->GetList("targets", &targets)) {
    LOG(ERROR) << "Configuration must contain a \"targets\" list.";
    return false;
  }

  if (!ProcessTargets(dry_run, targets))
    return false;

  return true;
}

bool PEHackerApp::ProcessTargets(bool dry_run, base::ListValue* targets) {
  DCHECK_NE(reinterpret_cast<base::ListValue*>(NULL), targets);

  if (targets->GetSize() == 0) {
    LOG(ERROR) << "No targets to process.";
    return false;
  }

  // Process the targets in order.
  for (size_t i = 0; i < targets->GetSize(); ++i) {
    base::DictionaryValue* target = NULL;
    if (!targets->GetDictionary(i, &target)) {
      LOG(ERROR) << "Each target must be a dictionary.";
      return false;
    }

    if (!ProcessTarget(dry_run, target))
      return false;
  }

  return true;
}

bool PEHackerApp::ProcessTarget(bool dry_run, base::DictionaryValue* target) {
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), target);

  base::FilePath input_module;
  base::FilePath output_module;
  base::FilePath input_pdb;
  base::FilePath output_pdb;
  bool opt = false;
  if (!GetFilePath(opt, *target, variables_, "input_module", &input_module))
    return false;
  if (!GetFilePath(opt, *target, variables_, "output_module", &output_module))
    return false;
  opt = true;
  if (!GetFilePath(opt, *target, variables_, "input_pdb", &input_pdb))
    return false;
  if (!GetFilePath(opt, *target, variables_, "output_pdb", &output_pdb))
    return false;

  base::ListValue* operations = NULL;
  if (!target->GetList("operations", &operations)) {
    LOG(ERROR) << "Each target must specify an \"operations\" list.";
    return false;
  }

  // Validate and infer module-related paths.
  if (!pe::ValidateAndInferPaths(
          input_module, output_module, overwrite_, &input_pdb, &output_pdb)) {
    return false;
  }

  ImageInfo* image_info = NULL;
  if (!dry_run) {
    // Get the decomposed image.
    image_info = GetImageInfo(
        input_module, output_module, input_pdb, output_pdb);
    if (image_info == NULL)
      return false;
  }

  VLOG(1) << "Processing operations for module \"" << input_module.value()
          << "\".";
  if (!ProcessOperations(dry_run, operations, image_info))
    return false;

  return true;
}

bool PEHackerApp::ProcessOperations(bool dry_run,
                                    base::ListValue* operations,
                                    ImageInfo* image_info) {
  DCHECK_NE(reinterpret_cast<base::ListValue*>(NULL), operations);
  if (!dry_run)
    DCHECK_NE(reinterpret_cast<ImageInfo*>(NULL), image_info);

  for (size_t i = 0; i < operations->GetSize(); ++i) {
    base::DictionaryValue* operation = NULL;
    if (!operations->GetDictionary(i, &operation)) {
      LOG(ERROR) << "Each operation must be a dictionary.";
      return false;
    }

    if (!ProcessOperation(dry_run, operation, image_info))
      return false;
  }

  return true;
}

bool PEHackerApp::ProcessOperation(bool dry_run,
                                   base::DictionaryValue* operation,
                                   ImageInfo* image_info) {
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), operation);
  if (!dry_run)
    DCHECK_NE(reinterpret_cast<ImageInfo*>(NULL), image_info);

  std::string type;
  if (!operation->GetString("type", &type)) {
    LOG(ERROR) << "Each operation must specify a \"type\".";
    return false;
  }

  // Dispatch to the appropriate operation implementation.
  scoped_ptr<OperationInterface> operation_impl;
  if (type == "none") {
    // The 'none' operation is always defined, and does nothing. This is
    // mainly there for simple unittesting of configuration files.
    return true;
  } else if (type == "add_imports") {
    operation_impl.reset(new operations::AddImportsOperation());
  } else if (type == "redirect_imports") {
    operation_impl.reset(new operations::RedirectImportsOperation());
  } else {
    LOG(ERROR) << "Unrecognized operation type \"" << type << "\".";
    return false;
  }

  // Initialize the operation.
  DCHECK_NE(reinterpret_cast<OperationInterface*>(NULL), operation_impl.get());
  if (!operation_impl->Init(&policy_, operation)) {
    LOG(ERROR) << "Failed to initialize \"" << operation_impl->name()
               << "\".";
    return false;
  }

  // If not in a dry-run then apply the operation.
  if (!dry_run) {
    LOG(INFO) << "Applying operation \"" << type << "\" to \""
              << image_info->input_module.value() << "\".";
    if (!operation_impl->Apply(&policy_,
                               &image_info->block_graph,
                               image_info->header_block)) {
      LOG(ERROR) << "Failed to apply \"" << operation_impl->name() << "\".";
      return false;
    }
  }

  return true;
}

PEHackerApp::ImageInfo* PEHackerApp::GetImageInfo(
    const base::FilePath& input_module,
    const base::FilePath& output_module,
    const base::FilePath& input_pdb,
    const base::FilePath& output_pdb) {
  DCHECK(!input_module.empty());
  DCHECK(!output_module.empty());
  DCHECK(!input_pdb.empty());
  DCHECK(!output_pdb.empty());

  // Return the existing module if it exists.
  ImageId image_id = { input_module, output_module };
  ImageInfoMap::iterator it = image_info_map_.find(image_id);
  if (it != image_info_map_.end())
    return it->second;

  // Initialize a new ImageInfo struct.
  scoped_ptr<ImageInfo> image_info(new ImageInfo());
  image_info->input_module = input_module;
  image_info->output_module = output_module;
  image_info->input_pdb = input_pdb;
  image_info->output_pdb = output_pdb;
  if (!image_info->pe_file.Init(input_module)) {
    LOG(ERROR) << "Failed to read image: " << input_module.value();
    return NULL;
  }

  // Decompose the image.
  pe::ImageLayout image_layout(&image_info->block_graph);
  pe::Decomposer decomposer(image_info->pe_file);
  if (!decomposer.Decompose(&image_layout)) {
    LOG(ERROR) << "Failed to decompose image: " << input_module.value();
    return NULL;
  }

  // Lookup the header block.
  image_info->header_block = image_layout.blocks.GetBlockByAddress(
      BlockGraph::RelativeAddress(0));
  DCHECK_NE(reinterpret_cast<BlockGraph::Block*>(NULL),
            image_info->header_block);

  // Remove padding blocks. No need to carry these through the pipeline.
  VLOG(1) << "Removing padding blocks.";
  RemovePaddingBlocks(&image_info->block_graph);

  // Get the input range to use in generating OMAP information. This is required
  // when finalizing the PDB.
  pe::GetOmapRange(image_layout.sections, &image_info->input_omap_range);

  // Decomposition was successful. Add it to the map, transfer the image info to
  // the scoped array and return it.
  it = image_info_map_.insert(std::make_pair(image_id, image_info.get())).first;
  image_infos_.push_back(image_info.release());
  return it->second;
}

bool PEHackerApp::WriteImages() {
  ImageInfoMap::iterator it = image_info_map_.begin();
  for (; it != image_info_map_.end(); ++it) {
    ImageInfo* image_info = it->second;

    LOG(INFO) << "Finalizing and writing image \""
              << image_info->output_module.value() << "\".";

    // Create a GUID for the output PDB.
    GUID pdb_guid = {};
    if (FAILED(::CoCreateGuid(&pdb_guid))) {
      LOG(ERROR) << "Failed to create new GUID for output PDB.";
      return false;
    }

    // Finalize the block-graph.
    VLOG(1) << "Finalizing the block-graph.";
    if (!pe::FinalizeBlockGraph(image_info->input_module,
                                image_info->output_pdb,
                                pdb_guid,
                                true,
                                &policy_,
                                &image_info->block_graph,
                                image_info->header_block)) {
      return false;
    }

    // Build the ordered block-graph.
    block_graph::OrderedBlockGraph ordered_block_graph(
        &image_info->block_graph);
    block_graph::orderers::OriginalOrderer orderer;
    VLOG(1) << "Ordering the block-graph.";
    if (!orderer.OrderBlockGraph(&ordered_block_graph,
                                 image_info->header_block)) {
      return false;
    }

    // Finalize the ordered block-graph.
    VLOG(1) << "Finalizing the ordered block-graph.";
    if (!pe::FinalizeOrderedBlockGraph(&ordered_block_graph,
                                       image_info->header_block)) {
      return false;
    }

    // Build the image layout.
    pe::ImageLayout image_layout(&image_info->block_graph);
    VLOG(1) << "Building the image layout.";
    if (!pe::BuildImageLayout(0, 1, ordered_block_graph,
                              image_info->header_block, &image_layout)) {
      return false;
    }

    // Write the image.
    pe::PEFileWriter pe_writer(image_layout);
    VLOG(1) << "Writing image to disk.";
    if (!pe_writer.WriteImage(image_info->output_module))
      return false;

    LOG(INFO) << "Finalizing and writing PDB file \""
              << image_info->output_pdb.value() << "\".";

    // Parse the original PDB.
    pdb::PdbFile pdb_file;
    pdb::PdbReader pdb_reader;
    VLOG(1) << "Reading original PDB.";
    if (!pdb_reader.Read(image_info->input_pdb, &pdb_file))
      return false;

    // Finalize the PDB to reflect the transformed image.
    VLOG(1) << "Finalizing PDB.";
    if (!pe::FinalizePdbFile(image_info->input_module,
                             image_info->output_module,
                             image_info->input_omap_range,
                             image_layout,
                             pdb_guid,
                             false,
                             false,
                             false,
                             &pdb_file)) {
      return false;
    }

    // Write the PDB.
    pdb::PdbWriter pdb_writer;
    VLOG(1) << "Writing transformed PDB.";
    if (!pdb_writer.Write(image_info->output_pdb, pdb_file))
      return false;
  }

  return true;
}

}  // namespace pehacker
