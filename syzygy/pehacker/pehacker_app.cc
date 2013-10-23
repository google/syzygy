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
#include "base/stringprintf.h"
#include "base/utf_string_conversions.h"
#include "base/json/json_reader.h"
#include "base/strings/string_split.h"
#include "syzygy/core/file_util.h"
#include "syzygy/pehacker/variables.h"

namespace pehacker {

namespace {

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
// in |path|. Returns true on success, false otherwise.
bool GetFilePath(const base::DictionaryValue& dictionary,
                 const base::DictionaryValue& variables,
                 const std::string& name,
                 base::FilePath* path) {
  DCHECK_NE(reinterpret_cast<base::FilePath*>(NULL), path);

  const base::Value* value;
  if (!dictionary.Get(name, &value)) {
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

}  // namespace

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
  if (!file_util::ReadFileToString(config_file_, &json)) {
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

  if (!dry_run) {
    // TODO(chrisha): Finalize any transformed modules and write them to disk.
    LOG(ERROR) << "Module finalization not implemented.";
    return false;
  }

  return true;
}

bool PEHackerApp::ProcessTarget(bool dry_run, base::DictionaryValue* target) {
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), target);

  base::FilePath input_module;
  if (!GetFilePath(*target, variables_, "input_module", &input_module))
    return false;

  base::FilePath output_module;
  if (!GetFilePath(*target, variables_, "output_module", &output_module))
    return false;

  base::ListValue* operations = NULL;
  if (!target->GetList("operations", &operations)) {
    LOG(ERROR) << "Each target must specify an \"operations\" list.";
    return false;
  }

  // Validate the input path exists.
  if (!file_util::PathExists(input_module)) {
    LOG(ERROR) << "Path for \"input_module\" does not exist: "
               << input_module.value();
    return false;
  }

  // If we're not overwriting then make sure the output path does not exist.
  if (!overwrite_ && file_util::PathExists(output_module)) {
    LOG(ERROR) << "Path for \"output_module\" exists: "
               << output_module.value();
    LOG(ERROR) << "Specify --overwrite to ignore this error.";
    return false;
  }

  BlockGraph* block_graph = NULL;
  if (!dry_run) {
    // TODO(chrisha): Decompose the PE file, or find the already decomposed
    //     version of it.
    LOG(ERROR) << "Target processing not yet implemented.";
    return false;
  }

  VLOG(1) << "Processing operations for module \"" << input_module.value()
          << "\".";
  if (!ProcessOperations(dry_run, operations, block_graph))
    return false;

  return true;
}

bool PEHackerApp::ProcessOperations(bool dry_run,
                                    base::ListValue* operations,
                                    BlockGraph* block_graph) {
  DCHECK_NE(reinterpret_cast<base::ListValue*>(NULL), operations);
  if (!dry_run)
    DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);

  for (size_t i = 0; i < operations->GetSize(); ++i) {
    base::DictionaryValue* operation = NULL;
    if (!operations->GetDictionary(i, &operation)) {
      LOG(ERROR) << "Each operation must be a dictionary.";
      return false;
    }

    if (!ProcessOperation(dry_run, operation, block_graph))
      return false;
  }

  return true;
}

bool PEHackerApp::ProcessOperation(bool dry_run,
                                   base::DictionaryValue* operation,
                                   BlockGraph* block_graph) {
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), operation);
  if (!dry_run)
    DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);

  std::string type;
  if (!operation->GetString("type", &type)) {
    LOG(ERROR) << "Each operation must specify a \"type\".";
    return false;
  }

  // Dispatch to the appropriate operation implementation.
  if (type == "none") {
    // The 'none' operation is always defined, and does nothing. This is
    // mainly there for simple unittesting of configuration files.
    return true;
  } else if (type == "add_imports") {
    if (!ProcessAddImports(dry_run, operation, block_graph))
      return false;
  } else {
    LOG(ERROR) << "Unrecognized operation type \"" << type << "\".";
    return false;
  }

  return true;
}

bool PEHackerApp::ProcessAddImports(bool dry_run,
                                    base::DictionaryValue* operation,
                                    BlockGraph* block_graph) {
  DCHECK_NE(reinterpret_cast<base::DictionaryValue*>(NULL), operation);
  if (!dry_run) {
    DCHECK_NE(reinterpret_cast<BlockGraph*>(NULL), block_graph);
    LOG(ERROR) << "The add_imports operation is not yet implemented.";
    return false;
  }

  return true;
}

}  // namespace pehacker
