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

#include "syzygy/genfilter/genfilter_app.h"

#include "base/file_util.h"
#include "base/strings/string_util.h"
#include "base/strings/stringprintf.h"
#include "syzygy/genfilter/filter_compiler.h"
#include "syzygy/pe/image_filter.h"

namespace genfilter {

namespace {

typedef pe::ImageFilter ImageFilter;

const char kUsageFormatStr[] =
    "Usage: %ls --action=<action> [options] [inputs ...]\n"
    "\n"
    "  A tool for generating filters to be used in instrumenting a binary.\n"
    "  Inputs may be specified using wildcards.\n"
    "\n"
    "Required parameters:\n"
    "  --action=<action>\n"
    "    The action to be performed. Must be one of 'compiler', 'intersect',\n"
    "    'invert', 'subtract' or 'union.\n"
    "\n"
    "Optional parameters:\n"
    "  --output-file=<path>\n"
    "    The path of the output file to produce. If none is specified this\n"
    "    will go to stdout. If the output file already exists it will not be\n"
    "    overwritten unless '--overwrite' is specified.\n"
    "  --overwrite\n"
    "    Indicates that the tool may safely overwrite existing files.\n"
    "  --pretty-print\n"
    "    If specified then the JSON encoded filter will be pretty printed.\n"
    "\n"
    "Actions:\n"
    "  compile    Compiles the rules in the filter description input files\n"
    "             and produces a JSON encoded filter as output.\n"
    "  intersect  Calculates the union of the inputs, which must all be JSON\n"
    "             encoded filters for the same module.\n"
    "  invert     Inverts the given JSON encoded filter. Only one input\n"
    "             should be provided.\n"
    "  subtract   Calculates the set difference of the inputs, subtracting\n"
    "             subsequent inputs from the first. All inputs must be JSON\n"
    "             encoded filters for the same module.\n"
    "  union      Calculates the union of the input filters, which must all\n"
    "             be JSON encoded filters for the same module.\n"
    "\n"
    "Parameters for 'compile' action:\n"
    "  --input-image=<path>                                        [REQUIRED]\n"
    "    The path of the module for which the filter is being generated.\n"
    "  --input-pdb=<path>                                          [OPTIONAL]\n"
    "    The path of the PDB corresponding to the input module. If not\n"
    "    specified this will be searched for.\n";

// Applies the given action to a set of filters. Assumes that all of the filters
// are already verified as belonging to the same module.
void ApplyBinarySetAction(GenFilterApp::Action action,
                          const ImageFilter& in1,
                          const ImageFilter& in2,
                          ImageFilter* out) {
  DCHECK(out != NULL);

  switch (action) {
    case GenFilterApp::kIntersect:
      return in1.filter.Intersect(in2.filter, &out->filter);
    case GenFilterApp::kSubtract:
      return in1.filter.Subtract(in2.filter, &out->filter);
    case GenFilterApp::kUnion:
      return in1.filter.Union(in2.filter, &out->filter);
    default:
      NOTREACHED() << "Not a binary set action.";
  }
}

bool OutputFilter(bool pretty_print,
                  const base::FilePath& path,
                  const ImageFilter& filter,
                  FILE* default_file) {
  // Open the output file. If none was specified we default to default_file.
  std::wstring dest(L"stdout");
  FILE* file = default_file;
  base::ScopedFILE scoped_file;
  if (!path.empty()) {
    dest = base::StringPrintf(L"\"%ls\"", path.value().c_str());
    scoped_file.reset(base::OpenFile(path, "wb"));
    file = scoped_file.get();
    if (file == NULL) {
      LOG(ERROR) << "Unable to open for writing: " << path.value();
      return false;
    }
  }

  LOG(INFO) << "Writing filter to " << dest << ".";
  if (!filter.SaveToJSON(pretty_print, file)) {
    LOG(ERROR) << "Failed to write filter to " << dest << ".";
    return false;
  }

  return true;
}

}  // namespace

bool GenFilterApp::ParseCommandLine(const CommandLine* command_line) {
  if (!command_line->HasSwitch("action")) {
    PrintUsage(command_line, "You must specify an action.");
    return false;
  }

  // Get a list of all input files.
  CommandLine::StringVector args = command_line->GetArgs();
  if (args.empty()) {
    PrintUsage(command_line, "You must provide at least one input file.");
    return false;
  }
  for (size_t i = 0; i < args.size(); ++i) {
    if (!AppendMatchingPaths(base::FilePath(args[i]), &inputs_)) {
      PrintUsage(command_line,
                 base::StringPrintf("No files matching '%ws'.",
                                    args[i].c_str()));
      return false;
    }
  }

  // Parse the optional parameters.
  output_file_ = command_line->GetSwitchValuePath("output-file");
  pretty_print_ = command_line->HasSwitch("pretty-print");
  overwrite_ = command_line->HasSwitch("overwrite");

  // Parse the action and any action-specific options.
  size_t min_inputs = 1;
  size_t max_inputs = -1;
  std::string action = command_line->GetSwitchValueASCII("action");
  if (LowerCaseEqualsASCII(action, "compile")) {
    action_ = kCompile;

    // In compile mode we need an input image.
    input_image_ = command_line->GetSwitchValuePath("input-image");
    if (input_image_.empty()) {
      PrintUsage(command_line,
                 "Must specify '--input-image' when action is 'compile'.");
      return false;
    }
    input_pdb_ = command_line->GetSwitchValuePath("input-pdb");
  } else if (LowerCaseEqualsASCII(action, "intersect")) {
    action_ = kIntersect;
    min_inputs = 2;
  } else if (LowerCaseEqualsASCII(action, "invert")) {
    action_ = kInvert;
    max_inputs = 1;
  } else if (LowerCaseEqualsASCII(action, "subtract")) {
    action_ = kSubtract;
    min_inputs = 2;
  } else if (LowerCaseEqualsASCII(action, "union")) {
    action_ = kUnion;
    min_inputs = 2;
  } else {
    PrintUsage(command_line,
               base::StringPrintf("Unknown action: %s.", action.c_str()));
    return false;
  }

  // Ensure we have the right number of inputs for the action.
  if (inputs_.size() < min_inputs) {
    PrintUsage(command_line,
               base::StringPrintf("Expect at least %d inputs for action '%s'.",
                                  min_inputs, action.c_str()));
    return false;
  }
  if (inputs_.size() > max_inputs) {
    PrintUsage(command_line,
               base::StringPrintf(
                   "Expect no more than %d inputs for action '%s'.",
                   max_inputs, action.c_str()));
    return false;
  }

  return true;
}

int GenFilterApp::Run() {
  // Double check the output doesn't already exist early on, so we can prevent
  // doing work if it does.
  if (!output_file_.empty() &&
      base::PathExists(output_file_) &&
      !overwrite_) {
    LOG(ERROR) << "Output file \"" << output_file_.value()
               << "\" already exists.";
    return 1;
  }

  // Run the appropriate action.
  if (action_ == kCompile) {
    if (!RunCompileAction())
      return 1;
  } else {
    if (!RunSetAction())
      return 1;
  }

  return 0;
}

void GenFilterApp::PrintUsage(const CommandLine* command_line,
                           const base::StringPiece& message) const {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(),
            kUsageFormatStr,
            command_line->GetProgram().BaseName().value().c_str());
}

bool GenFilterApp::RunCompileAction() {
  FilterCompiler filter_compiler;

  if (!filter_compiler.Init(input_image_, input_pdb_))
    return false;

  for (size_t i = 0; i < inputs_.size(); ++i) {
    LOG(INFO) << "Parsing filter description file \"" << inputs_[i].value()
              << "\".";
    if (!filter_compiler.ParseFilterDescriptionFile(inputs_[i]))
      return false;
  }

  LOG(INFO) << "Compiling filter.";
  ImageFilter filter;
  if (!filter_compiler.Compile(&filter))
    return false;

  if (!OutputFilter(pretty_print_, output_file_, filter, out()))
    return false;

  return true;
}

bool GenFilterApp::RunSetAction() {
  // At this point we're handling set operations on JSON encoded filters. Load
  // them and make sure they're for the same module.
  std::vector<ImageFilter> filters(inputs_.size());
  for (size_t i = 0; i < inputs_.size(); ++i) {
    if (!filters[i].LoadFromJSON(inputs_[i])) {
      LOG(ERROR) << "Failed to load filter \"" << inputs_[i].value() << "\".";
      return false;
    }

    // If this is a second or subsequent filter ensure it's for the same module
    // as the first one.
    if (i > 0 && !filters[0].signature.IsConsistent(filters[i].signature)) {
      LOG(ERROR) << "Filter \"" << inputs_[i].value() << "\" is not consistent "
                 << "with filter \"" << inputs_[0].value() << "\".";
      return false;
    }
  }

  // Handle the 'invert' action. This is a unary set operator.
  if (action_ == kInvert) {
    // Invert in place.
    filters[0].filter.Invert(&filters[0].filter);
  } else {
    // Otherwise we're a binary set operator. We do the work in place in the
    // place of the first filter.
    for (size_t i = 1; i < inputs_.size(); ++i)
      ApplyBinarySetAction(action_, filters[0], filters[i], &filters[0]);
  }

  if (!OutputFilter(pretty_print_, output_file_, filters[0], out()))
    return false;

  return true;
}

}  // namespace genfilter
