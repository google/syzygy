// Copyright 2012 Google Inc.
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

#include "syzygy/grinder/grinder_app.h"

#include "base/file_util.h"
#include "base/logging.h"
#include "base/stringprintf.h"
#include "syzygy/grinder/profile_grinder.h"

namespace grinder {

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls <trace files> [options]\n"
    "\n"
    "  A tool that parses trace files and produces summary output.\n"
    "\n"
    "  In 'profile' mode it outputs KCacheGrind-compatible output files for\n"
    "  visualization.\n"
    "\n"
    "  In 'coverage' mode it outputs GCOV/LCOV-compatible output files for\n"
    "  further processing with code coverage visualization tools.\n"
    "\n"
    "Required parameters\n"
    "  --mode=<mode>\n"
    "    The processing mode. Must be one of 'profile' or 'coverage'.\n"
    "Optional parameters\n"
    "  --output-file=<output file>\n"
    "    The location of output file. If not specified, output is to stdout.\n";

}  // namespace

GrinderApp::GrinderApp() : common::AppImplBase("Grinder"), mode_(kProfile) {
}

void GrinderApp::PrintUsage(const FilePath& program,
                            const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());
}

bool GrinderApp::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);

  CommandLine::StringVector args = command_line->GetArgs();
  if (args.empty()) {
    PrintUsage(command_line->GetProgram(),
               "You must provide at least one trace file.");
    return false;
  }

  if (!command_line->HasSwitch("mode")) {
    PrintUsage(command_line->GetProgram(),
               "You must specify the processing mode.");
    return false;
  }

  for (size_t i = 0; i < args.size(); ++i) {
    if (!ExpandArgument(FilePath(args[i]))) {
      PrintUsage(command_line->GetProgram(),
                 base::StringPrintf("No such file '%ws'.", args[i].c_str()));
      return false;
    }
  }

  // Parse the processing mode.
  std::string mode = command_line->GetSwitchValueASCII("mode");
  if (mode == "profile") {
    mode_ = kProfile;
  } else if (mode == "coverage") {
    mode_ = kCoverage;
    PrintUsage(command_line->GetProgram(), "Coverage mode not yet supported.");
    return false;
  } else {
    PrintUsage(command_line->GetProgram(),
               base::StringPrintf("Unknown mode: %s.", mode.c_str()));
    return false;
  }

  output_file_ = command_line->GetSwitchValuePath("output-file");

  return true;
}

int GrinderApp::Run() {
  // We currently only support profile mode.
  DCHECK_EQ(kProfile, mode_);

  grinder::ProfileGrinder profile_grinder;
  trace::parser::Parser parser;

  profile_grinder.set_parser(&parser);
  if (!parser.Init(&profile_grinder))
    return 1;

  // Open the input files.
  for (size_t i = 0; i < trace_files_.size(); ++i) {
    if (!parser.OpenTraceFile(trace_files_[i])) {
      LOG(ERROR) << "Unable to open trace file \'"
                 << trace_files_[i].value() << "'";
      return 1;
    }
  }

  // Open the output file. We do this early so as to fail before processing
  // the logs if the output is not able to be opened.
  FILE* output = out();
  file_util::ScopedFILE auto_close;
  if (!output_file_.empty()) {
    output = file_util::OpenFile(output_file_, "w");
    if (output == NULL) {
      LOG(ERROR) << "Unable to create output file \'"
                 << output_file_.value() << "'";
      return 1;
    }

    auto_close.reset(output);
  }

  if (!parser.Consume()) {
    LOG(ERROR) << "Error parsing trace files.";
    return 1;
  }

  if (!profile_grinder.ResolveCallers()) {
    LOG(ERROR) << "Error resolving callers.";
    return 1;
  }

  DCHECK(output != NULL);
  if (!profile_grinder.OutputData(output)) {
    LOG(ERROR) << "Error writing output.";
    return 1;
  }

  return 0;
}

bool GrinderApp::ExpandArgument(const FilePath& path) {
  bool success = false;

  // Whether the path is an existing file or not, we expand it as a glob.
  // If it's a file, it'll match itself and nothing else.
  file_util::FileEnumerator files(path.DirName(),
                                  false,
                                  file_util::FileEnumerator::FILES,
                                  path.BaseName().value());
  while (true) {
    FilePath file = files.Next();
    if (file.empty())
      break;

    success = true;
    trace_files_.push_back(file);
  }

  return success;
}

}  // namespace grinder
