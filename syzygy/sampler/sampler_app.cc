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

#include "syzygy/sampler/sampler_app.h"

namespace sampler {

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls\n"
    "\n"
    "  A tool that polls running processes and profiles modules of interest.\n"
    "\n";

}  // namespace

SamplerApp::SamplerApp() : common::AppImplBase("Sampler") {
}

bool SamplerApp::ParseCommandLine(const CommandLine* command_line) {
  DCHECK(command_line != NULL);

  // TODO(chrisha): Implement me!
  return PrintUsage(command_line->GetProgram(), "Not yet implemented!");
}

int SamplerApp::Run() {
  // TODO(chrisha): Implement me!
  return 1;
}

bool SamplerApp::PrintUsage(const base::FilePath& program,
                            const base::StringPiece& message) {
  if (!message.empty()) {
    ::fwrite(message.data(), 1, message.length(), out());
    ::fprintf(out(), "\n\n");
  }

  ::fprintf(out(), kUsageFormatStr, program.BaseName().value().c_str());

  return false;
}

}  // namespace sampler
