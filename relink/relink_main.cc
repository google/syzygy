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

#include <iostream>
#include "base/at_exit.h"
#include "base/command_line.h"
#include "base/file_path.h"
#include "base/logging_win.h"
#include "base/string_number_conversions.h"
#include "syzygy/relink/order_relinker.h"
#include "syzygy/relink/random_relinker.h"
#include "syzygy/reorder/reorderer.h"

using relink::Relinker;
using relink::OrderRelinker;
using relink::RandomRelinker;

namespace {

// {E6FF7BFB-34FE-42a3-8993-1F477DC36247}
const GUID kRelinkLogProviderName = { 0xe6ff7bfb, 0x34fe, 0x42a3,
    { 0x89, 0x93, 0x1f, 0x47, 0x7d, 0xc3, 0x62, 0x47 } };

const char kUsage[] =
    "Usage: relink [options]\n"
    "  Required Options:\n"
    "    --input-dll=<path>   The input DLL to relink.\n"
    "    --output-dll=<path>  Output path for the rewritten DLL.\n"
    "  Optional Options:\n"
    "    --input-pdb=<path>   The PDB file associated with the input DLL.\n"
    "                         Default is inferred from input-dll.\n"
    "    --output-pdb=<path>  Output path for the rewritten PDB file.\n"
    "                         Default is inferred from output-dll.\n"
    "    --seed=<integer>     Randomly reorder based on the given seed.\n"
    "    --order-file=<path>  Reorder based on a JSON ordering file.\n"
    "    --no-metadata        Prevents the relinker from adding metadata\n"
    "                         to the output DLL.\n"
    "  Notes:\n"
    "    * The --seed and --order-file options are mutually exclusive\n"
    "    * If --order-file is specified, --input-dll is optional.\n";

int Usage(const char* message) {
  std::cerr << message << std::endl << kUsage;

  return 1;
}

bool ParsePadding(const std::wstring& value_str, size_t* out_value) {
  DCHECK(out_value != NULL);

  int temp;
  if (!base::StringToInt(value_str, &temp) ||
      temp < 0 ||
      static_cast<size_t>(temp) > Relinker::max_padding_length()) {
    return false;
  }

  *out_value = static_cast<size_t>(temp);
  return true;
}

bool ParseUInt32(const std::wstring& value_str, uint32* out_value) {
  DCHECK(out_value != NULL);
  return base::StringToInt(value_str, reinterpret_cast<int*>(out_value));
}

void GuessPdbPath(const FilePath& module_path, FilePath* pdb_path) {
  DCHECK(pdb_path != NULL);
  *pdb_path = module_path.ReplaceExtension(L"pdb");
}

}  // namespace

int main(int argc, char** argv) {
  base::AtExitManager at_exit_manager;
  CommandLine::Init(argc, argv);

  if (!logging::InitLogging(L"", logging::LOG_ONLY_TO_SYSTEM_DEBUG_LOG,
      logging::DONT_LOCK_LOG_FILE, logging::APPEND_TO_OLD_LOG_FILE,
      logging::ENABLE_DCHECK_FOR_NON_OFFICIAL_RELEASE_BUILDS)) {
    return 1;
  }
  logging::LogEventProvider::Initialize(kRelinkLogProviderName);

  CommandLine* cmd_line = CommandLine::ForCurrentProcess();
  DCHECK(cmd_line != NULL);

  FilePath input_dll_path = cmd_line->GetSwitchValuePath("input-dll");
  FilePath input_pdb_path = cmd_line->GetSwitchValuePath("input-pdb");
  FilePath output_dll_path = cmd_line->GetSwitchValuePath("output-dll");
  FilePath output_pdb_path = cmd_line->GetSwitchValuePath("output-pdb");
  FilePath order_file_path = cmd_line->GetSwitchValuePath("order-file");
  bool output_metadata = !cmd_line->HasSwitch("no-metadata");

  if (output_dll_path.empty()) {
    return Usage("You must specify --output-dll.");
  }

  // Ensure that we have an input-dll.
  bool have_order_file = cmd_line->HasSwitch("order-file");
  if (input_dll_path.empty()) {
    if (!have_order_file) {
      return Usage(
          "You must specify --input-dll if --order-file is not given.");
    }

    if (!reorder::Reorderer::Order::GetOriginalModulePath(
        order_file_path, &input_dll_path)) {
      LOG(ERROR) << "Unable to infer input-dll.";
      return false;
    }
    LOG(INFO) << "Inferring input DLL path from order file: "
        << input_dll_path.value();
  }

  // If explicit PDB paths are not provided, guess them.
  if (input_pdb_path.empty()) {
    GuessPdbPath(input_dll_path, &input_pdb_path);
    LOG(INFO) << "Inferring input PDB path from input DLL path: "
        << input_pdb_path.value();
  }
  if (output_pdb_path.empty()) {
    GuessPdbPath(output_dll_path, &output_pdb_path);
    LOG(INFO) << "Inferring output PDB path from output DLL path: "
        << output_pdb_path.value();
  }

  if (cmd_line->HasSwitch("seed") && cmd_line->HasSwitch("order-file")) {
    return Usage("The seed and order-file arguments are mutually exclusive");
  }

  uint32 seed = 0;
  std::wstring seed_str(cmd_line->GetSwitchValueNative("seed"));
  if (!seed_str.empty() && !ParseUInt32(seed_str, &seed)) {
    return Usage("Invalid seed value.");
  }

  size_t padding = 0;
  std::wstring padding_str(cmd_line->GetSwitchValueNative("padding"));
  if (!padding_str.empty() && !ParsePadding(padding_str, &padding)) {
    return Usage("Invalid padding value.");
  }

  // Log some info so we know what's about to happen.
  LOG(INFO) << "Input Image: " << input_dll_path.value();
  LOG(INFO) << "Input PDB: " << input_pdb_path.value();
  LOG(INFO) << "Output Image: " << output_dll_path.value();
  LOG(INFO) << "Output PDB: " << output_pdb_path.value();
  LOG(INFO) << "Padding Length: " << padding;
  if (!order_file_path.empty()) {
    LOG(INFO) << "Order File: " << (order_file_path.value().c_str());
  } else {
    LOG(INFO) << "Random Seed: " << seed;
  }

  // Relink the image with a new ordering.
  scoped_ptr<Relinker> relinker;
  if (!order_file_path.empty()) {
    relinker.reset(new OrderRelinker(order_file_path));
  } else {
    relinker.reset(new RandomRelinker(seed));
  }

  relinker->set_padding_length(padding);
  if (!relinker->Relink(input_dll_path,
                        input_pdb_path,
                        output_dll_path,
                        output_pdb_path,
                        output_metadata)) {
    return Usage("Unable to reorder the input image.");
  }

  return 0;
}
