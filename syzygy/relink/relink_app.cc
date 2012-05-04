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

#include "syzygy/relink/relink_app.h"

#include "base/logging_win.h"
#include "base/string_number_conversions.h"
#include "syzygy/block_graph/orderers/random_orderer.h"
#include "syzygy/pe/pe_relinker.h"
#include "syzygy/reorder/orderers/explicit_orderer.h"

namespace relink {

namespace {

const char kUsageFormatStr[] =
    "Usage: %ls [options]\n"
    "  Required Options:\n"
    "    --input-dll=<path>   The input DLL to relink.\n"
    "    --output-dll=<path>  Output path for the rewritten DLL.\n"
    "  Optional Options:\n"
    "    --input-pdb=<path>   The PDB file associated with the input DLL.\n"
    "                         Default is inferred from input-dll.\n"
    "    --no-metadata        Prevents the relinker from adding metadata\n"
    "                         to the output DLL.\n"
    "    --order-file=<path>  Reorder based on a JSON ordering file.\n"
    "    --output-pdb=<path>  Output path for the rewritten PDB file.\n"
    "                         Default is inferred from output-dll.\n"
    "    --overwrite          Allow output files to be overwritten.\n"
    "    --padding=<integer>  Add bytes of padding between blocks.\n"
    "    --seed=<integer>     Randomly reorder based on the given seed.\n"
    "  Notes:\n"
    "    * The --seed and --order-file options are mutually exclusive\n"
    "    * If --order-file is specified, --input-dll is optional.\n";

bool ParsePadding(const std::wstring& value_str, size_t* out_value) {
  DCHECK(out_value != NULL);

  int temp;
  if (!base::StringToInt(value_str, &temp) || temp < 0) {
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

bool RelinkApp::ParseCommandLine(const CommandLine* cmd_line) {
  input_dll_path_ = cmd_line->GetSwitchValuePath("input-dll");
  input_pdb_path_ = cmd_line->GetSwitchValuePath("input-pdb");
  output_dll_path_ = cmd_line->GetSwitchValuePath("output-dll");
  output_pdb_path_ = cmd_line->GetSwitchValuePath("output-pdb");
  order_file_path_ = cmd_line->GetSwitchValuePath("order-file");
  output_metadata_ = !cmd_line->HasSwitch("no-metadata");
  overwrite_ = cmd_line->HasSwitch("overwrite");

  // The --output-dll argument is required.
  if (output_dll_path_.empty()) {
    return Usage(cmd_line, "You must specify --output-dll.");
  }

  // Ensure that we have an input-dll, either explicity specified, or to be
  // taken from an order file.
  if (input_dll_path_.empty() && order_file_path_.empty()) {
    return Usage(
        cmd_line,
        "You must specify --input-dll if --order-file is not given.");
  }

  // Parse the random seed, if given. Note that the --seed and --order-file
  // arguments are mutually exclusive.
  if (cmd_line->HasSwitch("seed")) {
    if (cmd_line->HasSwitch("order-file")) {
      return Usage(cmd_line,
                   "The seed and order-file arguments are mutually exclusive");
    }
    std::wstring seed_str(cmd_line->GetSwitchValueNative("seed"));
    if (!ParseUInt32(seed_str, &seed_))
      return Usage(cmd_line, "Invalid seed value.");
  }

  // Parse the padding argument.
  if (cmd_line->HasSwitch("padding")) {
    std::wstring padding_str(cmd_line->GetSwitchValueNative("padding"));
    if (!ParsePadding(padding_str, &padding_))
      return Usage(cmd_line, "Invalid padding value.");
  }

  return true;
}

bool RelinkApp::SetUp() {
  if (input_dll_path_.empty()) {
    DCHECK(!order_file_path_.empty());
    if (!reorder::Reorderer::Order::GetOriginalModulePath(order_file_path_,
                                                          &input_dll_path_)) {
      LOG(ERROR) << "Unable to infer input-dll.";
      return false;
    }

    LOG(INFO) << "Inferring input DLL path from order file: "
              << input_dll_path_.value();
  }

  DCHECK(!input_dll_path_.empty());
  DCHECK(!output_dll_path_.empty());
  DCHECK(order_file_path_.empty() || seed_ == 0);

  return true;
}

int RelinkApp::Run() {
  pe::PERelinker relinker;
  relinker.set_input_path(input_dll_path_);
  relinker.set_input_pdb_path(input_pdb_path_);
  relinker.set_output_path(output_dll_path_);
  relinker.set_output_pdb_path(output_pdb_path_);
  relinker.set_padding(padding_);
  relinker.set_allow_overwrite(overwrite_);
  relinker.set_add_metadata(output_metadata_);

  // Initialize the relinker. This does the decomposition, etc.
  if (!relinker.Init()) {
    LOG(ERROR) << "Failed to initialize relinker.";
    return 1;
  }

  // Set up the orderer.
  scoped_ptr<block_graph::BlockGraphOrdererInterface> orderer;
  scoped_ptr<reorder::Reorderer::Order> order;
  if (!order_file_path_.empty()) {
    order.reset(new reorder::Reorderer::Order());
    if (!order->LoadFromJSON(relinker.input_pe_file(),
                             relinker.input_image_layout(),
                             order_file_path_)) {
      LOG(ERROR) << "Failed to load order file: " << order_file_path_.value();
      return 1;
    }

    orderer.reset(new reorder::orderers::ExplicitOrderer(order.get()));
  } else {
    orderer.reset(new block_graph::orderers::RandomOrderer(true, seed_));
  }

  // Append the orderer to the relinker.
  relinker.AppendOrderer(orderer.get());

  // Perform the actual relink.
  if (!relinker.Relink()) {
    LOG(ERROR) << "Unable to relink input image.";
    return 1;
  }

  return 0;
}

bool RelinkApp::Usage(const CommandLine* cmd_line,
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

}  // namespace relink
