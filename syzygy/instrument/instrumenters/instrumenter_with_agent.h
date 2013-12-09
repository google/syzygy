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
// Specialization of the instrumenter interface for the instrumenters who use an
// agent. This performs all the common bits of this kind of instrumenters:
//     - Parse the shared command-line parameters.
//     - Initialization the relinker.
//     - Default implementation of Instrument.
#ifndef  SYZYGY_INSTRUMENT_INSTRUMENTERS_INSTRUMENTER_WITH_AGENT_H_
#define  SYZYGY_INSTRUMENT_INSTRUMENTERS_INSTRUMENTER_WITH_AGENT_H_

#include <string>

#include "base/command_line.h"
#include "syzygy/instrument/instrumenter.h"
#include "syzygy/pe/coff_relinker.h"
#include "syzygy/pe/pe_relinker.h"

namespace instrument {
namespace instrumenters {

class InstrumenterWithAgent : public InstrumenterInterface {
 public:
  InstrumenterWithAgent()
      : image_format_(pe::PE_IMAGE),
        allow_overwrite_(false),
        debug_friendly_(false),
        no_augment_pdb_(false),
        no_strip_strings_(false),
        old_decomposer_(false) {
  }

  ~InstrumenterWithAgent() { }

  // @name InstrumenterInterface implementation.
  // @{
  virtual bool ParseCommandLine(const CommandLine* command_line) OVERRIDE;
  virtual bool Instrument() OVERRIDE;
  // @}

  // @name Accessors.
  // @
  const std::string& agent_dll() {
    return agent_dll_;
  }
  // @}

 protected:
  // Virtual method that determines whether or not the input object file
  // format is supported by the instrumenter. The default implementation
  // supports PE files, and does not support COFF files.
  virtual bool ImageFormatIsSupported(pe::ImageFormat image_format);

  // Virtual method that does the actual instrumentation for a given agent.
  // This function is meant to be called by the Instrument function.
  // @note The implementation should log on failure.
  virtual bool InstrumentImpl() = 0;

  // Pure virtual method that should return the name of the instrumentation
  // mode.
  virtual const char* InstrumentationMode() = 0;

  // Virtual method called by ParseCommandLine to parse the additional
  // command-line arguments specific to an instrumenter.
  // @param command_line the command-line to be parsed.
  // @returns true by default. Should return false on error.
  virtual bool ParseAdditionalCommandLineArguments(
     const CommandLine* command_line) {
    return true;
  }

  // @name Internal machinery, replaceable for testing purposes. These will
  //     only ever be called once per object lifetime.
  // @{
  virtual pe::PETransformPolicy* GetPETransformPolicy();
  virtual pe::CoffTransformPolicy* GetCoffTransformPolicy();
  virtual pe::PERelinker* GetPERelinker();
  virtual pe::CoffRelinker* GetCoffRelinker();
  // @}

  // Creates and configures a relinker. This is split out for unittesting
  // purposes, allowing child classes to test their InstrumentImpl functions
  // in isolation.
  bool CreateRelinker();

  // The agent DLL used by this instrumentation.
  std::string agent_dll_;

  // The type of image file we are transforming.
  pe::ImageFormat image_format_;

  // @name Command-line parameters.
  // @{
  base::FilePath input_image_path_;
  base::FilePath input_pdb_path_;
  base::FilePath output_image_path_;
  base::FilePath output_pdb_path_;
  bool allow_overwrite_;
  bool debug_friendly_;
  bool no_augment_pdb_;
  bool no_strip_strings_;
  bool old_decomposer_;
  // @}

  // This is used to save a pointer to the object returned by the call to
  // Get(PE|Coff)Relinker. Ownership of the object is internal in the default
  // case, but may be external during tests.
  pe::RelinkerInterface* relinker_;

 private:
  // They are used as containers for holding policy and relinker objects that
  // are allocated by our default Get* implementations above.
  scoped_ptr<block_graph::TransformPolicyInterface> policy_object_;
  scoped_ptr<pe::RelinkerInterface> relinker_object_;

  DISALLOW_COPY_AND_ASSIGN(InstrumenterWithAgent);
};

}  // namespace instrumenters
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_INSTRUMENTER_WITH_AGENT_H_
