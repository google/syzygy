// Copyright 2014 Google Inc. All Rights Reserved.
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
// Instrumentation adapter that adds archive support to any existing
// instrumenter. Takes care of instantiating a new instance of the
// underlying instrumenter for each file in the archive. When not processing
// an archive simply passes through the original instrumenter.
//
// This presumes that the underlying instrumenter uses --input-image and
// --output-image for configuring which files are operated on.

#ifndef SYZYGY_INSTRUMENT_INSTRUMENTERS_ARCHIVE_INSTRUMENTER_H_
#define SYZYGY_INSTRUMENT_INSTRUMENTERS_ARCHIVE_INSTRUMENTER_H_

#include "base/logging.h"
#include "base/files/file_path.h"
#include "base/memory/scoped_ptr.h"
#include "syzygy/ar/ar_common.h"
#include "syzygy/instrument/instrumenter.h"

namespace instrument {
namespace instrumenters {

class ArchiveInstrumenter : public InstrumenterInterface {
 public:
  typedef InstrumenterInterface* (*InstrumenterFactoryFunction)();

  // Constructor.
  ArchiveInstrumenter();
  explicit ArchiveInstrumenter(InstrumenterFactoryFunction factory);

  // @name Accessors.
  // @{
  // @returns the factory function being used by this instrumenter
  //     adapter.
  InstrumenterFactoryFunction factory() const { return factory_; }
  // @}

  // @name Mutators.
  // @{
  void set_factory(InstrumenterFactoryFunction factory) {
    DCHECK_NE(reinterpret_cast<InstrumenterFactoryFunction>(NULL), factory);
    factory_ = factory;
  }
  // @}

  // @name InstrumenterInterface implementation.
  virtual bool ParseCommandLine(const CommandLine* command_line) OVERRIDE;
  virtual bool Instrument() OVERRIDE;
  // @}

 private:
  // Determines if we're processing an archive file or not.
  bool ProcessingArchive() const;
  // Passes through to the underlying instrumenter.
  bool InstrumentPassthrough();
  // Instruments an archive.
  bool InstrumentArchive();
  // Callback for the ArTransform object. This is invoked for each file in an
  // archive.
  bool InstrumentFile(const base::FilePath& input_path,
                      const base::FilePath& output_path,
                      ar::ParsedArFileHeader* header,
                      bool* remove);

  // The factory function that is used to produce instrumenter instances.
  InstrumenterFactoryFunction factory_;

  // A copy of the command-line that we originally parsed.
  scoped_ptr<CommandLine> command_line_;

  // Bits of the command-line that we've parsed.
  base::FilePath input_image_;
  base::FilePath output_image_;
  bool overwrite_;

  DISALLOW_COPY_AND_ASSIGN(ArchiveInstrumenter);
};

}  // namespace instrumenters
}  // namespace instrument

#endif  // SYZYGY_INSTRUMENT_INSTRUMENTERS_ARCHIVE_INSTRUMENTER_H_
