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

#include "syzygy/pdb/pdb_symbol_record_stream.h"

#include "base/file_util.h"
#include "gtest/gtest.h"
#include "syzygy/core/unittest_util.h"
#include "syzygy/pdb/cvinfo_ext.h"
#include "syzygy/pdb/pdb_byte_stream.h"
#include "syzygy/pdb/unittest_util.h"
#include "syzygy/pe/unittest_util.h"

namespace pdb {

namespace cci = Microsoft_Cci_Pdb;

const uint16 array_of_symbol_types[] = {
    cci::S_OEM,
    cci::S_REGISTER_ST,
    cci::S_CONSTANT_ST,
    cci::S_UDT_ST,
    cci::S_COBOLUDT_ST,
    cci::S_MANYREG_ST,
    cci::S_BPREL32_ST,
    cci::S_LDATA32_ST,
    cci::S_GDATA32_ST,
    cci::S_PUB32_ST,
    cci::S_LPROC32_ST,
    cci::S_GPROC32_ST,
    cci::S_VFTABLE32,
    cci::S_REGREL32_ST,
    cci::S_LTHREAD32_ST,
    cci::S_GTHREAD32_ST,
    cci::S_LPROCMIPS_ST,
    cci::S_GPROCMIPS_ST,
    cci::S_FRAMEPROC,
    cci::S_COMPILE2_ST,
    cci::S_MANYREG2_ST,
    cci::S_LPROCIA64_ST,
    cci::S_GPROCIA64_ST,
    cci::S_LOCALSLOT_ST,
    cci::S_PARAMSLOT_ST,
    cci::S_ANNOTATION,
    cci::S_GMANPROC_ST,
    cci::S_LMANPROC_ST,
    cci::S_RESERVED1,
    cci::S_RESERVED2,
    cci::S_RESERVED3,
    cci::S_RESERVED4,
    cci::S_LMANDATA_ST,
    cci::S_GMANDATA_ST,
    cci::S_MANFRAMEREL_ST,
    cci::S_MANREGISTER_ST,
    cci::S_MANSLOT_ST,
    cci::S_MANMANYREG_ST,
    cci::S_MANREGREL_ST,
    cci::S_MANMANYREG2_ST,
    cci::S_MANTYPREF,
    cci::S_UNAMESPACE_ST,
    cci::S_ST_MAX,
    cci::S_OBJNAME,
    cci::S_THUNK32,
    cci::S_BLOCK32,
    cci::S_WITH32,
    cci::S_LABEL32,
    cci::S_REGISTER,
    cci::S_CONSTANT,
    cci::S_UDT,
    cci::S_COBOLUDT,
    cci::S_MANYREG,
    cci::S_BPREL32,
    cci::S_LDATA32,
    cci::S_GDATA32,
    cci::S_PUB32,
    cci::S_LPROC32,
    cci::S_GPROC32,
    cci::S_REGREL32,
    cci::S_LTHREAD32,
    cci::S_GTHREAD32,
    cci::S_LPROCMIPS,
    cci::S_GPROCMIPS,
    cci::S_COMPILE2,
    cci::S_MANYREG2,
    cci::S_LPROCIA64,
    cci::S_GPROCIA64,
    cci::S_LOCALSLOT,
    cci::S_PARAMSLOT,
    cci::S_LMANDATA,
    cci::S_GMANDATA,
    cci::S_MANFRAMEREL,
    cci::S_MANREGISTER,
    cci::S_MANSLOT,
    cci::S_MANMANYREG,
    cci::S_MANREGREL,
    cci::S_MANMANYREG2,
    cci::S_UNAMESPACE,
    cci::S_PROCREF,
    cci::S_DATAREF,
    cci::S_LPROCREF,
    cci::S_ANNOTATIONREF,
    cci::S_TOKENREF,
    cci::S_GMANPROC,
    cci::S_LMANPROC,
    cci::S_TRAMPOLINE,
    cci::S_MANCONSTANT,
    cci::S_ATTR_FRAMEREL,
    cci::S_ATTR_REGISTER,
    cci::S_ATTR_REGREL,
    cci::S_ATTR_MANYREG,
    cci::S_SEPCODE,
    cci::S_LOCAL,
    cci::S_DEFRANGE,
    cci::S_DEFRANGE2,
    cci::S_SECTION,
    cci::S_COFFGROUP,
    cci::S_EXPORT,
    cci::S_CALLSITEINFO,
    cci::S_FRAMECOOKIE,
    cci::S_DISCARDED,
    cci::S_RECTYPE_MAX
};

TEST(PdbReadSymbolRecordTest, ReadValidSymRecordStream) {
  FilePath valid_sym_record_path = testing::GetSrcRelativePath(
      testing::kValidPDBSymbolRecordStreamPath);

  scoped_refptr<pdb::PdbFileStream> valid_sym_record_stream =
      testing::GetStreamFromFile(valid_sym_record_path);
  SymbolRecordVector symbol_vector;
  EXPECT_TRUE(ReadSymbolRecord(valid_sym_record_stream.get(), &symbol_vector));
}

TEST(PdbReadSymbolRecordTest, ReadInvalidSymRecordStream) {
  FilePath invalid_sym_record_path = testing::GetSrcRelativePath(
      testing::kInvalidPDBSymbolRecordStreamPath);

  scoped_refptr<pdb::PdbFileStream> invalid_sym_record_stream =
      testing::GetStreamFromFile(invalid_sym_record_path);
  SymbolRecordVector symbol_vector;
  EXPECT_FALSE(ReadSymbolRecord(invalid_sym_record_stream.get(),
                                &symbol_vector));
}

class PdbDumpSymbolRecordTest : public testing::Test {
 public:
  virtual void SetUp() OVERRIDE {
    FilePath stdout_path;
    ASSERT_TRUE(file_util::CreateTemporaryFile(&stdout_path));
    out_ = new RefCountedFILE(file_util::OpenFile(stdout_path, "w"));
    stream_ = new PdbByteStream();
    writable_stream_ = stream_->GetWritablePdbStream();
    ASSERT_TRUE(writable_stream_ != NULL);
  }

 protected:
  scoped_refptr<RefCountedFILE> out_;
  scoped_refptr<PdbByteStream> stream_;
  scoped_refptr<WritablePdbStream> writable_stream_;
};

TEST_F(PdbDumpSymbolRecordTest, DumpInvalidSymbols) {
  // The minimal data size for a non-empty symbol record block is 2 bytes (only
  // the type ID).
  const uint16 symbol_record_length = 2;
  writable_stream_->Write(symbol_record_length);

  // Iterate over each symbol record type and update the stream each time.
  for (uint16 i = 0; i < sizeof(array_of_symbol_types); ++i) {
    writable_stream_->set_pos(sizeof(symbol_record_length));
    writable_stream_->Write(array_of_symbol_types[i]);
    SymbolRecordVector symbol_vector;
    EXPECT_TRUE(ReadSymbolRecord(stream_.get(), &symbol_vector));
    DumpSymbolRecord(out_->file(), stream_.get(), symbol_vector);
  }
}

}  // namespace pdb
