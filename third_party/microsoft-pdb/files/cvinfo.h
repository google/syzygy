///////////////////////////////////////////////////////////////////////////////
//
// Copyright (c) 2015 Microsoft Corporation. All rights reserved.
//
// This code is licensed under the MIT License (MIT).
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.
//
///////////////////////////////////////////////////////////////////////////////

#ifndef THIRD_PARTY_MICROSOFT_PDB_FILES_CVINFO_H_
#define THIRD_PARTY_MICROSOFT_PDB_FILES_CVINFO_H_

namespace Microsoft_Cci_Pdb {

// Ranges for en-registered symbol.
const uint16_t S_DEFRANGE_REGISTER = 0x1141;
// Range for stack symbol.
const uint16_t S_DEFRANGE_FRAMEPOINTER_REL = 0x1142;
// Ranges for en-registered field of symbol.
const uint16_t S_DEFRANGE_SUBFIELD_REGISTER = 0x1143;
// Range for stack symbol span valid full scope of function body, gap might
// apply. Provides the frame pointer offset for the S_LOCAL_VS2013 variables.
const uint16_t S_DEFRANGE_FRAMEPOINTER_REL_FULL_SCOPE = 0x1144;
// Range for symbol address as register + offset.
const uint16_t S_DEFRANGE_REGISTER_REL = 0x1145;

// Inlined function callsite.
const uint16_t S_INLINESITE = 0x114d;
const uint16_t S_INLINESITE_END = 0x114e;

}  // namespace Microsoft_Cci_Pdb

// All of the data structures below need to have tight alignment so that they
// can be overlaid directly onto byte streams.
#pragma pack(push, 1)

// Represents an address range, used for optimized code debug info.
struct CvLvarAddrRange {
  uint32_t offStart;
  uint16_t isectStart;
  uint16_t cbRange;  // Length.
};
COMPILE_ASSERT_IS_POD_OF_SIZE(CvLvarAddrRange, 8);

// Represents the holes in overall address range, all address is pre-bbt.
// It is for compress and reduce the amount of relocations need.
struct CvLvarAddrGap {
  uint16_t gapStartOffset;  // Relative offset from beginning of live range.
  uint16_t cbRange;  // Length of gap.
};
COMPILE_ASSERT_IS_POD_OF_SIZE(CvLvarAddrGap, 4);

// Attributes of a variable's range.
union CvRangeAttr {
  uint16_t raw;
  struct {
    uint16_t maybe : 1;  // May have no user name on one of control flow path.
    uint16_t padding : 15;  // Padding for future use.
  };
};
// We coerce a stream of bytes to this structure, so we require it to be
// exactly 2 bytes in size.
COMPILE_ASSERT_IS_POD_OF_SIZE(CvRangeAttr, 2);

// A live range of en-registed variable.
struct DefrangeSymRegister {
  uint16_t reg;             // Register to hold the value of the symbol
  CvRangeAttr attr;       // Attribute of the register range.
  CvLvarAddrRange range;  // Range of addresses where this program is valid.
  CvLvarAddrGap gaps[1];  // The value is not available in following gaps.
};
COMPILE_ASSERT_IS_POD_OF_SIZE(DefrangeSymRegister, 16);

// A live range of frame variable.
struct DefRangeSymFramePointerRel {
  int32_t offFramePointer;  // Offset to frame pointer.
  CvLvarAddrRange range;   // Range of addresses where this program is valid.
  CvLvarAddrGap gaps[1];   // The value is not available in following gaps.
};
COMPILE_ASSERT_IS_POD_OF_SIZE(DefRangeSymFramePointerRel, 16);

// Ranges for en-registered field of symbol.
struct DefRangeSymSubfieldRegister {
  uint16_t reg;             // Register to hold the value of the symbol
  CvRangeAttr attr;       // Attribute of the register range.
  uint32_t offParent : 12;  // Offset in parent variable.
  uint32_t padding : 20;    // Padding for future use.
  CvLvarAddrRange range;  // Range of addresses where this program is valid.
  CvLvarAddrGap gaps[1];  // The value is not available in following gaps.
};
COMPILE_ASSERT_IS_POD_OF_SIZE(DefRangeSymSubfieldRegister, 20);

// Inlined function callsite.
struct InlineSiteSym {
  uint32_t pParent;              // Pointer to the inliner.
  uint32_t pEnd;                 // Pointer to this block's end.
  uint32_t inlinee;              // CV_ItemId of inlinee.
  uint8_t binaryAnnotations[1];  // An array of compressed binary annotations.
};
COMPILE_ASSERT_IS_POD_OF_SIZE(InlineSiteSym, 13);

#pragma pack(pop)

#endif  // THIRD_PARTY_MICROSOFT_PDB_FILES_CVINFO_H_
