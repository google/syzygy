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

#include "syzygy/assm/register.h"

#include "gtest/gtest.h"

namespace assm {

TEST(RegisterTest, AllViewsOccupySameMemory) {
  // We expect the by-type arrays to be slices of the full register array.
  EXPECT_EQ(reinterpret_cast<const Register*>(&kRegisters8[0]),
            &kRegisters[kRegister8Min]);
  EXPECT_EQ(reinterpret_cast<const Register*>(&kRegisters16[0]),
            &kRegisters[kRegister16Min]);
  EXPECT_EQ(reinterpret_cast<const Register*>(&kRegisters32[0]),
            &kRegisters[kRegister32Min]);

  // We expect the individual registers to be members of the full register
  // array.
  EXPECT_EQ(reinterpret_cast<const Register*>(&al), &kRegisters[kRegisterAl]);
  EXPECT_EQ(reinterpret_cast<const Register*>(&ch), &kRegisters[kRegisterCh]);

  EXPECT_EQ(reinterpret_cast<const Register*>(&dx), &kRegisters[kRegisterDx]);
  EXPECT_EQ(reinterpret_cast<const Register*>(&sp), &kRegisters[kRegisterSp]);

  EXPECT_EQ(reinterpret_cast<const Register*>(&ebx), &kRegisters[kRegisterEbx]);
  EXPECT_EQ(reinterpret_cast<const Register*>(&ebp), &kRegisters[kRegisterEbp]);
}

TEST(RegisterTest, Accessors) {
  EXPECT_EQ(kRegisterEax, eax.id());
  EXPECT_EQ(kSize32Bit, eax.size());
  EXPECT_EQ(0, eax.code());
}

TEST(RegisterTest, Get) {
  EXPECT_EQ(reinterpret_cast<const Register*>(&ch),
            &Register::Get(kRegisterCh));
  EXPECT_EQ(reinterpret_cast<const Register*>(&bx),
            &Register::Get(kRegisterBx));
  EXPECT_EQ(reinterpret_cast<const Register*>(&eax),
            &Register::Get(kRegisterEax));
}

TEST(RegisterTest, Comparison) {
  EXPECT_TRUE(dh == dh);
  EXPECT_TRUE(sp == sp);
  EXPECT_TRUE(eax == eax);

  EXPECT_FALSE(al == ax);
  EXPECT_FALSE(al == eax);
  EXPECT_FALSE(ax == eax);

  EXPECT_TRUE(al != ax);
  EXPECT_TRUE(al != eax);
  EXPECT_TRUE(ax != eax);

  EXPECT_FALSE(dh != dh);
  EXPECT_FALSE(sp != sp);
  EXPECT_FALSE(eax != eax);
}

}  // namespace assm
