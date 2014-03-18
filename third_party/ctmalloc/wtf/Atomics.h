/*
 * Copyright (C) 2007, 2008, 2010, 2012 Apple Inc. All rights reserved.
 * Copyright (C) 2007 Justin Haygood (jhaygood@reaktix.com)
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1.  Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 * 2.  Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in the
 *     documentation and/or other materials provided with the distribution.
 * 3.  Neither the name of Apple Computer, Inc. ("Apple") nor the names of
 *     its contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY APPLE AND ITS CONTRIBUTORS "AS IS" AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL APPLE OR ITS CONTRIBUTORS BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef Atomics_h
#define Atomics_h

#include "wtf/Assertions.h"

#include <stdint.h>

#if COMPILER(MSVC)
#include <windows.h>
#endif

namespace WTF {

#if COMPILER(MSVC)

// atomicAdd returns the result of the addition.
ALWAYS_INLINE int atomicAdd(int volatile* addend, int increment)
{
    return InterlockedExchangeAdd(reinterpret_cast<long volatile*>(addend), static_cast<long>(increment)) + increment;
}

// atomicSubtract returns the result of the subtraction.
ALWAYS_INLINE int atomicSubtract(int volatile* addend, int decrement)
{
    return InterlockedExchangeAdd(reinterpret_cast<long volatile*>(addend), static_cast<long>(-decrement)) - decrement;
}

ALWAYS_INLINE int atomicIncrement(int volatile* addend) { return InterlockedIncrement(reinterpret_cast<long volatile*>(addend)); }
ALWAYS_INLINE int atomicDecrement(int volatile* addend) { return InterlockedDecrement(reinterpret_cast<long volatile*>(addend)); }

ALWAYS_INLINE int64_t atomicIncrement(int64_t volatile* addend) { return InterlockedIncrement64(reinterpret_cast<long long volatile*>(addend)); }
ALWAYS_INLINE int64_t atomicDecrement(int64_t volatile* addend) { return InterlockedDecrement64(reinterpret_cast<long long volatile*>(addend)); }

ALWAYS_INLINE int atomicTestAndSetToOne(int volatile* ptr)
{
    int ret = InterlockedExchange(reinterpret_cast<long volatile*>(ptr), 1);
    ASSERT(!ret || ret == 1);
    return ret;
}

ALWAYS_INLINE void atomicSetOneToZero(int volatile* ptr)
{
    ASSERT(*ptr == 1);
    InterlockedExchange(reinterpret_cast<long volatile*>(ptr), 0);
}

#else

// atomicAdd returns the result of the addition.
ALWAYS_INLINE int atomicAdd(int volatile* addend, int increment) { return __sync_add_and_fetch(addend, increment); }
// atomicSubtract returns the result of the subtraction.
ALWAYS_INLINE int atomicSubtract(int volatile* addend, int decrement) { return __sync_sub_and_fetch(addend, decrement); }

ALWAYS_INLINE int atomicIncrement(int volatile* addend) { return atomicAdd(addend, 1); }
ALWAYS_INLINE int atomicDecrement(int volatile* addend) { return atomicSubtract(addend, 1); }

ALWAYS_INLINE int64_t atomicIncrement(int64_t volatile* addend) { return __sync_add_and_fetch(addend, 1); }
ALWAYS_INLINE int64_t atomicDecrement(int64_t volatile* addend) { return __sync_sub_and_fetch(addend, 1); }

ALWAYS_INLINE int atomicTestAndSetToOne(int volatile* ptr)
{
    int ret = __sync_lock_test_and_set(ptr, 1);
    ASSERT(!ret || ret == 1);
    return ret;
}

ALWAYS_INLINE void atomicSetOneToZero(int volatile* ptr)
{
    ASSERT(*ptr == 1);
    __sync_lock_release(ptr);
}

#endif

} // namespace WTF

using WTF::atomicAdd;
using WTF::atomicSubtract;
using WTF::atomicDecrement;
using WTF::atomicIncrement;
using WTF::atomicTestAndSetToOne;
using WTF::atomicSetOneToZero;

#endif // Atomics_h
