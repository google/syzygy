#ifndef WTF_COMPILER_H_
#define WTF_COMPILER_H_

/* COMPILER() - the compiler being used to build the project */
#define COMPILER(WTF_FEATURE) (defined WTF_COMPILER_##WTF_FEATURE  && WTF_COMPILER_##WTF_FEATURE)

#define WTF_COMPILER_MSVC 1

#define ALWAYS_INLINE __forceinline
#define NEVER_INLINE __declspec(noinline)

// MSVC has no way mechanism for providing branch hints.
#define LIKELY(x) (x)
// This is now defined by base/compiler_specific.h, so be careful not
// to redefine it.
#ifndef UNLIKELY
#define UNLIKELY(x) (x)
#endif

#endif  // WTF_COMPILER_H_
