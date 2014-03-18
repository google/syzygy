/* COMPILER() - the compiler being used to build the project */
#define COMPILER(WTF_FEATURE) (defined WTF_COMPILER_##WTF_FEATURE  && WTF_COMPILER_##WTF_FEATURE)

#define WTF_COMPILER_MSVC 1

#define ALWAYS_INLINE __forceinline
#define NEVER_INLINE __declspec(noinline)

// MSVC has no way mechanism for providing branch hints.
#define LIKELY(x) x
#define UNLIKELY(x) x
