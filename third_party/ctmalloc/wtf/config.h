#include <stddef.h>

/* OS() - underlying operating system; only to be used for mandated low-level services like
   virtual memory, not to choose a GUI toolkit */
#define OS(WTF_FEATURE) (defined WTF_OS_##WTF_FEATURE  && WTF_OS_##WTF_FEATURE)

#define WTF_OS_WIN 1

// Defining this causes CTMalloc to use an LRU freelist, which allows memory to
// sit as long as possible before being reused.
#define CTMALLOC_LRU_FREELIST
