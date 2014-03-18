#include "config.h"

#include "wtf/PartitionAlloc.h"

#include <string.h>

static PartitionAllocatorGeneric partition;
static bool initialized;

extern "C" {

void* ctmalloc_malloc(size_t size)
{
    if (UNLIKELY(!initialized)) {
        initialized = true;
        partition.init();
    }
    return partitionAllocGeneric(partition.root(), size);
}

void ctmalloc_free(void* ptr)
{
    partitionFreeGeneric(partition.root(), ptr);
}

void* ctmalloc_realloc(void* ptr, size_t size)
{
    if (UNLIKELY(!initialized)) { 
        initialized = true;
        partition.init();
    }
    if (UNLIKELY(!ptr)) {
        return partitionAllocGeneric(partition.root(), size);
    }
    if (UNLIKELY(!size)) {
        partitionFreeGeneric(partition.root(), ptr);
        return 0;
    }
    return partitionReallocGeneric(partition.root(), ptr, size);
}

void* ctmalloc_calloc(size_t nmemb, size_t size)
{
    void* ret;
    size_t real_size = nmemb * size;
    if (UNLIKELY(!initialized)) { 
        initialized = true;
        partition.init();
    }
    RELEASE_ASSERT(!nmemb || real_size / nmemb == size);
    ret = partitionAllocGeneric(partition.root(), real_size);
    memset(ret, '\0', real_size);
    return ret;
}

}
