#include "base/logging.h"
#include "wtf/Compiler.h"

#define IMMEDIATE_CRASH() NOTREACHED()

#define ASSERT(assertion) DCHECK(assertion)

#define RELEASE_ASSERT(assertion) CHECK(assertion)
