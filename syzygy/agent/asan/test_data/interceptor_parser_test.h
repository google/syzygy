VOID
WINAPI
valid_function1(
    type1 param1,
    type2 param2,
    type3 param3
    );
BOOL
WINAPI
valid_function2(
    _In_ type1 param1[],
     _Out_writes_bytes_opt_(nNumberOfBytesToRead)
         __out_data_source(FILE) LPVOID lpBuffer,
    _Inout_opt_ type3 param3,
    );
int
WINAPI
valid_function3(void foo);
BOOL
invalid_function1(
    type1 param1,
    type2 param2,
    type3 param3
    );
BOOL
WINAPI
#ifdef FOO
invalid_function2(
else
invalid_function2(
#endif
    type1 param1
    );
BOOL
invalid_function3(
    type1 param1,
WINAPI
invalid_function4(
    type1 param1
    );