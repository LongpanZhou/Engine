#pragma once
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wsign-conversion"
#pragma clang diagnostic ignored "-Wnested-anon-types"
#pragma clang diagnostic ignored "-Wgnu-anonymous-struct"

//LOG
#define INFO(msg)	"[*]" msg "\n"
#define OK(msg)		"[+]" msg "\n"
#define WARN(msg)	"[!]" msg "\n"
#define ERROR(msg)	"[-]" msg "\n"


//PRINT FUNC
#define DEBUG

#ifdef DEBUG
// PRINT FUNC for debug mode
template <typename... T>
__forceinline void print(const char* fmt, T... args)
{
    win::print_ex(0, 0, fmt, args...);
}
#else
// No-op in release mode
template <typename... T>
__forceinline void print(const char*, T...)
{
    // Do nothing in release mode
}
#endif