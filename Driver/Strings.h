#pragma once

// Every string the driver uses at runtime, stored encoded so the plain text does not appear in Driver.sys.
// Decode each one where it is used, for example: EnumerateEProcess(Decode(UserExeName).data())
//
// Include this after PatternToBytes (Func.cpp) and after Crypt.cpp, which provide Encode and Decode.
// Debug messages (print(...)) are not listed here: print() compiles to nothing in release builds.

// The bytes that identify NtCompareSigningLevels in ntoskrnl (? is a wildcard)
constexpr auto Signature = Decode(PatternToBytes("4C 8B 05 ? ? ? ? 33 C0 4D 85 C0 74 ? 49 8B C0 E8 ? ? ? ? F7 D8"));

// Names searched for at runtime
constexpr auto UserExeName = Encode(L"User.exe");
constexpr auto NtoskrnlName = Encode("ntoskrnl.exe");
constexpr auto PageSectionName = Encode("PAGE");
