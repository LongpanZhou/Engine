// Client-only entry point: links PostboxClient.cpp without the old shared-memory client
// in main.cpp. Use this for a deployment binary; User.exe remains the dual-client test harness.
#include <windows.h>

int PostboxClientMain(int argc, char** argv);

int main(int argc, char** argv)
{
    return PostboxClientMain(argc, argv);
}
