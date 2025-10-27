#ifndef ADDONS_H
#define ADDONS_H

#include <windows.h>
#include <shlwapi.h>

#define REG_KEY_NAME "PEAnalyzer"

char* ConvertWcharToUtf8(WCHAR* wideString);
WCHAR* ConvertUtf8ToWchar(char* utf8String);
int enable_integration_for_type(const char* fileType, const char* exePath);
int disable_integration_for_type(const char* fileType);
int is_integration_enabled_for_type(const char* fileType);
int is_integration_enabled_all();
int enable_integration_all();
int disable_integration_all();

#endif