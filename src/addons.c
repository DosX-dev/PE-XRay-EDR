#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <locale.h>
#include "../include/addons.h"

#define UNICODE
#define _UNICODE

char* ConvertWcharToUtf8(WCHAR* wideString) // Converting from UTF-16 to UTF-8
{
    if (wideString == NULL) {
        return NULL;
    }

    int requiredSize = WideCharToMultiByte(
        CP_UTF8,
        0,
        wideString,
        -1,
        NULL,
        0,
        NULL,
        NULL
    );

    if (requiredSize == 0) {
        return NULL;
    }

    char* utf8String = (char*)malloc(requiredSize);
    if (utf8String == NULL) {
        return NULL;
    }

    int result = WideCharToMultiByte(
        CP_UTF8,
        0,
        wideString,
        -1,
        utf8String,
        requiredSize,
        NULL,
        NULL
    );

    if (result == 0) {
        free(utf8String);
        return NULL;
    }

    return utf8String;
}

WCHAR* ConvertUtf8ToWchar(char* utf8String) // Converting from UTF-8 to UTF-16 
{
    if (utf8String == NULL) {
        return NULL;
    }

    int requiredSize = MultiByteToWideChar(
        CP_UTF8,
        0,
        utf8String,
        -1,
        NULL,
        0
    );

    if (requiredSize == 0) {
        return NULL;
    }
    WCHAR* wideString = (WCHAR*)malloc(requiredSize * sizeof(WCHAR));
    if (wideString == NULL) {
        return NULL;
    }
    int result = MultiByteToWideChar(
        CP_UTF8,
        0,
        utf8String,
        -1,
        wideString,
        requiredSize
    );

    if (result == 0) {
        free(wideString);
        return NULL;
    }
    return wideString;
}

// enable integration
int enable_integration_for_type(const char* fileType, const char* exePath) {
    char command[MAX_PATH + 5];
    char iconPath[MAX_PATH + 3];
    sprintf(command, "\"%s\" \"%%1\"", exePath);
    sprintf(iconPath, "%s,0", exePath);

    HKEY hKey;
    char fullKeyPath[MAX_PATH];
    sprintf(fullKeyPath, "%s\\shell\\%s", fileType, REG_KEY_NAME);

    if (RegCreateKeyExA(HKEY_CLASSES_ROOT, fullKeyPath, 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hKey, NULL) != ERROR_SUCCESS) {
        return 0;
    }

    const char* menuText = "Analyze with PE-XRay";
    RegSetValueExA(hKey, NULL, 0, REG_SZ, (const BYTE*)menuText, strlen(menuText) + 1);
    RegSetValueExA(hKey, "Icon", 0, REG_SZ, (const BYTE*)iconPath, strlen(iconPath) + 1);

    HKEY hCmdKey;
    if (RegCreateKeyExA(hKey, "command", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_WRITE, NULL, &hCmdKey, NULL) != ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 0;
    }

    RegSetValueExA(hCmdKey, NULL, 0, REG_SZ, (const BYTE*)command, strlen(command) + 1);

    RegCloseKey(hCmdKey);
    RegCloseKey(hKey);

    return 1;
}

// disable integration
int disable_integration_for_type(const char* fileType) {
    char fullKeyPath[MAX_PATH];
    sprintf(fullKeyPath, "%s\\shell\\%s", fileType, REG_KEY_NAME);
    return (SHDeleteKeyA(HKEY_CLASSES_ROOT, fullKeyPath) == ERROR_SUCCESS);
}

//checking if integration is enabled.
int is_integration_enabled_for_type(const char* fileType) {
    HKEY hKey;
    char fullKeyPath[MAX_PATH];
    sprintf(fullKeyPath, "%s\\shell\\%s", fileType, REG_KEY_NAME);

    if (RegOpenKeyExA(HKEY_CLASSES_ROOT, fullKeyPath, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
        RegCloseKey(hKey);
        return 1;
    }
    return 0;
}

int is_integration_enabled_all() {
    return is_integration_enabled_for_type("exefile") && is_integration_enabled_for_type("dllfile");
}

// creating a key from a registry
int enable_integration_all() {
    char exePath[MAX_PATH];
    if (GetModuleFileNameA(NULL, exePath, MAX_PATH) == 0) {
        return 0;
    }
    int success_exe = enable_integration_for_type("exefile", exePath);
    int success_dll = enable_integration_for_type("dllfile", exePath);
    return success_exe && success_dll;
}

// deleting a key from the registry
int disable_integration_all() {
    int success_exe = disable_integration_for_type("exefile");
    int success_dll = disable_integration_for_type("dllfile");
    return success_exe && success_dll;
}