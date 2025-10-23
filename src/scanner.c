#include <Windows.h>
#include <stdio.h>
#include <strsafe.h>
#include <locale.h>
#include "../include/scanner.h"

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