#ifndef PE_ANALYZER_H
#define PE_ANALYZER_H

#include <windows.h>
#include <stdio.h>
#include <math.h>
#include <locale.h>
#include <ctype.h>

#define MAX_FINDINGS 256
#define MIN_STRING_LENGTH 5
#define MAX_STRING_BUFFER 1024

#define ENTROPY_CRITICAL 7.5f
#define ENTROPY_HIGH 7.0f
#define ENTROPY_MEDIUM 6.0f

#define SIGNATURE_STATE_VALID_AND_TRUSTED  0  // подпись валидна. все гуд
#define SIGNATURE_STATE_INVALID            1  // подпись есть, но она невалид
#define SIGNATURE_STATE_NOT_TRUSTED        2  // подпись валидна (самопальный серт)
#define SIGNATURE_STATE_ABSENT             3  // подписи нет
#define SIGNATURE_STATE_ERROR              4 // другая ошибка

#define REG_KEY_NAME "PEAnalyzer"

typedef struct {
    char description[256];
    int score;
} HeuristicFinding;  //для описания

typedef struct {
    char name[IMAGE_SIZEOF_SHORT_NAME + 1];
    DWORD virtual_address;
    DWORD virtual_size;
    DWORD raw_pointer;
    DWORD raw_size;
    float entropy;
    char flags[4];
    BOOL is_suspicious;
} SectionInfo; // информация о секции

typedef struct {
    DWORD hash;
    const char* dll_name;
    const char* api_name;
} ApiHashInfo; //для хэшей

typedef struct {
    DWORD found_hash;
    const char* possible_api; // указатель на базу
} FoundApiHash;

typedef struct {
    char name[256];
    BOOL is_suspicious; // подсветка в гуи
} FunctionInfo;  // информация

typedef struct {
    char name[256];
    FunctionInfo* functions; // динамический массив функций
    int function_count;
    int function_capacity; // для управления realloc
} DllInfo; //структура длл

typedef struct {
    const char* function_name; // имя функции
    int score;                 // кол-во очков
    const char* category;      // критичность
} ApiRule; // структура для функций

typedef struct {
    BOOL is_pe;
    char verdict[32];
    int total_score;
    WORD machine_type;
    DWORD entry_point_rva;

    HeuristicFinding findings[MAX_FINDINGS];
    int finding_count;

    SectionInfo* sections;
    int section_count;

    DllInfo* dlls;
    int dll_count;
    int dll_capacity; // для управления realloc

    FoundApiHash found_hashes[50];
    int found_hashes_count;
} AnalysisResult; //структура для анализа

BOOL analyze_pe_file(WCHAR* file_path, AnalysisResult* result); //основная функция для вызова анализа 
FLOAT calculate_entropy(LPVOID data_sections, DWORD size_data_sections); //подсчет энтропии
BOOL find_high_entropy_blocks(LPVOID data_sections, DWORD size_data_sections); //вычисление энтропии по блокам
VOID scan_section_for_strings(LPVOID section_data, DWORD section_size, AnalysisResult* result); //поиск строк
DWORD RvaToOffset(PIMAGE_NT_HEADERS p_nt_header, DWORD rva, LONGLONG file_size);
VOID evaluate_threats(PIMAGE_NT_HEADERS p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size, WCHAR* file_path, const ApiRule* dangerous_functions, size_t num_dangerous_functions);

void free_analysis_result(AnalysisResult* result);

//x64
VOID parse_sections_x64(PIMAGE_NT_HEADERS64 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size);
BOOL parse_imports_x64(PIMAGE_NT_HEADERS64 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size, const ApiRule* dangerous_functions, size_t num_dangerous_functions);

//x86
VOID parse_sections_x86(PIMAGE_NT_HEADERS32 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size);
BOOL parse_imports_x86(PIMAGE_NT_HEADERS32 p_nt_header, LPVOID lp_base_address, AnalysisResult* result, LONGLONG file_size, const ApiRule* dangerous_functions, size_t num_dangerous_functions);

static const char* suspicious_strings[] = {
        "cmd.exe", "powershell", "packed", "/c schtasks", "WinDefend", 
        "ICryptoTransform", "DownloaderApp", "runas", "ShellExecute"
        
    };

static const ApiRule dangerous_api_rules[] = {
    // CRITICAL
    { "CreateRemoteThread",         30, "CRITICAL" },
    { "WriteProcessMemory",         30, "CRITICAL" },
    { "SetWindowsHookExA",          30, "CRITICAL" },
    { "SetWindowsHookExW",          30, "CRITICAL" },
    { "NtCreateThreadEx",           35, "CRITICAL" },
    { "RtlCreateUserThread",        35, "CRITICAL" },
    { "VirtualAllocEx",             30, "CRITICAL" },
    { "NtMapViewOfSection",         35, "CRITICAL" },
    { "CreateServiceA",             30, "CRITICAL" },
    { "CreateServiceW",             30, "CRITICAL" },
    { "QueueUserAPC",               25, "CRITICAL" },
    { "VirtualProtectEx",           25, "CRITICAL" },
    { "SetThreadContext",           30, "CRITICAL" },
    { "NtLoadDriver",               40, "CRITICAL" },
    { "ZwLoadDriver",               40, "CRITICAL" },
    { "DeviceIoControl",            25, "CRITICAL" },
    
    // HIGH
    { "LoadLibraryA",               15, "HIGH" },
    { "LoadLibraryW",               15, "HIGH" },
    { "ShellExecuteA",              20, "HIGH" },
    { "ShellExecuteW",              20, "HIGH" },
    { "CreateProcessA",             20, "HIGH" },
    { "CreateProcessW",             20, "HIGH" },
    { "system",                     20, "HIGH" },
    { "HttpSendRequestA",           20, "HIGH" },
    { "HttpSendRequestW",           20, "HIGH" },
    { "WinHttpSendRequest",         20, "HIGH" },
    { "CryptEncrypt",               25, "HIGH" },
    { "CryptGenKey",                22, "HIGH" },
    { "CryptImportKey",             22, "HIGH" },
    
    // MEDIUM
    { "GetProcAddress",             3,  "MEDIUM" },
    { "URLDownloadToFileA",         5,  "MEDIUM" },
    { "URLDownloadToFileW",         5,  "MEDIUM" },
    { "InternetOpenA",              5,  "MEDIUM" },
    { "InternetOpenW",              5,  "MEDIUM" },
    { "InternetConnectA",           5,  "MEDIUM" },
    { "InternetConnectW",           5,  "MEDIUM" },
    { "InternetReadFile",           8,  "MEDIUM" },
    { "IsDebuggerPresent",          2,  "MEDIUM" },
    { "CheckRemoteDebuggerPresent", 3,  "MEDIUM" },
    { "GetTickCount",               1,  "MEDIUM" },
    { "FindWindowA",                5,  "MEDIUM" },
    { "FindWindowW",                5,  "MEDIUM" },
    { "EnumWindows",                5,  "MEDIUM" },
    { "GetAdaptersInfo",            3,  "MEDIUM" },
    { "GetComputerNameA",           2,  "MEDIUM" },
    { "GetComputerNameW",           2,  "MEDIUM" },
    { "GetUserNameA",               2,  "MEDIUM" },
    { "GetUserNameW",               2,  "MEDIUM" },
    { "GetAsyncKeyState",           5,  "MEDIUM" },
    { "GetKeyState",                5,  "MEDIUM" },
    { "FindFirstFileA",             8,  "MEDIUM" },
    { "FindFirstFileW",             8,  "MEDIUM" },
    { "FindNextFileA",              8,  "MEDIUM" },
    { "FindNextFileW",              8,  "MEDIUM" },
    { "GetTempPathA",               4,  "MEDIUM" },
    { "GetTempPathW",               4,  "MEDIUM" },
    { "OpenProcess",                10, "MEDIUM" },
    { "OpenThread",                 10, "MEDIUM" },
    { "OutputDebugStringA",         3,  "MEDIUM" },
    { "OutputDebugStringW",         3,  "MEDIUM" },
    { "Process32FirstW",            7, "MEDIUM" },
    { "Process32NextW",             7, "MEDIUM" },
    { "EnumProcesses",              7, "MEDIUM" },
    
    // LOW
    { "GetSystemInfo",              1, "LOW" },
    { "GetVersionExA",              1, "LOW" },
    { "GetVersionExW",              1, "LOW" },
    { "Sleep",                      1, "LOW" },
    { "FindResourceA",              2, "LOW" },
    { "FindResourceW",              2, "LOW" },
    { "LoadResource",               2, "LOW" },
    { "SizeofResource",             2, "LOW" },
    { "GetModuleHandleA",           2, "LOW" },
    { "GetModuleHandleW",           2, "LOW" },
    { "GetModuleFileNameA",         2, "LOW" },
    { "GetModuleFileNameW",         2, "LOW" },
    { "GetForegroundWindow",        3, "LOW" },
    { "GetCursorPos",               2, "LOW" },
    { "GetDC",                      3, "LOW" }
};

#endif