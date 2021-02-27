/* compile :
gcc.exe noimport.c -o noimport -nostartfiles -nostdlib "-Wl,--entry=__start" -masm=intel
*/

// Import for structures and type definition only : NO FUNCTIONS
#include <windows.h>
#include <winnt.h>
#include <winternl.h>

// https://www.nirsoft.net/kernel_struct/vista/LDR_DATA_TABLE_ENTRY.html
typedef struct _LDR_DATA_TABLE_ENTRY_COMPLETED
{
     LIST_ENTRY InLoadOrderLinks;
     LIST_ENTRY InMemoryOrderLinks;
     LIST_ENTRY InInitializationOrderLinks;
     PVOID DllBase;
     PVOID EntryPoint;
     ULONG SizeOfImage;
     UNICODE_STRING FullDllName;
     UNICODE_STRING BaseDllName;
     //rest is not used
} LDR_DATA_TABLE_ENTRY_COMPLETED, *PLDR_DATA_TABLE_ENTRY_COMPLETED;

// ### Necesasry functions ###

int string_cmp(char* cmp, char* other) {
    /* char* string comparison, return true/false */
    while(*other == *cmp && *other != 0) {
        cmp ++;
        other ++;
    }
    return (*cmp == *other);
}

int wstring_cmp_i(WCHAR* cmp, WCHAR* other) {
    /* Case insensitive Wstring compare, cmp must be lowercase.
    returns true/false */
    WORD* w_cmp = (WORD*) cmp;
    WORD* w_other = (WORD*) other;
    while(*w_other != 0) {
        WORD lowercase_other = ( (*w_other>='A' && *w_other<='Z')
                                 ? *w_other - 'A' + 'a'
                                 : *w_other);
        if(*w_cmp != lowercase_other) {
            return 0;
        }
        w_cmp ++;
        w_other ++;
    }
    return (*w_cmp == 0);
}


void* myGetModuleHandleW(WCHAR* module_name) {
    /* Find module by readin the PEB.
    module_name must be lowerstring */

    // Get the PEB address from the TEB
    PEB* PEB_ptr = NULL;
    __asm__(
        "mov %[PEB_ptr], fs:[0x30];"
        : [PEB_ptr] "=r" (PEB_ptr)    //output
        : :
    );

    // Get to the module linked list
    PEB_LDR_DATA* peb_ldr_data = PEB_ptr->Ldr;
    LIST_ENTRY* list_head = &(peb_ldr_data->InMemoryOrderModuleList);
    LIST_ENTRY* list_entry;
    LDR_DATA_TABLE_ENTRY_COMPLETED* ldr_entry;

    // goes through the linked list to find kernel32.dll
    // stops when return to header element (the list head is linked to the tail)
    for(list_entry = list_head->Flink; list_entry != list_head; list_entry = list_entry->Flink){
        // We follow inMemoryOrder, so list_entry points to LDR_DATA_TABLE_ENTRY_COMPLETED.InMemoryOrderLinks
        // We need to remove the size of the first element to get the address of the object
        ldr_entry = (LDR_DATA_TABLE_ENTRY_COMPLETED*) ((char*)list_entry - sizeof(LIST_ENTRY));
        WCHAR* name = ldr_entry->BaseDllName.Buffer;
        if(wstring_cmp_i(module_name, name)) {
            return ldr_entry->DllBase;
        }
    }
    return NULL;
}

void* myGetProcAddress(char* module, char* search_name){
    /* Find an exported function in a module, by name */

    // Get to the export table
    IMAGE_DOS_HEADER* p_DOS_HDR  = (IMAGE_DOS_HEADER*) module;
    IMAGE_NT_HEADERS* p_NT_HDR = (IMAGE_NT_HEADERS*) (((char*) p_DOS_HDR) + p_DOS_HDR->e_lfanew);
    IMAGE_EXPORT_DIRECTORY* export_directory = (IMAGE_EXPORT_DIRECTORY*) (module +
            p_NT_HDR->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    // Get the arrays based on their RVA in the IMAGE_EXPORT_DIRECTORY struct
    DWORD* names_RVA_array = (DWORD*) (module + export_directory->AddressOfNames);
    DWORD* function_RVA_array = (DWORD*) (module + export_directory->AddressOfFunctions);
    WORD* name_ordinals_array = (WORD*) (module + export_directory->AddressOfNameOrdinals);

    //Then for each function
    for(int i=0; i< export_directory->NumberOfFunctions; ++i) {
        // Get the functions ordinal, name and code RVA
        //DWORD exported_ordinal = name_ordinals_array[i] + export_directory->Base;
        char* funct_name = module + names_RVA_array[i];
        DWORD exported_RVA = function_RVA_array[name_ordinals_array[i]];

        if(string_cmp(search_name, funct_name)){
            return (void*) (module + exported_RVA);
        }
    }
    return NULL;
}

int _start(){
    void* kernel32_dll = myGetModuleHandleW(L"kernel32.dll");
    void* (__stdcall *GetProcAddress)(void*,char*) = myGetProcAddress(kernel32_dll, "GetProcAddress");
    void* (__stdcall *LoadLibraryA)(char*) = GetProcAddress(kernel32_dll, "LoadLibraryA");

    //Win32 Hello World
    void* User32_dll = LoadLibraryA("user32.dll");
    int (__stdcall *MessageBoxA)(void*, char*, char*, int) = GetProcAddress(User32_dll, "MessageBoxA");
    MessageBoxA(NULL, "Hello, with no imports", "Hello world", 0);
}
