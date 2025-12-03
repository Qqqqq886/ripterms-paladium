#include <Windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <string>
#include <thread>
#include <chrono>
#include <fstream>
#include <random>
#include <shlobj.h>

class SelfDestruct {
private:
    bool triggered = false;
    
    // Generate random data
    void OverwriteMemory(void* address, size_t size) {
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);
        
        char* ptr = static_cast<char*>(address);
        for (size_t i = 0; i < size; i++) {
            ptr[i] = dis(gen);
        }
    }
    
    // Unlink from PEB (Process Environment Block)
    void UnlinkFromPEB() {
        HMODULE ntdll = GetModuleHandleA("ntdll.dll");
        if (!ntdll) return;
        
        FARPROC NtUnmapViewOfSection = GetProcAddress(ntdll, "NtUnmapViewOfSection");
        if (!NtUnmapViewOfSection) return;
        
        PPEB peb = (PPEB)__readgsqword(0x60); // x64 PEB offset
        PLIST_ENTRY listHead = &peb->Ldr->InMemoryOrderModuleList;
        PLIST_ENTRY listEntry = listHead->Flink;
        
        while (listEntry != listHead) {
            PLDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(listEntry, LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);
            
            wchar_t* baseName = entry->BaseDllName.Buffer;
            if (baseName && wcsstr(baseName, L"YOUR_DLL_NAME.dll")) {
                // Remove from module list
                listEntry->Flink->Blink = listEntry->Blink;
                listEntry->Blink->Flink = listEntry->Flink;
                break;
            }
            listEntry = listEntry->Flink;
        }
    }
    
    // Erase file from disk securely
    void SecureFileErase(const std::string& filepath) {
        // Overwrite file with random data multiple times
        HANDLE hFile = CreateFileA(filepath.c_str(), GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (hFile != INVALID_HANDLE_VALUE) {
            LARGE_INTEGER fileSize;
            GetFileSizeEx(hFile, &fileSize);
            
            // Gutmann method - 35 passes
            char patterns[35][4] = {
                {0x55, 0x55, 0x55, 0x55}, {0xAA, 0xAA, 0xAA, 0xAA}, {0x92, 0x49, 0x24, 0x92},
                {0x49, 0x24, 0x92, 0x49}, {0x24, 0x92, 0x49, 0x24}, {0x00, 0x00, 0x00, 0x00},
                {0x11, 0x11, 0x11, 0x11}, {0x22, 0x22, 0x22, 0x22}, {0x33, 0x33, 0x33, 0x33},
                {0x44, 0x44, 0x44, 0x44}, {0x55, 0x55, 0x55, 0x55}, {0x66, 0x66, 0x66, 0x66},
                {0x77, 0x77, 0x77, 0x77}, {0x88, 0x88, 0x88, 0x88}, {0x99, 0x99, 0x99, 0x99},
                {0xAA, 0xAA, 0xAA, 0xAA}, {0xBB, 0xBB, 0xBB, 0xBB}, {0xCC, 0xCC, 0xCC, 0xCC},
                {0xDD, 0xDD, 0xDD, 0xDD}, {0xEE, 0xEE, 0xEE, 0xEE}, {0xFF, 0xFF, 0xFF, 0xFF},
                {0x92, 0x49, 0x24, 0x92}, {0x49, 0x24, 0x92, 0x49}, {0x24, 0x92, 0x49, 0x24},
                {0x6D, 0xB6, 0xDB, 0x6D}, {0xB6, 0xDB, 0x6D, 0xB6}, {0xDB, 0x6D, 0xB6, 0xDB},
                {0x00, 0x00, 0x00, 0x00}, {0x11, 0x11, 0x11, 0x11}, {0x22, 0x22, 0x22, 0x22},
                {0x33, 0x33, 0x33, 0x33}, {0x44, 0x44, 0x44, 0x44}, {0x55, 0x55, 0x55, 0x55},
                {0x66, 0x66, 0x66, 0x66}, {0x77, 0x77, 0x77, 0x77}
            };
            
            for (int pass = 0; pass < 35; pass++) {
                SetFilePointer(hFile, 0, NULL, FILE_BEGIN);
                char* buffer = new char[fileSize.LowPart];
                for (DWORD i = 0; i < fileSize.LowPart; i++) {
                    buffer[i] = patterns[pass % 35][i % 4];
                }
                WriteFile(hFile, buffer, fileSize.LowPart, NULL, NULL);
                delete[] buffer;
            }
            
            CloseHandle(hFile);
            
            // Rename file multiple times
            for (int i = 0; i < 10; i++) {
                std::string newName = filepath + std::to_string(i);
                MoveFileA(filepath.c_str(), newName.c_str());
            }
            
            // Final deletion
            DeleteFileA(filepath.c_str());
        }
    }
    
    // Clear all hooks and detours
    void RemoveHooks() {
        HMODULE hModule = GetModuleHandle(NULL);
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hModule;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)hModule + dosHeader->e_lfanew);
        
        // Clear IAT (Import Address Table)
        PIMAGE_IMPORT_DESCRIPTOR importDesc = (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)hModule + 
            ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
        
        while (importDesc->Name) {
            char* moduleName = (char*)((BYTE*)hModule + importDesc->Name);
            PIMAGE_THUNK_DATA thunk = (PIMAGE_THUNK_DATA)((BYTE*)hModule + importDesc->FirstThunk);
            
            while (thunk->u1.Function) {
                // Overwrite function pointer
                thunk->u1.Function = 0;
                thunk++;
            }
            importDesc++;
        }
    }
    
    // Wipe heap memory
    void WipeHeap() {
        HANDLE heap = GetProcessHeap();
        if (heap) {
            PROCESS_HEAP_ENTRY entry;
            SecureZeroMemory(&entry, sizeof(entry));
            
            while (HeapWalk(heap, &entry)) {
                if (entry.wFlags & PROCESS_HEAP_ENTRY_BUSY) {
                    OverwriteMemory(entry.lpData, entry.cbData);
                }
            }
        }
    }
    
    // Spawn suicide process
    void CreateSuicideProcess() {
        char modulePath[MAX_PATH];
        GetModuleFileNameA(NULL, modulePath, MAX_PATH);
        
        // Create batch script that deletes itself and the DLL
        std::ofstream batch("cleanup.bat");
        batch << "@echo off\n";
        batch << ":loop\n";
        batch << "del \"" << modulePath << "\" >nul 2>&1\n";
        batch << "if exist \"" << modulePath << "\" goto loop\n";
        batch << "del cleanup.bat\n";
        batch.close();
        
        // Execute batch script hidden
        ShellExecuteA(NULL, "open", "cleanup.bat", NULL, NULL, SW_HIDE);
    }
    
public:
    void Execute() {
        if (triggered) return;
        triggered = true;
        
        // Phase 1: Memory obfuscation
        std::thread([this]() {
            // Clear hooks first
            RemoveHooks();
            
            // Unlink from PEB
            UnlinkFromPEB();
            
            // Wipe heap
            WipeHeap();
            
            // Overwrite module memory
            HMODULE self = GetModuleHandleA("YOUR_DLL_NAME.dll");
            if (self) {
                PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)self;
                PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)self + dosHeader->e_lfanew);
                DWORD size = ntHeaders->OptionalHeader.SizeOfImage;
                
                // Multiple overwrite passes
                for (int i = 0; i < 7; i++) {
                    OverwriteMemory(self, size);
                }
            }
            
            // Phase 2: File cleanup
            char dllPath[MAX_PATH];
            GetModuleFileNameA(self, dllPath, MAX_PATH);
            SecureFileErase(dllPath);
            
            // Phase 3: Process suicide
            CreateSuicideProcess();
            
            // Final: Unload self
            FreeLibraryAndExitThread(self, 0);
        }).detach();
    }
    
    void renderGUI() {
        if (ImGui::Button("SELF DESTRUCT", ImVec2(-1, 40))) {
            Execute();
        }
    }
};

// Global instance
SelfDestruct g_SelfDestruct;

// GUI rendering
void RenderSelfDestructGUI() {
    g_SelfDestruct.renderGUI();
}

// Trigger via hotkey
void CheckSelfDestructHotkey() {
    if (GetAsyncKeyState(VK_DELETE) & 1) {
        g_SelfDestruct.Execute();
    }
}
