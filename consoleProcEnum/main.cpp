#include <vector>
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string>
#include <tchar.h>

/*
TODO

1.
searchProcesses exhibits undefined behaviour regarding the returned result.
a query for "fdm.exe" will yield firefox.exe, and a query for "firefox.exe" will yield firefox


2.
Make code look nicer.

3.
Query lookup output to CLI should be stylistically improved. 

*/



//First module is not being added to vector, so not being logged.
struct logProcessInfo
{
    DWORD parentProc; //PID of parent process
    DWORD processID; //PID
    std::wstring copySzModuleStr = L"uninitalized";
    std::wstring copySzExePathStr = L"uninitalized";


    logProcessInfo(PROCESSENTRY32 process, MODULEENTRY32* p_module)//Constructor;
    {
        parentProc = process.th32ParentProcessID;
        processID = process.th32ProcessID;
        //Module, enumeration is required to get access to szModule (Name Of Process), and szExepath (Executables path)
        HANDLE specificProcSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, processID);
        Module32First(specificProcSnapshot, p_module); //p_module points to the relevantly populated MODULEENTRY32 struct 
        //  std::wcout << (p_module->szModule[it]);
        parentProc = process.th32ParentProcessID;
        processID = process.th32ProcessID;
        copySzExePathStr = (p_module->szExePath);
        copySzModuleStr = (p_module->szModule);



    }
};
std::vector<logProcessInfo> allProcs;


logProcessInfo* searchProcesses(std::wstring* processName) //Returns Pointer to logProcessInfo obj when it reaches first stringmatch, NULL if none found
{
    for (auto &it : allProcs)
    {
     
        if (lstrcmpiA((LPCSTR)(*processName).c_str(), (LPCSTR)it.copySzModuleStr.c_str()) == 0) 
        {
            std::cout << "MATCH FOUND! \n";
            return &it;
        }
    
    }
    return NULL;
}



DWORD main()
{

    HANDLE procSnapshot;
    PROCESSENTRY32 process;
    process.dwSize = sizeof(PROCESSENTRY32);
    MODULEENTRY32 module;
    module.dwSize = sizeof(MODULEENTRY32);


     procSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0); //Second param is not used with SNAPPROCESS
    if (procSnapshot == INVALID_HANDLE_VALUE)
    {
        std::cout << "INVALID_HANDLE_VALUE \n" ;
        DWORD err = GetLastError();
        std::cout << err << "\n";
        return err;
    }
    Process32First(procSnapshot, &process);





    allProcs.push_back(logProcessInfo(process,&module));
    while (Process32Next(procSnapshot, &process) == TRUE) //Process32Next will iterate through snapshot, repopulating process struct w relevant info during each iteration
    {
        allProcs.push_back(logProcessInfo(process,&module)); //If proc32next returns true, than it means that info was copied into process buffer. We want to make processInfo obj with that info, which then is put in vector.

    }


    for (auto it : allProcs) //display all
    {

        std::cout << "Parent Process " << it.parentProc << "\n";
        std::cout << "PID " << it.processID << "\n";
        std::wcout << "EXE PATH: " << it.copySzExePathStr << "\n";
        std::wcout << "MODULE NAME:" << it.copySzModuleStr;




        std::cout << "\n";
        std::cout << "---------------------------- \n";
        std::cout << "---------------------------- \n";

    }
    std::cout << "\n\n\n\n -------- \n";

    while (1 > 0) //infinite loop, for lookup queries
    {
        std::cout << "Enter a process name for lookup. for example: firefox.exe or lsass.exe  \n";
        std::wstring input;
        std::wcin >> input;
        std::wcout << input;

        logProcessInfo* test = searchProcesses(&input);
        if (test != NULL)
        {
            std::wcout << "PE Path:" << test->copySzExePathStr << "\n";
            std::wcout << "Process Name: " << test->copySzModuleStr << "\n";
            std::cout << "Parent Process: " << test->parentProc << "\n";
            std::cout << "PID: " << test->processID << "\n";
        }
        else
        {
            std::cout << "search operation returned NULL \n";
        }
    }
    CloseHandle(procSnapshot); //close handle...duhh. No memory leak
    return 1;
}