#include <vector>
#include <Windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <string.h>
#include <tchar.h>



//First module is not being added to vector, so not being logged.
struct logProcessInfo
{
    DWORD parentProc; //PID of parent process
    DWORD processID; //PID
    std::vector<WCHAR>    copySzModule;
    std::vector<WCHAR>   copySzExePath;


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
        for (int it = 0; it < 255; it++)
        {
            copySzModule.push_back(p_module->szModule[it]);
        }
        

        for (int it = 0; it < 255; it++)
        {
            copySzExePath.push_back(p_module->szExePath[it]);
        }
    }
};



DWORD main()
{

    std::vector<logProcessInfo> allProcs;
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


    std::cout << "Handle acquired: " << procSnapshot << "\n";

    allProcs.push_back(logProcessInfo(process,&module));

    while (Process32Next(procSnapshot, &process) == TRUE) //Process32Next will iterate through snapshot, repopulating process struct w relevant info during each iteration
    {
        allProcs.push_back(logProcessInfo(process,&module)); //If proc32next returns true, than it means that info was copied into process buffer. We want to make processInfo obj with that info, which then is put in vector.

    }


    for (auto it : allProcs)
    {
        std::cout <<"Parent Process " << it.parentProc << "\n";
        std::cout << "PID " << it.processID << "\n";
        std::cout << "EXE PATH: ";
        for (std::vector<WCHAR>::iterator vecIt = it.copySzExePath.begin(); vecIt != it.copySzExePath.end(); vecIt++)
        {
            std::wcout << *vecIt ;
        }
        std::cout << "\n MODULE NAME:";

        for (std::vector<WCHAR>::iterator vecIt = it.copySzModule.begin(); vecIt != it.copySzModule.end(); vecIt++)
        {
            std::wcout << *vecIt;
        }


        std::cout << "\n";
        std::cout << "---------------------------- \n";
        std::cout << "---------------------------- \n";

     //   std::wcout << it.copySzExePath;
      //  _tprintf(TEXT("\n\n     Path to Exe:     %s \n"), it.copySzExePath);

    }


    CloseHandle(procSnapshot); //close handle...duhh 
    return 1;
}