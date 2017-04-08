#include 
#include 
#define PROCESO    "explorer.exe"
#define SIZE  1024          


typedef int (WINAPI *MYMESSAGE)(HWND, LPCSTR, LPCSTR, UINT); //Puntero a Estructura

typedef struct _EstructuraInyectar
{
 MYMESSAGE _MessageBox;
 char mensaje[1024];
}EstructuraInyectar;

void FuncionInyectar(EstructuraInyectar *estructura)
{
 estructura->_MessageBox(NULL, estructura->mensaje, estructura->mensaje, MB_OK);
}

void ObtenerPunteros(EstructuraInyectar *estructura)
{
 HINSTANCE Library;
 ZeroMemory(estructura, sizeof(EstructuraInyectar));
 Library = LoadLibrary("user32.dll");
 estructura->_MessageBox = (MYMESSAGE)GetProcAddress(Library, "MessageBoxA");
 memset(estructura->mensaje, 0, sizeof(estructura->mensaje));
 strcpy(estructura->mensaje, "Ola Ke Ase?,ejecutandose o ke ase");
}


int main()
{
 DWORD pID;
 HANDLE hProcess, hSnap;
 void *pRemoteThread;
 EstructuraInyectar estructura, *Estructura;
 PROCESSENTRY32 pe32 = {0};
 
 ObtenerPunteros(&estructura);
 if((hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)) == INVALID_HANDLE_VALUE) return -1;
 pe32.dwSize = sizeof(PROCESSENTRY32);
 Process32First(hSnap, &pe32);
 do{
  if(strcmp(PROCESO,pe32.szExeFile) == 0)
  {
   pID = pe32.th32ProcessID;
   break;
  }
 }while(Process32Next(hSnap, &pe32));
 if(hSnap != INVALID_HANDLE_VALUE){CloseHandle(hSnap);}
 
 hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pID);
 pRemoteThread = VirtualAllocEx(hProcess, 0, SIZE, MEM_COMMIT | MEM_RESERVE,PAGE_EXECUTE_READWRITE);
 WriteProcessMemory(hProcess, pRemoteThread,(LPCVOID) FuncionInyectar, SIZE, 0);
 Estructura = (EstructuraInyectar*)VirtualAllocEx(hProcess , 0, sizeof(EstructuraInyectar), MEM_COMMIT, PAGE_READWRITE);
 WriteProcessMemory(hProcess, Estructura,&estructura, sizeof estructura, 0);
 CreateRemoteThread(hProcess , 0, 0, (DWORD (__stdcall *)(void *))pRemoteThread, Estructura, 0, NULL);
 CloseHandle(hProcess);
}
