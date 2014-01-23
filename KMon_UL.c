#include <windows.h>
#include <stdio.h>
#include <winioctl.h>

#define IOCTL_SETEVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_QUERYREQUEST CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)
#define IOCTL_DESTROYEVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_IN_DIRECT, FILE_READ_DATA | FILE_WRITE_DATA)

HANDLE hDevice;
HANDLE hEvent[2];
LPSTR lpszInfo = NULL;

DWORD WINAPI WaitForClose(LPVOID lParam)
{
	DWORD dwRet = 0;
	while(GetAsyncKeyState(VK_ESCAPE) != -32767)
		Sleep(100);
	
	printf("Exiting");
	
	DeviceIoControl(hDevice, IOCTL_DESTROYEVENTS, NULL, 0, NULL, 0, &dwRet, NULL);
	if(hEvent[0])
		CloseHandle(hEvent[0]);
	if(hEvent[1])
		CloseHandle(hEvent[1]);
	if(hDevice)
		CloseHandle(hDevice);
	if(lpszKey)
		free(lpszKey);
	
	exit(0);
}

int main(void)
{
	DWORD dwRet = 0, dwLen = 0, dwWait = 0;
	BOOLEAN bRes;
	CHAR message[] = "A potential malicous application is attempting to create\n" 
					 "a registry key in a known auto-start location.\n"
					 "Details: ";
	CHAR location[MAX_PATH], processName[100], keyPath[MAX_PATH];
	
	hDevice = CreateFile("\\\\.\\ioCtl", GENERIC_READ | GENERIC_WRITE,  0, NULL, OPEN_EXISTING, 0, NULL);
	if(!hDevice){
		printf("Error opening device: %d", GetLastError());
		fflush(stdout);
		return 1;
	}
	
	hEvent[0] = CreateEvent(NULL, FALSE, FALSE, NULL); // user
	if(!hEvent[0]){
		printf("Could not create hEvent[0]\n");
		fflush(stdout);
		CloseHandle(hDevice);
		return 1;
	}
		
	hEvent[1] = CreateEvent(NULL, FALSE, FALSE, NULL); // kernel
	if(!hEvent[1]){
		printf("Could not create hEvent[1]\n");
		fflush(stdout);
		CloseHandle(hEvent[0]);
		CloseHandle(hDevice);
		return 1;
	}
	
	if(!DeviceIoControl(hDevice, IOCTL_SETEVENTS, hEvent, sizeof(hEvent), NULL, 0, &dwRet, NULL)){
		printf("Could not send IOCTL_SETEVENTS\n");
		fflush(stdout);
		CloseHandle(hEvent[0]);
		CloseHandle(hEvent[1]);
		CloseHandle(hDevice);
		return 1;
	}
	
	CreateThread(NULL, 0, WaitForClose, 0, 0, NULL);
	
	do{
		dwWait = WaitForSingleObject(hEvent[1], INFINITE);
		
		lpszInfo = (LPSTR)malloc((1000));
		if(!lpszInfo){
			printf("Out of memory\n");
			break;
		}
		
		memset(lpszInfo, 0, 1000);
		
		ReadFile(hDevice, lpszInfo, 999, &dwRet, NULL);
		printf("ReadFile(buffer): dwRet: %u\n", dwRet);
		fflush(stdout);
		
		SetEvent(hEvent[0]);
		
		bRes = 1;
		keyPath = strok(lpszInfo, "|");
		if(keyPath){
			bRes = (MessageBox(HWND_DESKTOP, lpszKey, "Important event", MB_YESNO | MB_ICONEXCLAMATION) == IDYES);
		}
		
		free(lpszInfo);
		DeviceIoControl(hDevice, IOCTL_QUERYREQUEST, &bRes, sizeof(bRes), NULL, 0, &dwRet, NULL);
	}while(dwWait == WAIT_OBJECT_0);	
	
	printf("Exited loop\n");	
	CloseHandle(hEvent[0]);
	CloseHandle(hEvent[1]);
	CloseHandle(hDevice);
	if(lpszInfo) free(lpszInfo);
	return 0;
}