#include "Utils.hpp"

// Returns the last Win32 error, in string format. Returns an empty string if there is no error.
void PrintWin32Error(DWORD dwError)
{
	LPWSTR messageBuffer = NULL;
	size_t size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

	wprintf(L"[error] Error 0x%08x - %s", dwError, messageBuffer);
	// Free the buffer.
	LocalFree(messageBuffer);
}

void print_auth_identity(SEC_WINNT_AUTH_IDENTITY_A * authidentity)
{
	printf("[debug] SEC_WINNT_AUTH_IDENTITY * authidentity = 0x%08p\n", authidentity);
	printf("      | (%d) authidentity->User: %s\n", authidentity->UserLength, authidentity->User);
	printf("      | (%d) authidentity->Domain: %s\n", authidentity->DomainLength, authidentity->Domain);
	printf("      | (%d) authidentity->Password: %s\n", authidentity->PasswordLength, authidentity->Password);
}

// Source: https://github.com/microsoft/Windows-classic-samples/blob/main/Samples/Win7Samples/netds/rpc/rpcsvc/Client.C#L589-L598
void* __RPC_USER MIDL_user_allocate(size_t size)
{
	return(HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, size));
}

void __RPC_USER MIDL_user_free(void* pointer)
{
	HeapFree(GetProcessHeap(), 0, pointer);
}
