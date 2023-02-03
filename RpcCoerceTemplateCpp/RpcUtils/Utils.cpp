#include "Utils.hpp"
#include <map>
#include <list>
#include <string>


// Returns the last Win32 error, in string format. Returns an empty string if there is no error.
void PrintWin32Error(DWORD dwError)
{
	LPWSTR messageBuffer = NULL;
	size_t size = FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
		NULL, dwError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPWSTR)&messageBuffer, 0, NULL);

	wprintf(L"[!] Error 0x%08x - %s", dwError, messageBuffer);
	// Free the buffer.
	LocalFree(messageBuffer);
}


void print_auth_identity(SEC_WINNT_AUTH_IDENTITY_A * authidentity)
{
	printf("[>] SEC_WINNT_AUTH_IDENTITY * authidentity = 0x%08p\n", authidentity);
	printf("  | (%03d) authidentity->User     : %s\n", authidentity->UserLength, authidentity->User);
	printf("  | (%03d) authidentity->Domain   : %s\n", authidentity->DomainLength, authidentity->Domain);
	printf("  | (%03d) authidentity->Password : %s\n", authidentity->PasswordLength, authidentity->Password);
	printf("  | authidentity->Flags: %ul\n",  authidentity->Flags);
}


void print_auth_identity(SEC_WINNT_AUTH_IDENTITY_W* authidentity)
{
	printf("[>] SEC_WINNT_AUTH_IDENTITY * authidentity = 0x%08p\n", authidentity);
	printf("  | (%03d) authidentity->User     : %s\n", authidentity->UserLength, (char *)authidentity->User);
	printf("  | (%03d) authidentity->Domain   : %s\n", authidentity->DomainLength, (char*)authidentity->Domain);
	printf("  | (%03d) authidentity->Password : %s\n", authidentity->PasswordLength, (char*)authidentity->Password);
	printf("  | authidentity->Flags: %ul\n", authidentity->Flags);
}


void print_auth_params(unsigned long AuthnLevel, unsigned long AuthnSvc, unsigned long AuthzSvc)
{
	// https://learn.microsoft.com/en-us/windows/win32/rpc/authentication-level-constants
	std::map<unsigned long, std::string> map_authentication_level_constants;
	map_authentication_level_constants[RPC_C_AUTHN_LEVEL_DEFAULT] = "RPC_C_AUTHN_LEVEL_DEFAULT";
	map_authentication_level_constants[RPC_C_AUTHN_LEVEL_NONE] = "RPC_C_AUTHN_LEVEL_NONE";
	map_authentication_level_constants[RPC_C_AUTHN_LEVEL_CONNECT] = "RPC_C_AUTHN_LEVEL_CONNECT";
	map_authentication_level_constants[RPC_C_AUTHN_LEVEL_CALL] = "RPC_C_AUTHN_LEVEL_CALL";
	map_authentication_level_constants[RPC_C_AUTHN_LEVEL_PKT] = "RPC_C_AUTHN_LEVEL_PKT";
	map_authentication_level_constants[RPC_C_AUTHN_LEVEL_PKT_INTEGRITY] = "RPC_C_AUTHN_LEVEL_PKT_INTEGRITY";
	map_authentication_level_constants[RPC_C_AUTHN_LEVEL_PKT_PRIVACY] = "RPC_C_AUTHN_LEVEL_PKT_PRIVACY";
	// https://learn.microsoft.com/en-us/windows/win32/rpc/authentication-service-constants
	std::map<unsigned long, std::string> map_authentication_service_constants;
	map_authentication_service_constants[RPC_C_AUTHN_NONE] = "RPC_C_AUTHN_NONE";
	map_authentication_service_constants[RPC_C_AUTHN_DCE_PRIVATE] = "RPC_C_AUTHN_DCE_PRIVATE";
	map_authentication_service_constants[RPC_C_AUTHN_DCE_PUBLIC] = "RPC_C_AUTHN_DCE_PUBLIC";
	map_authentication_service_constants[RPC_C_AUTHN_DEC_PUBLIC] = "RPC_C_AUTHN_DEC_PUBLIC";
	map_authentication_service_constants[RPC_C_AUTHN_GSS_NEGOTIATE] = "RPC_C_AUTHN_GSS_NEGOTIATE";
	map_authentication_service_constants[RPC_C_AUTHN_WINNT] = "RPC_C_AUTHN_WINNT";
	map_authentication_service_constants[RPC_C_AUTHN_GSS_SCHANNEL] = "RPC_C_AUTHN_GSS_SCHANNEL";
	map_authentication_service_constants[RPC_C_AUTHN_GSS_KERBEROS] = "RPC_C_AUTHN_GSS_KERBEROS";
	map_authentication_service_constants[RPC_C_AUTHN_DPA] = "RPC_C_AUTHN_DPA";
	map_authentication_service_constants[RPC_C_AUTHN_MSN] = "RPC_C_AUTHN_MSN";
	map_authentication_service_constants[RPC_C_AUTHN_DIGEST] = "RPC_C_AUTHN_DIGEST";
	map_authentication_service_constants[RPC_C_AUTHN_NEGO_EXTENDER] = "RPC_C_AUTHN_NEGO_EXTENDER";
	map_authentication_service_constants[RPC_C_AUTHN_MQ] = "RPC_C_AUTHN_MQ";
	map_authentication_service_constants[RPC_C_AUTHN_DEFAULT] = "RPC_C_AUTHN_DEFAULT";
	// https://learn.microsoft.com/en-us/windows/win32/rpc/authorization-service-constants
	std::map<unsigned long, std::string> map_authorization_service_constants;
	map_authorization_service_constants[RPC_C_AUTHZ_NONE] = "RPC_C_AUTHZ_NONE";
	map_authorization_service_constants[RPC_C_AUTHZ_NAME] = "RPC_C_AUTHZ_NAME";
	map_authorization_service_constants[RPC_C_AUTHZ_DCE] = "RPC_C_AUTHZ_DCE";
	map_authorization_service_constants[RPC_C_AUTHZ_DEFAULT] = "RPC_C_AUTHZ_DEFAULT";

	printf("[>] Authentication parameters\n");
	printf("  | AuthnLevel : %s\n", map_authentication_level_constants[AuthnLevel].c_str());
	printf("  | AuthnSvc   : %s\n", map_authentication_service_constants[AuthnSvc].c_str());
	printf("  | AuthzSvc   : %s\n", map_authorization_service_constants[AuthzSvc].c_str());
}


// Source: https://docs.microsoft.com/en-us/windows/win32/rpc/the-midl-user-allocate-function
void* __RPC_USER MIDL_user_allocate(size_t size)
{
	return(HeapAlloc(GetProcessHeap(), HEAP_GENERATE_EXCEPTIONS, size));
}

// Source: https://docs.microsoft.com/en-us/windows/win32/rpc/the-midl-user-free-function
void __RPC_USER MIDL_user_free(void* pointer)
{
	HeapFree(GetProcessHeap(), 0, pointer);
}

bool cmp_wchar_t(wchar_t* first, wchar_t* second) {
	return wcscmp(first, second) == 0;
}

void get_rpc_runtime_version() {
	wchar_t* path; // Length of MAX_PATH
	std::list<void*> used_functions;
	std::list<wchar_t*> libraries_paths;
	
	used_functions.push_back(&RpcStringBindingComposeW);
	used_functions.push_back(&RpcBindingFromStringBindingW);
	used_functions.push_back(&RpcStringFreeW);
	used_functions.push_back(&RpcBindingSetAuthInfoW);
	used_functions.push_back(&RpcBindingFree);
	used_functions.unique();

	printf("[>] Runtime information (for debug):\n");
	for (auto& ptr : used_functions) {
		path = (wchar_t* )malloc(sizeof(wchar_t) * MAX_PATH);
		if (get_library_path_from_function(ptr, path)) {
			// printf("Path found: %ls", path);
			libraries_paths.push_back(path);
		}
	}
	libraries_paths.unique(cmp_wchar_t);
	for (auto& ptr : libraries_paths) {
		print_pe_file_version(ptr);
	}
	printf("\n");
}

void print_pe_file_version(const wchar_t* pszFilePath) {
	// Adapted from: https://stackoverflow.com/a/940784
	// Docs: https://learn.microsoft.com/en-us/windows/win32/api/winver/nf-winver-getfileversioninfoa

	DWORD dwSize = 0;
	BYTE* pbVersionInfo = NULL;
	VS_FIXEDFILEINFO* pFileInfo = NULL;
	UINT puLenFileInfo = 0;

	// Get the version information for the file requested
	dwSize = GetFileVersionInfoSizeW(pszFilePath, NULL);
	if (dwSize == 0) {
		printf("Error in GetFileVersionInfoSize: %d\n", GetLastError());
		return;
	}

	pbVersionInfo = new BYTE[dwSize];

	if (!GetFileVersionInfoW(pszFilePath, 0, dwSize, pbVersionInfo)) {
		printf("Error in GetFileVersionInfo: %d\n", GetLastError());
		delete[] pbVersionInfo;
		return;
	}

	if (!VerQueryValueW(pbVersionInfo, TEXT("\\"), (LPVOID*)&pFileInfo, &puLenFileInfo)) {
		printf("Error in VerQueryValue: %d\n", GetLastError());
		delete[] pbVersionInfo;
		return;
	}

	printf("  | \"%ls\" : (File Version: %d.%d.%d.%d) (Product Version: %d.%d.%d.%d)\n",
		pszFilePath,

		(pFileInfo->dwFileVersionMS >> 16) & 0xffff,
		(pFileInfo->dwFileVersionMS >> 0) & 0xffff,
		(pFileInfo->dwFileVersionLS >> 16) & 0xffff,
		(pFileInfo->dwFileVersionLS >> 0) & 0xffff,

		(pFileInfo->dwProductVersionMS >> 16) & 0xffff,
		(pFileInfo->dwProductVersionMS >> 0) & 0xffff,
		(pFileInfo->dwProductVersionLS >> 16) & 0xffff,
		(pFileInfo->dwProductVersionLS >> 0) & 0xffff
	);
}


int get_library_path_from_function(void* functionpointer, wchar_t* path) {
	HMODULE hm = NULL;
	wchar_t _path[MAX_PATH];

	if (GetModuleHandleEx(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT, (LPCWSTR)functionpointer, &hm) == 0) {
		int ret = GetLastError();
		fprintf(stderr, "GetModuleHandle failed, error = %d\n", ret);
		// Return or however you want to handle an error.
		return 0;
	}
	if (GetModuleFileName(hm, _path, sizeof(_path)) == 0) {
		int ret = GetLastError();
		fprintf(stderr, "GetModuleFileName failed, error = %d\n", ret);
		// Return or however you want to handle an error.
		return 0;
	}
	wcsncpy_s(path, MAX_PATH-1, _path, MAX_PATH-1);

	// The path variable should now contain the full filepath for this DLL.
	return 1;
}