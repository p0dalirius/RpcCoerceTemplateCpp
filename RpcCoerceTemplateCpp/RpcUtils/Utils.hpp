#include <assert.h>
#include <stdio.h>
#include <tchar.h>
#include <SDKDDKVer.h>
#include <Windows.h>
#include <winver.h>

#pragma comment(lib, "version.lib")


void PrintWin32Error(DWORD dwError);
void print_auth_identity(SEC_WINNT_AUTH_IDENTITY_A * authidentity);
void print_auth_identity(SEC_WINNT_AUTH_IDENTITY_W* authidentity);
void print_auth_params(unsigned long AuthnLevel, unsigned long AuthnSvc, unsigned long AuthzSvc);

void* __RPC_USER MIDL_user_allocate(size_t size);
void __RPC_USER MIDL_user_free(void* pointer);

void get_rpc_runtime_version();
void print_pe_file_version(const wchar_t* pszFilePath);