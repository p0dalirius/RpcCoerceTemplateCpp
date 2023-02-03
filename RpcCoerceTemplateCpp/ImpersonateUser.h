#ifndef HDR_ImpersonateUser_H
#define HDR_ImpersonateUser_H

	// Wraps User Impersonation so that an application can impersonate any other user (with automatic cleanup)

	// Version 1.10
	// Copyright (C) 2004-2007 - Jonathan Wilkes
	
	// License - Free for any purpose, just do not remove the copyright
	// Supported on Windows 2000 and above

#if !defined(STRICT)
#define STRICT 1
#endif

#undef _WIN32_WINNT
#define _WIN32_WINNT 0x0500 // Required for LOGON32_LOGON_NEW_CREDENTIALS and LOGON32_PROVIDER_WINNT50

#include <windows.h>
#include <string>


class ImpersonateUser
{
private:
	bool init_;
	HANDLE userToken_;
	DWORD errorCode_;

public:
	ImpersonateUser() : init_(false), userToken_(NULL), errorCode_(0) {}
	~ImpersonateUser();

	bool Logon(const std::wstring& userName, const std::wstring& domain, const std::wstring& password);
	void Logoff();

		// Misc Methods
	DWORD GetErrorCode() const { return errorCode_; }
};


#endif // HDR_Impersonate_H
