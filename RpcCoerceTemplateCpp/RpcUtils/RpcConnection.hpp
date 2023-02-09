#pragma once

#include <Windows.h>
#include <rpcdce.h>

#pragma comment(lib, "rpcrt4.lib")

class rpcConnection
{
    RPC_STATUS RpcStatus;
    RPC_WSTR StringBinding;
    handle_t hBinding;

    RPC_WSTR InterfaceUUID;
    RPC_WSTR InterfaceAddress;

    SEC_WINNT_AUTH_IDENTITY_W AuthIdentity;

    unsigned long AuthnLevel;
    unsigned long AuthnSvc;
    unsigned long AuthzSvc;

public:
    rpcConnection();
    int setCredentials();
    void close();

    /* get / set */
    void setInterfaceUUID(RPC_WSTR InterfaceUUID);
    RPC_WSTR getInterfaceUUID();
    void setInterfaceAddress(RPC_WSTR InterfaceAddress);
    RPC_WSTR getInterfaceAddress();

    void setAuthnLevel(unsigned long AuthnLevel);
    unsigned long getAuthnLevel();
    void setAuthnSvc(unsigned long AuthnSvc);
    unsigned long getAuthnSvc();
    void setAuthzSvc(unsigned long AuthzSvc);
    unsigned long getAuthzSvc();
};
