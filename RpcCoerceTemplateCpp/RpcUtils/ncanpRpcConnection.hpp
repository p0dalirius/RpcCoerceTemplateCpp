#pragma once
class ncacn_np_rpcConnection
{
    RPC_WSTR InterfaceUUID = (RPC_WSTR)L"c681d488-d850-11d0-8c52-00c04fd90f7e";
    RPC_WSTR InterfaceAddress = (RPC_WSTR)L"\\pipe\\lsarpc";

    unsigned long AuthnLevel = RPC_C_AUTHN_LEVEL_PKT_PRIVACY;
    unsigned long AuthnSvc = RPC_C_AUTHN_WINNT;
    unsigned long AuthzSvc = RPC_C_AUTHZ_NONE;

public:
    ncacn_np_rpcConnection();
    int setCredentials();

    /* get / set */
    void setAuthnLevel(unsigned long AuthnLevel);
    unsigned long getAuthnLevel();
    void setAuthnSvc(unsigned long AuthnSvc);
    unsigned long getAuthnSvc();
    void setAuthzSvc(unsigned long AuthzSvc);
    unsigned long getAuthzSvc();

};
