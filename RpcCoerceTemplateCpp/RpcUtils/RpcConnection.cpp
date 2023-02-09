#include "RpcConnection.hpp"

enum class rpc_access_protocols { NCAN_NP, NCAN_TCP_IP };

rpcConnection::rpcConnection() {} ;

int rpcConnection::setCredentials() {

}

void rpcConnection::setAuthnLevel(unsigned long AuthnLevel) {
    this->AuthnLevel = AuthnLevel;
}

unsigned long rpcConnection::getAuthnLevel() {
    return this->AuthnLevel;
}

void rpcConnection::setAuthnSvc(unsigned long AuthnSvc) {
    this->AuthnSvc = AuthnSvc;
}

unsigned long rpcConnection::getAuthnSvc() {
    return this->AuthnSvc;
}

void rpcConnection::setAuthzSvc(unsigned long AuthzSvc) {
    this->AuthzSvc = AuthzSvc;
}

unsigned long rpcConnection::getAuthzSvc() {
    return this->AuthzSvc;
}

void rpcConnection::close() {

}