#include "ncanpRpcConnection.hpp"

ncacn_np_rpcConnection::ncacn_np_rpcConnection() {} ;

int ncacn_np_rpcConnection::setCredentials() {

}

void ncacn_np_rpcConnection::setAuthnLevel(unsigned long AuthnLevel) {
    this->AuthnLevel = AuthnLevel;
}

unsigned long ncacn_np_rpcConnection::getAuthnLevel() {
    return this->AuthnLevel;
}

void ncacn_np_rpcConnection::setAuthnSvc(unsigned long AuthnSvc) {
    this->AuthnSvc = AuthnSvc;
}

unsigned long ncacn_np_rpcConnection::getAuthnSvc() {
    return this->AuthnSvc;
}

void ncacn_np_rpcConnection::setAuthzSvc(unsigned long AuthzSvc) {
    this->AuthzSvc = AuthzSvc;
}

unsigned long ncacn_np_rpcConnection::getAuthzSvc() {
    return this->AuthzSvc;
}
