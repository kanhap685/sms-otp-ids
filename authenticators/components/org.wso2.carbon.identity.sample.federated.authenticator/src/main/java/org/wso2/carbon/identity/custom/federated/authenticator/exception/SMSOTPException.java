package org.wso2.carbon.identity.custom.federated.authenticator.exception;

public class SMSOTPException extends Exception {

    public SMSOTPException(String msg) {
        super(msg);
    }

    public SMSOTPException(String msg, Throwable cause) {
        super(msg, cause);
    }
}