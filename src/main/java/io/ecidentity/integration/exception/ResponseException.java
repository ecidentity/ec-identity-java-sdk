package io.ecidentity.integration.exception;

import io.ecidentity.protocol.types.ResultCodeExtProtocol;

public class ResponseException extends Exception{

    private ResultCodeExtProtocol resultCode;

    public ResponseException(ResultCodeExtProtocol resultCode) {
        this.resultCode = resultCode;
    }

    public ResponseException(String message, ResultCodeExtProtocol resultCode) {
        super(message);
        this.resultCode = resultCode;
    }

    public ResultCodeExtProtocol getResultCode() {
        return resultCode;
    }
}
