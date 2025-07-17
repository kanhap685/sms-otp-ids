package org.wso2.carbon.identity.custom.federated.authenticator.sms.model;

/**
 * Model class representing SMS response
 */
public class SMSResponse {
    
    private boolean success;
    private String actualOtpSent;
    private String message;
    private String responseBody;
    
    /**
     * Constructor for SMS response
     * 
     * @param success Whether SMS was sent successfully
     * @param actualOtpSent The actual OTP that was sent
     * @param message Response message
     * @param responseBody Full response body from SMS provider
     */
    public SMSResponse(boolean success, String actualOtpSent, String message, String responseBody) {
        this.success = success;
        this.actualOtpSent = actualOtpSent;
        this.message = message;
        this.responseBody = responseBody;
    }
    
    // Getters and setters
    public boolean isSuccess() {
        return success;
    }
    
    public void setSuccess(boolean success) {
        this.success = success;
    }
    
    public String getActualOtpSent() {
        return actualOtpSent;
    }
    
    public void setActualOtpSent(String actualOtpSent) {
        this.actualOtpSent = actualOtpSent;
    }
    
    public String getMessage() {
        return message;
    }
    
    public void setMessage(String message) {
        this.message = message;
    }
    
    public String getResponseBody() {
        return responseBody;
    }
    
    public void setResponseBody(String responseBody) {
        this.responseBody = responseBody;
    }
    
    @Override
    public String toString() {
        return "SMSResponse{" +
                "success=" + success +
                ", actualOtpSent='" + actualOtpSent + '\'' +
                ", message='" + message + '\'' +
                ", responseBody='" + responseBody + '\'' +
                '}';
    }
}
