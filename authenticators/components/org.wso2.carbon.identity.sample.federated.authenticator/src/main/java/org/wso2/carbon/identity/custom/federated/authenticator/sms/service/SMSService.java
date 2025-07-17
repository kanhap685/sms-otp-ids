package org.wso2.carbon.identity.custom.federated.authenticator.sms.service;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPConstants;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.model.SMSResponse;

import java.io.IOException;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import javax.net.ssl.HttpsURLConnection;

/**
 * Service class for SMS operations
 * Handles all SMS-related functionality including sending OTP messages
 */
public class SMSService {

    private static final Log log = LogFactory.getLog(SMSService.class);

    /**
     * Sends SMS OTP to the specified mobile number
     * 
     * @param context Authentication context
     * @param mobileNumber Target mobile number
     * @param otpCode OTP code to send
     * @param smsConfig SMS configuration parameters
     * @return SMS response containing the actual OTP sent
     * @throws IOException If SMS sending fails
     */
    public SMSResponse sendOTP(AuthenticationContext context, String mobileNumber, String otpCode, SMSConfig smsConfig) 
            throws IOException {
        
        if (log.isDebugEnabled()) {
            log.debug("Sending OTP to mobile: " + mobileNumber + " with OTP length: " + otpCode.length());
        }

        String encodedMobileNumber = URLEncoder.encode(mobileNumber, "UTF-8");
        String finalSmsUrl = buildSmsUrl(smsConfig.getSmsUrl(), encodedMobileNumber, otpCode);
        
        HttpURLConnection connection = createConnection(finalSmsUrl, smsConfig);
        
        try {
            configureConnection(connection, smsConfig, encodedMobileNumber, otpCode);
            
            if (SMSOTPConstants.POST_METHOD.equalsIgnoreCase(smsConfig.getHttpMethod())) {
                sendPostData(connection, smsConfig, encodedMobileNumber, otpCode);
            }
            
            return processResponse(connection, context, otpCode);
            
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Builds the final SMS URL with placeholders replaced
     */
    private String buildSmsUrl(String baseUrl, String encodedMobileNumber, String otpCode) {
        String smsMessage = SMSOTPConstants.SMS_MESSAGE;
        return baseUrl.replaceAll("\\$ctx.num", encodedMobileNumber)
                     .replaceAll("\\$ctx.msg", smsMessage.replaceAll("\\s", "+") + otpCode)
                     + "sendOneTimePW.json";
    }

    /**
     * Creates HTTP connection based on protocol
     */
    private HttpURLConnection createConnection(String smsUrl, SMSConfig smsConfig) throws IOException {
        URL url = new URL(smsUrl);
        
        if (log.isDebugEnabled()) {
            log.debug("SMS Provider URL: " + url);
        }
        
        if (SMSOTPConstants.HTTPS.equals(url.getProtocol())) {
            return (HttpsURLConnection) url.openConnection();
        } else {
            return (HttpURLConnection) url.openConnection();
        }
    }

    /**
     * Configures the HTTP connection with headers and method
     */
    private void configureConnection(HttpURLConnection connection, SMSConfig smsConfig, 
                                   String encodedMobileNumber, String otpCode) throws IOException {
        
        connection.setDoInput(true);
        connection.setDoOutput(true);
        connection.setRequestMethod(smsConfig.getHttpMethod());
        
        // Set headers if provided
        if (smsConfig.getHeaders() != null && !smsConfig.getHeaders().trim().isEmpty()) {
            setHeaders(connection, smsConfig.getHeaders(), encodedMobileNumber, otpCode);
        }
    }

    /**
     * Sets HTTP headers with placeholder replacement
     */
    private void setHeaders(HttpURLConnection connection, String headerString, 
                           String encodedMobileNumber, String otpCode) {
        
        String processedHeaders = headerString.trim()
                .replaceAll("\\$ctx.num", encodedMobileNumber)
                .replaceAll("\\$ctx.msg", SMSOTPConstants.SMS_MESSAGE + otpCode);
        
        String[] headers = processedHeaders.split(",");
        for (String header : headers) {
            String[] headerParts = header.split(":");
            if (headerParts.length > 1) {
                connection.setRequestProperty(headerParts[0].trim(), headerParts[1].trim());
            }
        }
    }

    /**
     * Sends POST data to SMS provider
     */
    private void sendPostData(HttpURLConnection connection, SMSConfig smsConfig, 
                             String encodedMobileNumber, String otpCode) throws IOException {
        
        if (smsConfig.getPayload() == null || smsConfig.getPayload().trim().isEmpty()) {
            log.warn("POST method specified but payload is empty");
            return;
        }
        
        // Process mobile number for Thai format (remove leading 0, add 66)
        String processedMobileNumber = encodedMobileNumber.replaceFirst("0", "66");
        String processedPayload = smsConfig.getPayload().replaceAll("\\$ctx.num", processedMobileNumber);
        
        if (log.isDebugEnabled()) {
            log.debug("Sending payload to SMS provider: " + processedPayload);
        }
        
        OutputStreamWriter writer = null;
        try {
            writer = new OutputStreamWriter(connection.getOutputStream(), SMSOTPConstants.CHAR_SET);
            writer.write(processedPayload);
            writer.flush();
        } finally {
            if (writer != null) {
                writer.close();
            }
        }
    }

    /**
     * Processes the HTTP response and extracts OTP information
     */
    private SMSResponse processResponse(HttpURLConnection connection, AuthenticationContext context, String otpCode) throws IOException {
        int responseCode = connection.getResponseCode();
        
        if (responseCode == 200 || responseCode == 201 || responseCode == 202) {
            return handleSuccessResponse(connection, context, otpCode);
        } else {
            return handleErrorResponse(connection, context, responseCode);
        }
    }

    /**
     * Handles successful SMS response
     */
    private SMSResponse handleSuccessResponse(HttpURLConnection connection, AuthenticationContext context, String otpCode) throws IOException {
        String responseBody = readResponseBody(connection);
        
        if (log.isDebugEnabled()) {
            log.debug("SMS sent successfully. Response: " + responseBody);
        }
        
        // Parse response to extract actual OTP (implementation depends on SMS provider format)
        String actualOtpSent = extractOtpFromResponse(responseBody);
        
        // If we couldn't extract OTP from response, use the original OTP code we sent
        if (actualOtpSent == null || actualOtpSent.isEmpty()) {
            actualOtpSent = otpCode;
            if (log.isDebugEnabled()) {
                log.debug("Using original OTP code as fallback: " + otpCode);
            }
        }
        
        return new SMSResponse(true, actualOtpSent, "SMS sent successfully", responseBody);
    }

    /**
     * Handles error response from SMS provider
     */
    private SMSResponse handleErrorResponse(HttpURLConnection connection, AuthenticationContext context, int responseCode) throws IOException {
        String errorBody = readErrorBody(connection);
        String errorMessage = "SMS sending failed. Response code: " + responseCode;
        
        log.error(errorMessage + ". Response: " + errorBody);
        
        return new SMSResponse(false, null, errorMessage, errorBody);
    }

    /**
     * Reads response body from successful connection
     */
    private String readResponseBody(HttpURLConnection connection) throws IOException {
        StringBuilder response = new StringBuilder();
        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(connection.getInputStream(), SMSOTPConstants.CHAR_SET))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }
        return response.toString();
    }

    /**
     * Reads error body from failed connection
     */
    private String readErrorBody(HttpURLConnection connection) throws IOException {
        StringBuilder response = new StringBuilder();
        try (java.io.BufferedReader reader = new java.io.BufferedReader(
                new java.io.InputStreamReader(connection.getErrorStream(), SMSOTPConstants.CHAR_SET))) {
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        } catch (Exception e) {
            return "Unable to read error response";
        }
        return response.toString();
    }

    /**
     * Extracts OTP from SMS provider response
     * This method should be customized based on the SMS provider's response format
     */
    private String extractOtpFromResponse(String responseBody) {
        // Implementation depends on SMS provider's response format
        // This is a placeholder that should be customized
        try {
            // For GSSO service, parse JSON response to extract OTP
            // This is a simplified implementation
            if (responseBody.contains("\"oneTimePassword\"")) {
                // Extract OTP from JSON response
                String[] parts = responseBody.split("\"oneTimePassword\":");
                if (parts.length > 1) {
                    String otpPart = parts[1].split(",")[0].replace("\"", "").trim();
                    return otpPart;
                }
            }
        } catch (Exception e) {
            log.warn("Failed to extract OTP from response: " + e.getMessage());
        }
        return null;
    }

    /**
     * Configuration class for SMS settings
     */
    public static class SMSConfig {
        private String smsUrl;
        private String httpMethod;
        private String headers;
        private String payload;
        private String expectedResponse;

        // Constructors
        public SMSConfig(String smsUrl, String httpMethod, String headers, String payload, String expectedResponse) {
            this.smsUrl = smsUrl;
            this.httpMethod = httpMethod;
            this.headers = headers;
            this.payload = payload;
            this.expectedResponse = expectedResponse;
        }

        // Getters and setters
        public String getSmsUrl() { return smsUrl; }
        public void setSmsUrl(String smsUrl) { this.smsUrl = smsUrl; }

        public String getHttpMethod() { return httpMethod; }
        public void setHttpMethod(String httpMethod) { this.httpMethod = httpMethod; }

        public String getHeaders() { return headers; }
        public void setHeaders(String headers) { this.headers = headers; }

        public String getPayload() { return payload; }
        public void setPayload(String payload) { this.payload = payload; }

        public String getExpectedResponse() { return expectedResponse; }
        public void setExpectedResponse(String expectedResponse) { this.expectedResponse = expectedResponse; }
    }
}
