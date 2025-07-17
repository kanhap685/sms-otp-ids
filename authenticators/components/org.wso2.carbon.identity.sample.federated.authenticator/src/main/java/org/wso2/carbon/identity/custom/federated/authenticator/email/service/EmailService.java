package org.wso2.carbon.identity.custom.federated.authenticator.email.service;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPConstants;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;

/**
 * Service class for Email operations
 * Handles email sending, OTP delivery, and email-related configurations
 */
public class EmailService {

    private static final Log log = LogFactory.getLog(EmailService.class);

    /**
     * Email configuration class
     */
    public static class EmailConfig {
        private String url;
        private String httpMethod;
        private String headers;
        private String payload;
        private String expectedResponse;

        public EmailConfig(String url, String httpMethod, String headers, String payload, String expectedResponse) {
            this.url = url;
            this.httpMethod = httpMethod;
            this.headers = headers;
            this.payload = payload;
            this.expectedResponse = expectedResponse;
        }

        // Getters
        public String getUrl() { return url; }
        public String getHttpMethod() { return httpMethod; }
        public String getHeaders() { return headers; }
        public String getPayload() { return payload; }
        public String getExpectedResponse() { return expectedResponse; }
    }

    /**
     * Email response class
     */
    public static class EmailResponse {
        private boolean success;
        private String message;
        private String actualOtpSent;

        public EmailResponse(boolean success, String message, String actualOtpSent) {
            this.success = success;
            this.message = message;
            this.actualOtpSent = actualOtpSent;
        }

        // Getters
        public boolean isSuccess() { return success; }
        public String getMessage() { return message; }
        public String getActualOtpSent() { return actualOtpSent; }
    }

    /**
     * Sends OTP via email
     * 
     * @param context Authentication context
     * @param emailAddress Target email address
     * @param otpCode OTP code to send
     * @param emailConfig Email configuration
     * @return EmailResponse containing result
     * @throws IOException if email sending fails
     */
    public EmailResponse sendOTP(AuthenticationContext context, String emailAddress, String otpCode, 
                                EmailConfig emailConfig) throws IOException {
        
        if (log.isDebugEnabled()) {
            log.debug("Sending Email OTP to: " + maskEmailAddress(emailAddress) + 
                     " with OTP length: " + (otpCode != null ? otpCode.length() : "null"));
        }

        try {
            // Validate email configuration
            if (StringUtils.isEmpty(emailConfig.getUrl())) {
                return new EmailResponse(false, "Email URL not configured", null);
            }

            // Prepare email content
            String emailMessage = createEmailMessage(context, otpCode);
            
            // Replace placeholders in URL, headers, and payload
            String processedUrl = replacePlaceholders(emailConfig.getUrl(), emailAddress, emailMessage, context);
            String processedHeaders = replacePlaceholders(emailConfig.getHeaders(), emailAddress, emailMessage, context);
            String processedPayload = replacePlaceholders(emailConfig.getPayload(), emailAddress, emailMessage, context);

            // Send email via HTTP API
            EmailResponse response = sendEmailViaHTTP(processedUrl, emailConfig.getHttpMethod(), 
                                                    processedHeaders, processedPayload, emailConfig.getExpectedResponse());
            
            if (response.isSuccess()) {
                if (log.isDebugEnabled()) {
                    log.debug("Email OTP sent successfully to: " + maskEmailAddress(emailAddress));
                }
                // Return the OTP that was actually sent (use generated OTP as the actual sent OTP)
                return new EmailResponse(true, "Email sent successfully", otpCode);
            } else {
                log.error("Failed to send Email OTP: " + response.getMessage());
                return response;
            }

        } catch (Exception e) {
            log.error("Error sending Email OTP to " + maskEmailAddress(emailAddress) + ": " + e.getMessage(), e);
            return new EmailResponse(false, "Error sending email: " + e.getMessage(), null);
        }
    }

    /**
     * Creates email message content
     */
    private String createEmailMessage(AuthenticationContext context, String otpCode) {
        String message = "Your verification code is: " + otpCode;
        
        // Try to get custom message from configuration
        Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
        String customMessage = authenticatorProperties.get("EMAIL_MESSAGE_TEMPLATE");
        
        if (StringUtils.isNotEmpty(customMessage)) {
            message = customMessage.replace("{otp}", otpCode);
        }
        
        return message;
    }

    /**
     * Replaces placeholders in strings
     */
    private String replacePlaceholders(String input, String emailAddress, String message, AuthenticationContext context) {
        if (StringUtils.isEmpty(input)) {
            return input;
        }

        String result = input;
        
        // Replace email placeholder
        result = result.replace("$ctx.email", emailAddress);
        result = result.replace("{email}", emailAddress);
        
        // Replace message placeholder
        result = result.replace("$ctx.msg", message);
        result = result.replace("{message}", message);
        
        // Replace OTP placeholder if present in context
        String otpToken = (String) context.getProperty(SMSOTPConstants.OTP_TOKEN);
        if (StringUtils.isNotEmpty(otpToken)) {
            result = result.replace("{otp}", otpToken);
            result = result.replace("$ctx.otp", otpToken);
        }

        return result;
    }

    /**
     * Sends email via HTTP API
     */
    private EmailResponse sendEmailViaHTTP(String url, String httpMethod, String headers, 
                                         String payload, String expectedResponse) throws IOException {
        
        HttpURLConnection connection = null;
        try {
            URL apiUrl = new URL(url);
            connection = (HttpURLConnection) apiUrl.openConnection();
            
            // Set HTTP method
            String method = StringUtils.isNotEmpty(httpMethod) ? httpMethod.toUpperCase() : "POST";
            connection.setRequestMethod(method);
            
            // Set headers
            setHttpHeaders(connection, headers);
            
            // Set payload for POST/PUT requests
            if (("POST".equals(method) || "PUT".equals(method)) && StringUtils.isNotEmpty(payload)) {
                connection.setDoOutput(true);
                try (OutputStreamWriter writer = new OutputStreamWriter(connection.getOutputStream())) {
                    writer.write(payload);
                    writer.flush();
                }
            }
            
            // Get response
            int responseCode = connection.getResponseCode();
            String responseBody = readResponse(connection);
            
            if (log.isDebugEnabled()) {
                log.debug("Email API response code: " + responseCode + ", body: " + responseBody);
            }
            
            // Check if response is successful
            boolean isSuccess = isSuccessfulResponse(responseCode, responseBody, expectedResponse);
            String message = isSuccess ? "Email sent successfully" : 
                           "Email API returned error code: " + responseCode + ", response: " + responseBody;
            
            return new EmailResponse(isSuccess, message, null);
            
        } catch (Exception e) {
            log.error("Error calling Email API: " + e.getMessage(), e);
            return new EmailResponse(false, "Error calling Email API: " + e.getMessage(), null);
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    /**
     * Sets HTTP headers
     */
    private void setHttpHeaders(HttpURLConnection connection, String headers) {
        if (StringUtils.isEmpty(headers)) {
            connection.setRequestProperty("Content-Type", "application/json");
            return;
        }

        String[] headerLines = headers.split(",");
        for (String headerLine : headerLines) {
            String[] headerParts = headerLine.split(":", 2);
            if (headerParts.length == 2) {
                String headerName = headerParts[0].trim();
                String headerValue = headerParts[1].trim();
                connection.setRequestProperty(headerName, headerValue);
            }
        }
    }

    /**
     * Reads HTTP response
     */
    private String readResponse(HttpURLConnection connection) throws IOException {
        StringBuilder response = new StringBuilder();
        
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                connection.getResponseCode() >= 200 && connection.getResponseCode() < 300 ? 
                connection.getInputStream() : connection.getErrorStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
        }
        
        return response.toString();
    }

    /**
     * Checks if HTTP response indicates success
     */
    private boolean isSuccessfulResponse(int responseCode, String responseBody, String expectedResponse) {
        // Check response code first
        if (responseCode >= 200 && responseCode < 300) {
            // If expected response is specified, check if it matches
            if (StringUtils.isNotEmpty(expectedResponse)) {
                return responseBody.contains(expectedResponse);
            }
            return true;
        }
        
        return false;
    }

    /**
     * Masks email address for logging
     */
    private String maskEmailAddress(String email) {
        if (StringUtils.isEmpty(email) || !email.contains("@")) {
            return email;
        }
        
        String[] parts = email.split("@");
        String localPart = parts[0];
        String domain = parts[1];
        
        if (localPart.length() <= 2) {
            return email;
        }
        
        String maskedLocal = localPart.charAt(0) + "***";
        return maskedLocal + "@" + domain;
    }
}
