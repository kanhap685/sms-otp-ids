package org.wso2.carbon.identity.custom.federated.authenticator;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.AbstractApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.FederatedApplicationAuthenticator;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext;
import org.wso2.carbon.identity.application.authentication.framework.exception.AuthenticationFailedException;
import org.wso2.carbon.identity.application.common.model.Property;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPAuthenticator;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPConstants;
import org.wso2.carbon.identity.custom.federated.authenticator.sms.SMSOTPUtils;
import org.wso2.carbon.identity.custom.federated.authenticator.email.EmailOTPAuthenticator;

import net.minidev.json.JSONObject;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class CustomFederatedAuthenticator extends AbstractApplicationAuthenticator
        implements FederatedApplicationAuthenticator {

    private static final long serialVersionUID = 1L;

    private static final Log log = LogFactory.getLog(CustomFederatedAuthenticator.class);
    private transient SMSOTPAuthenticator smsOTPAuthenticator;
    private transient EmailOTPAuthenticator emailOTPAuthenticator;

    private SMSOTPAuthenticator getSmsOTPAuthenticator() {
        if (smsOTPAuthenticator == null) {
            smsOTPAuthenticator = new SMSOTPAuthenticator();
        }
        return smsOTPAuthenticator;
    }

    private EmailOTPAuthenticator getEmailOTPAuthenticator() {
        if (emailOTPAuthenticator == null) {
            emailOTPAuthenticator = new EmailOTPAuthenticator();
        }
        return emailOTPAuthenticator;
    }

    @Override
    public boolean canHandle(HttpServletRequest request) {

        log.debug("๕๕๕๕๕๕๕๕๕๕๕ start canHandle ๔๔๔๔๔๔๔๔๔๔๔๔ ");
        String selectedChannel = request.getParameter("otpChannel");
        log.debug("************ selectedChannel : " + selectedChannel);
        // Custom logic: If user has not selected OTP channel, redirect to channel selection page
        // String selectedChannel = null; //request.getParameter("otpChannel");
        // if (StringUtils.isEmpty(selectedChannel)) {
        //     try {
        //         // Build redirect URL to channel selection JSP
        //         String contextId = request.getParameter("sessionDataKey");
        //         String baseUrl = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
        //         String redirectUrl = baseUrl.replace("login.do", "otpChannelSelection.jsp");
        //         if (StringUtils.isNotEmpty(contextId)) {
        //             redirectUrl += "?sessionDataKey=" + java.net.URLEncoder.encode(contextId, "UTF-8");
        //         }
        //         // Actually redirect
        //         HttpServletResponse response = (HttpServletResponse) request.getAttribute("HTTP_RESPONSE");
        //         if (response != null) {
        //             response.sendRedirect(redirectUrl);
        //         } else {
        //             // fallback: try to get response from thread local (WSO2 style)
        //             javax.servlet.http.HttpServletResponse resp = null;
        //             org.apache.axis2.context.MessageContext axis2MsgCtx = org.apache.axis2.context.MessageContext.getCurrentMessageContext();
        //             if (axis2MsgCtx != null) {
        //                 Object responseObj = axis2MsgCtx.getProperty("HTTPServletResponse");
        //                 if (responseObj instanceof javax.servlet.http.HttpServletResponse) {
        //                     resp = (javax.servlet.http.HttpServletResponse) responseObj;
        //                     resp.sendRedirect(redirectUrl);
        //                 }
        //             }
        //         }
        //     } catch (Exception e) {
        //         log.error("Error redirecting to OTP channel selection page", e);
        //     }
        //     return false;
        // }
        // If user has selected channel, allow processing to continue
        return true;
    }

    @Override
    public String getFriendlyName() {
        return "Custom Federated Multi-OTP Authenticator";
    }

    @Override
    public String getName() {
        return "CustomFederatedAuthenticator";
    }

    @Override
    public String getClaimDialectURI() {
        return SMSOTPConstants.OIDC_DIALECT;
    }

    @Override
    public List<Property> getConfigurationProperties() {
        List<Property> configProperties = new ArrayList<Property>();

        // ================================
        // General Settings (Both SMS and EMAIL)
        // ================================
        Property generalTab = new Property();
        generalTab.setName("general_settings_tab");
        generalTab.setDisplayName("⚙️ General Settings ******************************");
        generalTab.setType("tab");
        generalTab.setDisplayOrder(0);
        generalTab.setRequired(false);
        generalTab.setDescription("Configure general OTP authentication settings");
        configProperties.add(generalTab);

        Property defaultOtpType = new Property();
        defaultOtpType.setName("DEFAULT_OTP_TYPE");
        defaultOtpType.setDisplayName("Default OTP Type");
        defaultOtpType.setRequired(false);
        defaultOtpType.setDescription("Select the default OTP type for authentication");
        defaultOtpType.setDisplayOrder(1);
        defaultOtpType.setType("select");
        defaultOtpType.setOptions(new String[] { "sms", "email" });
        defaultOtpType.setValue("sms");
        configProperties.add(defaultOtpType);

        // ================================
        // Tab 1: SMS Settings
        // ================================
        Property smsTab = new Property();
        smsTab.setName("sms_settings_tab");
        smsTab.setDisplayName("📱 SMS Settings ******************************");
        smsTab.setType("tab");
        smsTab.setDisplayOrder(2);
        smsTab.setRequired(false);
        smsTab.setDescription("Configure SMS OTP authentication settings");
        configProperties.add(smsTab);

        // SMS Configuration Properties
        Property smsUrl = new Property();
        smsUrl.setName(SMSOTPConstants.SMS_URL);
        smsUrl.setDisplayName("SMS URL");
        smsUrl.setRequired(true);
        smsUrl.setDescription("Enter client sms url value. If the phone number and text message are in URL, " +
                "specify them as $ctx.num and $ctx.msg");
        smsUrl.setDisplayOrder(3);
        smsUrl.setType("string");
        configProperties.add(smsUrl);

        Property httpMethod = new Property();
        httpMethod.setName(SMSOTPConstants.HTTP_METHOD);
        httpMethod.setDisplayName("HTTP Method");
        httpMethod.setRequired(true);
        httpMethod.setDescription("Enter the HTTP Method used by the SMS API");
        httpMethod.setDisplayOrder(4);
        httpMethod.setType("select");
        httpMethod.setOptions(new String[] { "GET", "POST", "PUT" });
        configProperties.add(httpMethod);

        Property headers = new Property();
        headers.setName(SMSOTPConstants.HEADERS);
        headers.setDisplayName("HTTP Headers");
        headers.setRequired(false);
        headers.setDescription("Enter the headers used by the API separated by comma, with the Header name and value " +
                "separated by \":\". If the phone number and text message are in Headers, specify them as $ctx.num and $ctx.msg");
        headers.setDisplayOrder(5);
        headers.setType("textarea");
        configProperties.add(headers);

        Property payload = new Property();
        payload.setName(SMSOTPConstants.PAYLOAD);
        payload.setDisplayName("HTTP Payload");
        payload.setRequired(false);
        payload.setDescription("Enter the HTTP Payload used by the SMS API. If the phone number and text message are " +
                "in Payload, specify them as $ctx.num and $ctx.msg");
        payload.setDisplayOrder(6);
        payload.setType("textarea");
        configProperties.add(payload);

        Property httpResponse = new Property();
        httpResponse.setName(SMSOTPConstants.HTTP_RESPONSE);
        httpResponse.setDisplayName("HTTP Response Code");
        httpResponse.setRequired(false);
        httpResponse.setDescription(
                "Enter the HTTP response code the API sends upon successful call. Leave empty if unknown");
        httpResponse.setDisplayOrder(7);
        httpResponse.setType("string");
        configProperties.add(httpResponse);

        // SMS Error Handling Section
        Property smsErrorHeader = new Property();
        smsErrorHeader.setName("sms_error_handling_header");
        smsErrorHeader.setDisplayName("SMS Error Handling");
        smsErrorHeader.setType("header");
        smsErrorHeader.setDisplayOrder(8);
        smsErrorHeader.setRequired(false);
        smsErrorHeader.setDescription("Configure SMS error handling and debugging options");
        configProperties.add(smsErrorHeader);

        Property showErrorInfo = new Property();
        showErrorInfo.setName(SMSOTPConstants.SHOW_ERROR_INFO);
        showErrorInfo.setDisplayName("Show Detailed Error Information");
        showErrorInfo.setRequired(false);
        showErrorInfo.setDescription("Enter \"true\" if detailed error information from SMS provider needs to be " +
                "displayed in the UI");
        showErrorInfo.setDisplayOrder(9);
        showErrorInfo.setType("boolean");
        configProperties.add(showErrorInfo);

        Property valuesToBeMasked = new Property();
        valuesToBeMasked.setName(SMSOTPConstants.VALUES_TO_BE_MASKED_IN_ERROR_INFO);
        valuesToBeMasked.setDisplayName("Mask values in Error Info");
        valuesToBeMasked.setRequired(false);
        valuesToBeMasked
                .setDescription("Enter comma separated Values to be masked by * in the detailed error messages");
        valuesToBeMasked.setDisplayOrder(10);
        valuesToBeMasked.setType("string");
        configProperties.add(valuesToBeMasked);

        // ================================
        // Tab 2: EMAIL Settings
        // ================================
        Property emailTab = new Property();
        emailTab.setName("email_settings_tab");
        emailTab.setDisplayName("📧 EMAIL Settings ******************************");
        emailTab.setType("tab");
        emailTab.setDisplayOrder(11);
        emailTab.setRequired(false);
        emailTab.setDescription("Configure Email OTP authentication settings");
        configProperties.add(emailTab);

        // EMAIL Configuration Properties
        Property emailUrl = new Property();
        emailUrl.setName("EMAIL_URL");
        emailUrl.setDisplayName("Email URL");
        emailUrl.setRequired(false);
        emailUrl.setDescription("Enter client email url value. If the email address and message are in URL, " +
                "specify them as $ctx.email and $ctx.msg");
        emailUrl.setDisplayOrder(12);
        emailUrl.setType("string");
        configProperties.add(emailUrl);

        Property emailMethod = new Property();
        emailMethod.setName("EMAIL_HTTP_METHOD");
        emailMethod.setDisplayName("HTTP Method");
        emailMethod.setRequired(false);
        emailMethod.setDescription("Enter the HTTP Method used by the Email API");
        emailMethod.setDisplayOrder(13);
        emailMethod.setType("select");
        emailMethod.setOptions(new String[] { "GET", "POST", "PUT" });
        configProperties.add(emailMethod);

        Property emailHeaders = new Property();
        emailHeaders.setName("EMAIL_HEADERS");
        emailHeaders.setDisplayName("HTTP Headers");
        emailHeaders.setRequired(false);
        emailHeaders.setDescription(
                "Enter the headers used by the API separated by comma, with the Header name and value " +
                        "separated by \":\". If the email address and message are in Headers, specify them as $ctx.email and $ctx.msg");
        emailHeaders.setDisplayOrder(14);
        emailHeaders.setType("textarea");
        configProperties.add(emailHeaders);

        Property emailPayload = new Property();
        emailPayload.setName("EMAIL_PAYLOAD");
        emailPayload.setDisplayName("HTTP Payload");
        emailPayload.setRequired(false);
        emailPayload
                .setDescription("Enter the HTTP Payload used by the Email API. If the email address and message are " +
                        "in Payload, specify them as $ctx.email and $ctx.msg");
        emailPayload.setDisplayOrder(15);
        emailPayload.setType("textarea");
        configProperties.add(emailPayload);

        Property emailResponse = new Property();
        emailResponse.setName("EMAIL_HTTP_RESPONSE");
        emailResponse.setDisplayName("HTTP Response Code");
        emailResponse.setRequired(false);
        emailResponse.setDescription(
                "Enter the HTTP response code the API sends upon successful call. Leave empty if unknown");
        emailResponse.setDisplayOrder(16);
        emailResponse.setType("string");
        configProperties.add(emailResponse);

        // EMAIL Error Handling Section
        Property emailErrorHeader = new Property();
        emailErrorHeader.setName("email_error_handling_header");
        emailErrorHeader.setDisplayName("Email Error Handling");
        emailErrorHeader.setType("header");
        emailErrorHeader.setDisplayOrder(17);
        emailErrorHeader.setRequired(false);
        emailErrorHeader.setDescription("Configure Email error handling and debugging options");
        configProperties.add(emailErrorHeader);

        Property emailShowErrorInfo = new Property();
        emailShowErrorInfo.setName("EMAIL_SHOW_ERROR_INFO");
        emailShowErrorInfo.setDisplayName("Show Detailed Error Information");
        emailShowErrorInfo.setRequired(false);
        emailShowErrorInfo
                .setDescription("Enter \"true\" if detailed error information from Email provider needs to be " +
                        "displayed in the UI");
        emailShowErrorInfo.setDisplayOrder(18);
        emailShowErrorInfo.setType("boolean");
        configProperties.add(emailShowErrorInfo);

        Property emailValuesToBeMasked = new Property();
        emailValuesToBeMasked.setName("EMAIL_VALUES_TO_BE_MASKED_IN_ERROR_INFO");
        emailValuesToBeMasked.setDisplayName("Mask values in Error Info");
        emailValuesToBeMasked.setRequired(false);
        emailValuesToBeMasked
                .setDescription("Enter comma separated Values to be masked by * in the detailed error messages");
        emailValuesToBeMasked.setDisplayOrder(19);
        emailValuesToBeMasked.setType("string");
        configProperties.add(emailValuesToBeMasked);

        return configProperties;
    }

    @Override
    protected void initiateAuthenticationRequest(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {
        try {

            log.debug("################### start initiateAuthenticationRequest ################### ");
            String contextId = request.getParameter("sessionDataKey");
            String baseUrl = ConfigurationFacade.getInstance().getAuthenticationEndpointURL();
            String redirectUrl = baseUrl.replace("login.do", "otpChannelSelection.jsp");
            if (StringUtils.isNotEmpty(contextId)) {
                redirectUrl += "?sessionDataKey=" + java.net.URLEncoder.encode(contextId, "UTF-8");
            }
            // Actually redirect
            if (response != null) {
                response.sendRedirect(redirectUrl);
            } else {
                // fallback: try to get response from thread local (WSO2 style)
                javax.servlet.http.HttpServletResponse resp = null;
                org.apache.axis2.context.MessageContext axis2MsgCtx = org.apache.axis2.context.MessageContext.getCurrentMessageContext();
                if (axis2MsgCtx != null) {
                    Object responseObj = axis2MsgCtx.getProperty("HTTPServletResponse");
                    if (responseObj instanceof javax.servlet.http.HttpServletResponse) {
                        resp = (javax.servlet.http.HttpServletResponse) responseObj;
                        resp.sendRedirect(redirectUrl);
                    }
                }
            }
        } catch (Exception e) {
            log.error("Error redirecting to OTP channel selection page", e);
            throw new AuthenticationFailedException("Error redirecting to OTP channel selection page", e);
        }
    }

    @Override
    protected void processAuthenticationResponse(HttpServletRequest request, HttpServletResponse response,
            AuthenticationContext context) throws AuthenticationFailedException {
                log.debug("################### start processAuthenticationResponse ################### ");
        String otpChannel = request.getParameter("otpChannel");

        log.debug( "~~~~~~~ otpChannel => " + otpChannel);
        if ("sms".equalsIgnoreCase(otpChannel)) {
            // ดำเนินการ OTP ผ่าน SMS
            getSmsOTPAuthenticator().processAuthenticationResponse(request, response, context);
        } else if ("email".equalsIgnoreCase(otpChannel)) {
            // ดำเนินการ OTP ผ่าน Email
            getEmailOTPAuthenticator().processAuthenticationResponse(request, response, context);
        } else {
            throw new AuthenticationFailedException("Unknown OTP channel: " + otpChannel);
        }
    }

    @Override
    public String getContextIdentifier(HttpServletRequest request) {
        // Delegate to SMS authenticator since it has the same logic
        return getSmsOTPAuthenticator().getContextIdentifier(request);
    }

    /**
     * Common utility functions used by SMS OTP authenticator
     */

    public static String getErrorPage(AuthenticationContext context)
            throws AuthenticationFailedException {
        String errorPage = SMSOTPUtils.getErrorPageFromXMLFile(context);

        if (StringUtils.isEmpty(errorPage)) {
            errorPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(SMSOTPConstants.LOGIN_PAGE, SMSOTPConstants.ERROR_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used for SMS");
            }
        }
        return errorPage;
    }

    public static String getLoginPage(AuthenticationContext context)
            throws AuthenticationFailedException {
        String loginPage = SMSOTPUtils.getLoginPageFromXMLFile(context);

        if (StringUtils.isEmpty(loginPage)) {
            loginPage = ConfigurationFacade.getInstance().getAuthenticationEndpointURL()
                    .replace(SMSOTPConstants.LOGIN_PAGE, SMSOTPConstants.SMS_LOGIN_PAGE);
            if (log.isDebugEnabled()) {
                log.debug("Default authentication endpoint context is used for SMS");
            }
        }
        return loginPage;
    }

    public static String getURL(String baseURI, String queryParams, String authenticatorName) {
        String url;
        String nameOfAuthenticators = SMSOTPConstants.NAME_OF_AUTHENTICATORS;

        if (StringUtils.isNotEmpty(queryParams)) {
            url = baseURI + "?" + queryParams + "&" + nameOfAuthenticators + authenticatorName;
        } else {
            url = baseURI + "?" + nameOfAuthenticators + authenticatorName;
        }
        return url;
    }

    public static String getMaskedValue(AuthenticationContext context, String attributeValue, int noOfDigits) {
        String screenValue;
        String hiddenScreenValue;
        String digitsOrder = SMSOTPUtils.getDigitsOrder(context);

        int attributeLength = attributeValue.length();
        String backwardOrder = SMSOTPConstants.BACKWARD;

        if (backwardOrder.equals(digitsOrder)) {
            screenValue = attributeValue.substring(attributeLength - noOfDigits, attributeLength);
            hiddenScreenValue = attributeValue.substring(0, attributeLength - noOfDigits);
            for (int i = 0; i < hiddenScreenValue.length(); i++) {
                screenValue = ("*").concat(screenValue);
            }
        } else {
            screenValue = attributeValue.substring(0, noOfDigits);
            hiddenScreenValue = attributeValue.substring(noOfDigits, attributeLength);
            for (int i = 0; i < hiddenScreenValue.length(); i++) {
                screenValue = screenValue.concat("*");
            }
        }
        return screenValue;
    }

    /**
     * Redirect to SMS OTP error page with error messages
     */
    private void redirectToErrorPage(HttpServletResponse response, AuthenticationContext context,
            String errorMessage) throws AuthenticationFailedException {
        try {
            String queryParams = "";
            if (context != null) {
                queryParams = context.getContextIdIncludedQueryParams();
            }

            String errorPage = getErrorPage(context);
            String redirectUrl = getURL(errorPage, queryParams, getName());

            // Add error message parameters
            String errorParam = "";
            if (StringUtils.isNotEmpty(errorMessage)) {
                errorParam = "&authFailure=true&authFailureMsg=" + java.net.URLEncoder.encode(errorMessage, "UTF-8");
            }

            // Add error code if available
            if (context != null && context.getProperty(SMSOTPConstants.ERROR_CODE) != null) {
                errorParam += "&errorCode=" + java.net.URLEncoder
                        .encode(context.getProperty(SMSOTPConstants.ERROR_CODE).toString(), "UTF-8");
            }

            // Add error info if available and configured to show
            if (context != null && context.getAuthenticatorProperties() != null) {
                Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
                if (context.getProperty(SMSOTPConstants.ERROR_INFO) != null &&
                        Boolean.parseBoolean(authenticatorProperties.get(SMSOTPConstants.SHOW_ERROR_INFO))) {
                    String errorInfo = context.getProperty(SMSOTPConstants.ERROR_INFO).toString();
                    try {
                        errorParam += "&errorInfo="
                                + java.util.Base64.getEncoder().encodeToString(errorInfo.getBytes("UTF-8"));
                    } catch (java.io.UnsupportedEncodingException e) {
                        log.warn("UTF-8 encoding not supported, using default encoding", e);
                        errorParam += "&errorInfo="
                                + java.util.Base64.getEncoder().encodeToString(errorInfo.getBytes());
                    }
                }
            }

            String finalRedirectUrl = redirectUrl + errorParam;

            if (log.isDebugEnabled()) {
                log.debug("Redirecting to error page: " + finalRedirectUrl);
            }

            response.sendRedirect(finalRedirectUrl);

        } catch (java.io.IOException e) {
            log.error("Error redirecting to error page", e);
            throw new AuthenticationFailedException("Error redirecting to error page", e);
        }
    }

    /**
     * Determines the OTP type to use (SMS or EMAIL)
     * Can be configured via request parameter, authenticator properties, or default logic
     */
    private String determineOTPType(HttpServletRequest request, AuthenticationContext context) {
        // Check if OTP type is specified in request parameter
        String requestOtpType = request.getParameter("otpType");
        if (StringUtils.isNotEmpty(requestOtpType)) {
            if ("sms".equalsIgnoreCase(requestOtpType) || "email".equalsIgnoreCase(requestOtpType)) {
                return requestOtpType.toLowerCase();
            }
        }
        
        // Check if OTP type is configured in authenticator properties
        if (context != null && context.getAuthenticatorProperties() != null) {
            Map<String, String> authenticatorProperties = context.getAuthenticatorProperties();
            String configuredOtpType = authenticatorProperties.get("DEFAULT_OTP_TYPE");
            if (StringUtils.isNotEmpty(configuredOtpType)) {
                if ("sms".equalsIgnoreCase(configuredOtpType) || "email".equalsIgnoreCase(configuredOtpType)) {
                    return configuredOtpType.toLowerCase();
                }
            }
        }
        
        // Default to SMS OTP for backward compatibility
        return "sms";
    }
}
