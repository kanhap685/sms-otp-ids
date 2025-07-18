<%@ page language="java" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.util.Map" %>
<%@ page import="java.util.HashMap" %>
<%@ page import="java.net.URLEncoder" %>
<%@ page import="java.net.URLDecoder" %>
<%@ page import="org.owasp.encoder.Encode" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.framework.context.AuthenticationContext" %>
<%@ page import="org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils" %>

<%
    // Extract URL parameters
    String sessionDataKey = request.getParameter("sessionDataKey");
    
    // OTP related parameters
    String Code = request.getParameter("Code");
    String authFailure = request.getParameter("authFailure");
    String authFailureMsg = request.getParameter("authFailureMsg");
    String screenvalue = request.getParameter("screenvalue");
    
    // Determine OTP type (SMS or EMAIL) from context
    String otpType = "SMS"; // Default
    String contactMethod = "mobile number"; // Default
    String contactIcon = "📱"; // Default
    String maskedContact = "";
    String otpPayload = null;
    
    // Get OTP information from authentication context (secure method)
    String actualOtpSent = null;
    String otpSentTimeStr = null;
    String tokenValidityTimeStr = null;
    
    try {
        AuthenticationContext authContext = FrameworkUtils.getAuthenticationContextFromCache(sessionDataKey);
        System.out.println("DEBUG: AuthenticationContext retrieved: " + (authContext != null ? "SUCCESS" : "NULL"));
        System.out.println("DEBUG: SessionDataKey: " + sessionDataKey);
        
        if (authContext != null) {
            // Get OTP type
            String contextOtpType = (String) authContext.getProperty("OTP_TYPE");
            if ("EMAIL".equals(contextOtpType)) {
                otpType = "EMAIL";
                contactMethod = "email address";
                contactIcon = "📧";
            }
            
            // Get masked contact information
            if ("EMAIL".equals(otpType)) {
                maskedContact = (String) authContext.getProperty("MASKED_EMAIL");
                if (maskedContact == null) {
                    maskedContact = (String) authContext.getProperty("screenValue");
                }
                // Get email payload
                otpPayload = (String) authContext.getProperty("EMAIL_PAYLOAD_CONFIG");
                if (otpPayload == null) {
                    otpPayload = (String) authContext.getProperty("SMS_PAYLOAD_CONFIG"); // Fallback
                }
            } else {
                // For SMS OTP, try MASKED_MOBILE first, then screenValue as fallback
                maskedContact = (String) authContext.getProperty("MASKED_MOBILE");
                if (maskedContact == null) {
                    maskedContact = (String) authContext.getProperty("screenValue");
                }
                // Get SMS payload
                otpPayload = (String) authContext.getProperty("SMS_PAYLOAD_CONFIG");
            }
            
            actualOtpSent = (String) authContext.getProperty("CLIENT_OTP_VALIDATION");
            
            // Get OTP timing information
            Long sentTime = (Long) authContext.getProperty("sentOTPTokenTime");
            Long validityTime = (Long) authContext.getProperty("tokenValidityTime");
            
            if (sentTime != null) {
                otpSentTimeStr = sentTime.toString();
            }
            if (validityTime != null) {
                tokenValidityTimeStr = validityTime.toString();
            }
            
            System.out.println("DEBUG: OTP Type: " + otpType);
            System.out.println("DEBUG: Contact Method: " + contactMethod);
            System.out.println("DEBUG: Masked Contact: " + maskedContact);
            System.out.println("DEBUG: actualOtpSent from CLIENT_OTP_VALIDATION: " + actualOtpSent);
            System.out.println("DEBUG: OTP Sent Time: " + otpSentTimeStr);
            System.out.println("DEBUG: Token Validity Time (minutes): " + tokenValidityTimeStr);
            
            // Log all context properties for debugging
            System.out.println("DEBUG: All context properties:");
            if (authContext.getProperties() != null) {
                for (Object key : authContext.getProperties().keySet()) {
                    Object value = authContext.getProperty(key.toString());
                    System.out.println("  " + key + " = " + value);
                }
            }
        }
    } catch (Exception e) {
        System.out.println("DEBUG: Exception getting AuthenticationContext: " + e.getMessage());
        e.printStackTrace();
        // Fallback to parameter if context access fails
        actualOtpSent = request.getParameter("actualOtpSent");
        System.out.println("DEBUG: actualOtpSent from request parameter: " + actualOtpSent);
    }
    
    // Legacy SMS Payload parameter handling (for backward compatibility)
    String smsPayload = otpPayload;
    if (smsPayload == null) {
        smsPayload = request.getParameter("smsPayload");
    }
    
    // Decode if needed
    if (smsPayload != null) {
        try {
            smsPayload = URLDecoder.decode(smsPayload, "UTF-8");
        } catch (Exception e) {
            smsPayload = null;
        }
    }
    
    // Use screenvalue parameter as fallback if maskedContact is not available
    if (maskedContact == null || maskedContact.isEmpty()) {
        maskedContact = screenvalue;
    }
    
    // Error handling
    String errorMessage = "";
    boolean hasError = false;
    if ("true".equals(authFailure) && authFailureMsg != null) {
        hasError = true;
        if ("authentication.fail.message".equals(authFailureMsg)) {
            errorMessage = "Authentication failed. Please check your " + otpType + " OTP code.";
        } else if ("code.mismatch".equals(authFailureMsg)) {
            errorMessage = "Invalid " + otpType + " OTP code. Please try again.";
        } else if ("token.expired".equals(authFailureMsg)) {
            errorMessage = otpType + " OTP has expired. Please request a new code.";
        } else if ("login.reinitiate.message".equals(authFailureMsg)) {
            hasError = false;
            //errorMessage = "Please check the " + otpType + " OTP code sent to your " + contactMethod + " and try again.";
        } else if (authFailureMsg.contains("session expired") || authFailureMsg.contains("Session expired")) {
            errorMessage = "Your session has expired. Please try again.";
        } else if (authFailureMsg.contains("not found") || authFailureMsg.contains("Not found")) {
            errorMessage = "User not found. Please contact your administrator.";
        } else if (authFailureMsg.contains("Invalid") || authFailureMsg.contains("invalid")) {
            errorMessage = authFailureMsg; // Use the specific error message
        } else {
            // For custom error messages, use them directly
            errorMessage = authFailureMsg.length() > 100 ? 
                "Authentication failed. Please try again." : authFailureMsg;
        }
    }
    
    // Build the form action URL with all necessary parameters
    StringBuilder actionUrl = new StringBuilder();
    // Use relative path for better compatibility across environments
    actionUrl.append("../../commonauth");
    
    // Build query parameters for form submission
    Map<String, String> hiddenParams = new HashMap<>();
    if (sessionDataKey != null) hiddenParams.put("sessionDataKey", sessionDataKey);
    
%>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title><%= Encode.forHtml(otpType) %> OTP Verification - WSO2 Identity Server</title>
    <style>
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            margin: 0;
            padding: 0;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }

        .container {
            background: white;
            border-radius: 12px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            padding: 40px;
            width: 100%;
            max-width: 400px;
            text-align: center;
        }

        .logo {
            margin-bottom: 30px;
        }

        .logo img {
            height: 60px;
            width: auto;
        }

        h1 {
            color: #333;
            margin-bottom: 10px;
            font-size: 24px;
            font-weight: 600;
        }

        .subtitle {
            color: #666;
            margin-bottom: 30px;
            font-size: 14px;
        }

        .mobile-info {
            background: #f8f9fa;
            border: 1px solid #e9ecef;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 20px;
            font-size: 14px;
            color: #495057;
        }

        .form-group {
            margin-bottom: 20px;
            text-align: center;
        }

        label {
            display: block;
            margin-bottom: 8px;
            color: #333;
            font-weight: 500;
            font-size: 14px;
        }

        .otp-container {
            display: flex;
            justify-content: center !important;
            gap: 8px;
            margin-bottom: 20px;
            flex-wrap: wrap;
            align-items: center;
        }

        .otp-input {
            width: 50px;
            height: 50px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 18px;
            text-align: center;
            font-weight: 600;
            transition: all 0.3s ease;
            box-sizing: border-box;
            flex-shrink: 0;
        }

        .otp-input:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            transform: scale(1.05);
        }

        .otp-input.filled {
            border-color: #28a745;
            background-color: #f8fff9;
        }

        .hidden-input {
            position: absolute;
            left: -9999px;
            opacity: 0;
        }

        .btn {
            width: 100%;
            padding: 12px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.3s ease;
            margin-bottom: 10px;
        }

        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }

        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 25px rgba(102, 126, 234, 0.3);
        }

        .btn-secondary {
            background: #f8f9fa;
            color: #495057;
            border: 1px solid #dee2e6;
        }

        .btn-secondary:hover {
            background: #e9ecef;
        }

        .error-message {
            background: #f8d7da;
            color: #721c24;
            border: 1px solid #f5c6cb;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 20px;
            font-size: 14px;
        }

        .success-message {
            background: #d4edda;
            color: #155724;
            border: 1px solid #c3e6cb;
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 20px;
            font-size: 14px;
        }

        .footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid #e9ecef;
            font-size: 12px;
            color: #6c757d;
        }

        @media (max-width: 480px) {
            .container {
                margin: 20px;
                padding: 30px 20px;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <!-- WSO2 Logo placeholder - you can replace with actual logo -->
            <div style="width: 60px; height: 60px; background: #667eea; border-radius: 50%; margin: 0 auto; display: flex; align-items: center; justify-content: center; color: white; font-weight: bold; font-size: 20px;">
                AIS
            </div>
        </div>

        <h1><%= Encode.forHtml(otpType) %> OTP Verification</h1>
        <p class="subtitle">Enter the verification code sent to your <%= Encode.forHtml(contactMethod) %></p>

        <% if (hasError) { %>
        <div class="error-message" id="serverError">
            <%= Encode.forHtml(errorMessage) %>
        </div>
        <% } %>
        
        <!-- Client-side error message container -->
        <div class="error-message" id="clientError" style="display: none;">
        </div>

        <% if ("true".equals(Code)) { %>
        <div class="success-message">
            A new verification code has been sent to your <%= Encode.forHtml(contactMethod) %>.
        </div>
        <% } %>

        <form id="otpForm" action="<%= Encode.forHtmlAttribute(actionUrl.toString()) %>" method="POST">
            <!-- Hidden parameters -->
            <% for (Map.Entry<String, String> param : hiddenParams.entrySet()) { %>
            <input type="hidden" name="<%= Encode.forHtmlAttribute(param.getKey()) %>" value="<%= Encode.forHtmlAttribute(param.getValue()) %>" />
            <% } %>

            <div class="form-group">
                <label class="otp-label" for="otp1" id="otpLabel">
                    <%= "EMAIL".equals(otpType) ? 
                        "กรุณาใส่รหัสผ่านที่ได้รับทาง Email" : 
                        "กรุณาใส่รหัสผ่านที่ได้รับทาง SMS" %>
                    <% if (maskedContact != null && !maskedContact.isEmpty()) { %>
                        <br><small style="color: #666; font-weight: normal;">
                            Sent to: <%= Encode.forHtml(contactIcon) %> <%= Encode.forHtml(maskedContact) %>
                        </small>
                    <% } %>
                </label>
                <div class="otp-container" style="justify-content: center;">
                    <input type="text" class="otp-input" id="otp1" maxlength="1" pattern="[0-9]" autocomplete="off" autofocus>
                    <input type="text" class="otp-input" id="otp2" maxlength="1" pattern="[0-9]" autocomplete="off">
                    <input type="text" class="otp-input" id="otp3" maxlength="1" pattern="[0-9]" autocomplete="off">
                    <input type="text" class="otp-input" id="otp4" maxlength="1" pattern="[0-9]" autocomplete="off">
                    <input type="text" class="otp-input" id="otp5" maxlength="1" pattern="[0-9]" autocomplete="off" style="display: none;">
                    <input type="text" class="otp-input" id="otp6" maxlength="1" pattern="[0-9]" autocomplete="off" style="display: none;">
                    <input type="text" class="otp-input" id="otp7" maxlength="1" pattern="[0-9]" autocomplete="off" style="display: none;">
                    <input type="text" class="otp-input" id="otp8" maxlength="1" pattern="[0-9]" autocomplete="off" style="display: none;">
                </div>
                <!-- Hidden input for form submission -->
                <input type="hidden" id="otpToken" name="OTPcode" required />
            </div>

            <button type="submit" class="btn btn-primary" id="verifyBtn">
                Verify Code
            </button>
        </form>

        <form >
            <button type="button" class="btn btn-secondary" onclick="clearOtpInputs();">
                Reset Code
            </button>
        </form>

        <div class="footer">
            <p>Powered by JOHN Kanha Pakkhemaya</p>
            <p>If you continue to have issues, please contact your administrator.</p>
        </div>

        <!-- Hidden fields for SMS payload -->
        <% if (smsPayload != null && !smsPayload.isEmpty()) { %>
        <input type="hidden" id="smsPayloadData" value="<%= Encode.forHtmlAttribute(smsPayload) %>" />
        <% } %>
        
        <!-- Hidden field for actual OTP sent -->
        <% if (actualOtpSent != null && !actualOtpSent.isEmpty()) { %>
        <input type="hidden" id="actualOtpSentData" value="<%= Encode.forHtmlAttribute(actualOtpSent) %>" />
        <% } %>
        
        <!-- Hidden fields for OTP timing -->
        <% if (otpSentTimeStr != null && !otpSentTimeStr.isEmpty()) { %>
        <input type="hidden" id="otpSentTimeData" value="<%= Encode.forHtmlAttribute(otpSentTimeStr) %>" />
        <% } %>
        
        <% if (tokenValidityTimeStr != null && !tokenValidityTimeStr.isEmpty()) { %>
        <input type="hidden" id="tokenValidityTimeData" value="<%= Encode.forHtmlAttribute(tokenValidityTimeStr) %>" />
        <% } %>
    </div>

    <script>
        // Define OTP type and contact information variables
        const otpType = '<%= Encode.forJavaScript(otpType) %>';
        const contactMethod = '<%= Encode.forJavaScript(contactMethod) %>';
        const contactIcon = '<%= Encode.forJavaScript(contactIcon) %>';
        const maskedContactInfo = '<%= maskedContact != null ? Encode.forJavaScript(maskedContact) : "" %>';
        
        // Server-provided timing information
        let serverOtpSentTime = null;
        let serverTokenValidityMinutes = null;
        
        // Try to get server timing data from hidden fields
        const otpSentTimeElement = document.getElementById('otpSentTimeData');
        const tokenValidityElement = document.getElementById('tokenValidityTimeData');
        
        if (otpSentTimeElement && otpSentTimeElement.value) {
            try {
                serverOtpSentTime = parseInt(otpSentTimeElement.value);
                // console.log('DEBUG: Server OTP sent time retrieved:', serverOtpSentTime);
            } catch (e) {
                // console.log('DEBUG: Error parsing server OTP sent time:', e);
            }
        }
        
        if (tokenValidityElement && tokenValidityElement.value) {
            try {
                serverTokenValidityMinutes = parseFloat(tokenValidityElement.value);
                // console.log('DEBUG: Server token validity retrieved:', serverTokenValidityMinutes);
            } catch (e) {
                // console.log('DEBUG: Error parsing server token validity:', e);
            }
        }
        
        document.addEventListener('DOMContentLoaded', function() {
            const otpInputs = document.querySelectorAll('.otp-input');
            const hiddenOtpInput = document.getElementById('otpToken');
            const verifyBtn = document.getElementById('verifyBtn');
            const otpForm = document.getElementById('otpForm');
            
            // OTP session storage keys
            const otpCreationTimeKey = 'otpCreationTime_' + '<%= Encode.forJavaScript(sessionDataKey) %>';
            const otpExpiredFlagKey = 'otpExpired_' + '<%= Encode.forJavaScript(sessionDataKey) %>';

            // Auto-focus on first OTP input
            otpInputs[0].focus();

            // Check if there's a server error and handle it
            const serverError = document.getElementById('serverError');
            if (serverError && serverError.style.display !== 'none') {
                // If there's a server error, trigger OTP error handling
                setTimeout(() => {
                    const errorText = serverError.textContent || serverError.innerText;
                    if (errorText.includes('Invalid') || errorText.includes('ไม่ถูกต้อง') || 
                        errorText.includes('mismatch') || errorText.includes('fail')) {
                        // Apply error styling to inputs
                        otpInputs.forEach(input => {
                            if (!input.disabled) {
                                input.style.borderColor = '#dc3545';
                                input.style.backgroundColor = '#fff5f5';
                                input.style.animation = 'shake 0.5s ease-in-out';
                            }
                        });
                        
                        // Clear inputs for retry
                        clearOtpInputs();
                        
                        // Remove error styling after 3 seconds
                        setTimeout(() => {
                            otpInputs.forEach(input => {
                                input.style.borderColor = '#e1e5e9';
                                input.style.backgroundColor = '';
                                input.style.animation = '';
                            });
                        }, 3000);
                    }
                }, 100);
            }

            // Get actual OTP sent from backend via hidden field
            const actualOtpElement = document.getElementById('actualOtpSentData');
            let actualOtpSent = null;
            
            if (actualOtpElement && actualOtpElement.value) {
                actualOtpSent = actualOtpElement.value;
            }

            // Get OTP timing information from server
            const otpSentTimeElement = document.getElementById('otpSentTimeData');
            const tokenValidityElement = document.getElementById('tokenValidityTimeData');
            
            let serverOtpSentTime = null;
            let serverTokenValidityMinutes = null;
            
            if (otpSentTimeElement && otpSentTimeElement.value) {
                serverOtpSentTime = parseInt(otpSentTimeElement.value);
                // console.log('DEBUG: Server OTP sent time:', serverOtpSentTime, 'Date:', new Date(serverOtpSentTime));
            }
            
            if (tokenValidityElement && tokenValidityElement.value) {
                serverTokenValidityMinutes = parseFloat(tokenValidityElement.value);
                // console.log('DEBUG: Server token validity (minutes):', serverTokenValidityMinutes);
            }

            // Process SMS payload if available
            const smsPayloadElement = document.getElementById('smsPayloadData');
            let expectedOtpLength = 4; // Default OTP length
            let lifeTimeoutMinutes = 0.5; // Default 30 seconds (0.5 minutes)
            
            // console.log('DEBUG: smsPayloadElement exists:', !!smsPayloadElement);
            // console.log('DEBUG: smsPayloadElement.value:', smsPayloadElement ? smsPayloadElement.value : 'null');
            
            if (smsPayloadElement && smsPayloadElement.value) {
                try {
                    const rawPayload = smsPayloadElement.value;
                    // console.log('DEBUG: Raw SMS payload string:', rawPayload);
                    
                    const smsPayload = JSON.parse(rawPayload);
                    // console.log('DEBUG: Parsed SMS Payload:', smsPayload);
                    // console.log('DEBUG: SMS Payload type:', typeof smsPayload);
                    // console.log('DEBUG: SMS Payload keys:', Object.keys(smsPayload));
                    
                    // Try multiple possible structures to find otpDigit
                    let foundOtpDigit = null;
                    
                    // Structure 1: smsPayload.sendOneTimePW.otpDigit
                    if (smsPayload && smsPayload.sendOneTimePW && smsPayload.sendOneTimePW.otpDigit) {
                        foundOtpDigit = smsPayload.sendOneTimePW.otpDigit;
                        // console.log('DEBUG: Found otpDigit in sendOneTimePW structure:', foundOtpDigit);
                    }
                    // Structure 2: smsPayload.otpDigit (direct)
                    else if (smsPayload && smsPayload.otpDigit) {
                        foundOtpDigit = smsPayload.otpDigit;
                        // console.log('DEBUG: Found otpDigit directly in payload:', foundOtpDigit);
                    }
                    // Structure 3: Search all nested objects for otpDigit
                    else {
                        function searchForOtpDigit(obj, path = '') {
                            if (obj && typeof obj === 'object') {
                                for (const key in obj) {
                                    if (obj.hasOwnProperty(key)) {
                                        const currentPath = path ? `${path}.${key}` : key;
                                        // console.log(`DEBUG: Checking path ${currentPath}:`, obj[key]);
                                        
                                        if (key === 'otpDigit' && obj[key]) {
                                            // console.log(`DEBUG: Found otpDigit at path ${currentPath}:`, obj[key]);
                                            return obj[key];
                                        }
                                        
                                        if (typeof obj[key] === 'object') {
                                            const result = searchForOtpDigit(obj[key], currentPath);
                                            if (result) return result;
                                        }
                                    }
                                }
                            }
                            return null;
                        }
                        
                        foundOtpDigit = searchForOtpDigit(smsPayload);
                        if (foundOtpDigit) {
                            // console.log('DEBUG: Found otpDigit through deep search:', foundOtpDigit);
                        }
                    }
                    
                    // Apply the found OTP digit length
                    if (foundOtpDigit) {
                        const parsedOtpLength = parseInt(foundOtpDigit);
                        if (!isNaN(parsedOtpLength) && parsedOtpLength > 0 && parsedOtpLength <= 8) {
                            expectedOtpLength = parsedOtpLength;
                            // console.log('DEBUG: Successfully set expectedOtpLength to:', expectedOtpLength);
                        } else {
                            // console.log('DEBUG: Invalid otpDigit value:', foundOtpDigit, 'keeping default:', expectedOtpLength);
                        }
                    } else {
                        // console.log('DEBUG: otpDigit not found in payload, using default:', expectedOtpLength);
                    }
                    
                    // Extract lifeTimeoutMins from payload structure (similar approach)
                    let foundLifeTimeout = null;
                    if (smsPayload && smsPayload.sendOneTimePW && smsPayload.sendOneTimePW.lifeTimeoutMins) {
                        foundLifeTimeout = smsPayload.sendOneTimePW.lifeTimeoutMins;
                    } else if (smsPayload && smsPayload.lifeTimeoutMins) {
                        foundLifeTimeout = smsPayload.lifeTimeoutMins;
                    } else {
                        // Search for lifeTimeoutMins in nested objects
                        function searchForLifeTimeout(obj) {
                            if (obj && typeof obj === 'object') {
                                for (const key in obj) {
                                    if (obj.hasOwnProperty(key)) {
                                        if (key === 'lifeTimeoutMins' && obj[key]) {
                                            return obj[key];
                                        }
                                        if (typeof obj[key] === 'object') {
                                            const result = searchForLifeTimeout(obj[key]);
                                            if (result) return result;
                                        }
                                    }
                                }
                            }
                            return null;
                        }
                        foundLifeTimeout = searchForLifeTimeout(smsPayload);
                    }
                    
                    if (foundLifeTimeout) {
                        const parsedLifeTimeout = parseFloat(foundLifeTimeout);
                        if (!isNaN(parsedLifeTimeout) && parsedLifeTimeout > 0) {
                            lifeTimeoutMinutes = parsedLifeTimeout;
                            // console.log('DEBUG: Successfully set lifeTimeoutMinutes to:', lifeTimeoutMinutes);
                        }
                    }
                    
                } catch (e) {
                    console.error('DEBUG: Error parsing SMS payload:', e);
                    // console.log('DEBUG: Raw payload value:', smsPayloadElement.value);
                    // Use default values if parsing fails
                }
            } else {
                // console.log('DEBUG: No SMS payload element found or empty value');
            }
            
            // Adjust OTP inputs based on expected length from SMS payload
            const activeOtpLength = Math.min(Math.max(expectedOtpLength, 1), 8); // Ensure between 1-8 digits
            
            // console.log('DEBUG: Final configuration:');
            // console.log('  - expectedOtpLength:', expectedOtpLength);
            // console.log('  - activeOtpLength:', activeOtpLength);
            // console.log('  - lifeTimeoutMinutes:', lifeTimeoutMinutes);
            // console.log('  - otpType:', otpType);
            // console.log('  - actualOtpSent:', actualOtpSent);
            
            // Show/hide OTP inputs based on required length
            otpInputs.forEach((input, index) => {
                if (index < activeOtpLength) {
                    input.style.display = 'block';
                    input.disabled = false;
                } else {
                    input.style.display = 'none';
                    input.disabled = true;
                    input.value = ''; // Clear disabled inputs
                }
            });
            
            // Adjust container layout for better spacing
            const otpContainer = document.querySelector('.otp-container');
            if (activeOtpLength > 6) {
                otpContainer.style.gap = '6px'; // Smaller gap for more inputs
            } else if (activeOtpLength <= 4) {
                otpContainer.style.justifyContent = 'space-between';
            } else {
                otpContainer.style.justifyContent = 'center';
            }

            // Handle OTP input behavior
            otpInputs.forEach((input, index) => {
                input.addEventListener('input', function(e) {
                    // Check if OTP has expired before allowing input
                    const expiredFlag = sessionStorage.getItem(otpExpiredFlagKey);
                    if (expiredFlag === 'true' || isOtpExpired()) {
                        e.preventDefault();
                        this.value = '';
                        showOtpExpiredError();
                        return;
                    }
                    
                    const originalValue = e.target.value;
                    
                    // Check if non-numeric characters were entered
                    if (originalValue && !/^\d*$/.test(originalValue)) {
                        showOtpError('รหัส OTP ต้องเป็นตัวเลขเท่านั้น / OTP code must contain only numbers.');
                        return;
                    }
                    
                    // Only allow numeric input
                    this.value = this.value.replace(/[^0-9]/g, '');
                    
                    // Move to next input if current is filled and not the last active input
                    if (this.value.length === 1 && index < activeOtpLength - 1) {
                        otpInputs[index + 1].focus();
                    }
                    
                    // Update visual state
                    this.classList.toggle('filled', this.value.length === 1);
                    
                    // Update hidden input with complete OTP
                    updateHiddenOtpInput();
                    
                    // Check if OTP is complete and validate immediately if we have the actual OTP
                    const currentOtp = getOtpValue();
                    if (currentOtp.length === activeOtpLength && actualOtpSent && actualOtpSent.trim() !== '') {
                        const cleanActualOtp = actualOtpSent.replace(/[^0-9]/g, '');
                        if (cleanActualOtp && currentOtp !== cleanActualOtp) {
                            setTimeout(() => {
                                const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
                                showOtpError(`รหัส ${methodText} OTP ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง / Invalid ${methodText} OTP code. Please try again.`);
                                // console.log('DEBUG: Real-time OTP Mismatch - User:', currentOtp, 'Expected:', cleanActualOtp);
                            }, 1500); // Small delay to let user finish typing
                        }
                    }
                });

                input.addEventListener('focus', function(e) {
                    // Check if OTP has expired before allowing focus
                    const expiredFlag = sessionStorage.getItem(otpExpiredFlagKey);
                    if (expiredFlag === 'true' || isOtpExpired()) {
                        e.preventDefault();
                        this.blur();
                        showOtpExpiredError();
                        return;
                    }
                    this.select();
                });

                input.addEventListener('keydown', function(e) {
                    // Check if OTP has expired before allowing keydown
                    const expiredFlag = sessionStorage.getItem(otpExpiredFlagKey);
                    if (expiredFlag === 'true' || isOtpExpired()) {
                        e.preventDefault();
                        showOtpExpiredError();
                        return;
                    }
                    
                    // Handle backspace
                    if (e.key === 'Backspace') {
                        if (this.value === '' && index > 0) {
                            otpInputs[index - 1].focus();
                            otpInputs[index - 1].value = '';
                            otpInputs[index - 1].classList.remove('filled');
                            updateHiddenOtpInput();
                        } else if (this.value !== '') {
                            this.value = '';
                            this.classList.remove('filled');
                            updateHiddenOtpInput();
                        }
                    }
                    
                    // Handle arrow keys
                    if (e.key === 'ArrowLeft' && index > 0) {
                        otpInputs[index - 1].focus();
                    }
                    if (e.key === 'ArrowRight' && index < otpInputs.length - 1) {
                        otpInputs[index + 1].focus();
                    }
                });

                input.addEventListener('paste', function(e) {
                    // Check if OTP has expired before allowing paste
                    const expiredFlag = sessionStorage.getItem(otpExpiredFlagKey);
                    if (expiredFlag === 'true' || isOtpExpired()) {
                        e.preventDefault();
                        showOtpExpiredError();
                        return;
                    }
                    
                    e.preventDefault();
                    const pasteData = e.clipboardData.getData('text').replace(/[^0-9]/g, '');
                    
                    if (pasteData.length === activeOtpLength) {
                        // Fill all inputs with pasted data - let server validate
                        for (let i = 0; i < activeOtpLength; i++) {
                            if (pasteData[i]) {
                                otpInputs[i].value = pasteData[i];
                                otpInputs[i].classList.add('filled');
                            }
                        }
                        updateHiddenOtpInput();
                        
                        // Show success message for paste
                        // console.log('DEBUG: OTP pasted successfully:', pasteData);
                    } else {
                        showOtpError(`กรุณาใส่รหัส OTP ให้ครบ ${activeOtpLength} หลัก / Please enter a complete ${activeOtpLength}-digit OTP code.`);
                    }
                });
            });

            function getOtpValue() {
                // Only get values from enabled inputs (those within activeOtpLength)
                let otpValue = '';
                for (let i = 0; i < activeOtpLength; i++) {
                    if (otpInputs[i] && !otpInputs[i].disabled) {
                        otpValue += otpInputs[i].value || '';
                    }
                }
                return otpValue;
            }

            function updateHiddenOtpInput() {
                const otpValue = getOtpValue();
                hiddenOtpInput.value = otpValue;
            }

            function clearOtpInputs() {
                // Clear only OTP input fields
                otpInputs.forEach(input => {
                    input.value = '';
                    input.classList.remove('filled');
                });
                hiddenOtpInput.value = '';
                otpInputs[0].focus(); // Focus back to first input
            }

            // Make clearOtpInputs available globally
            window.clearOtpInputs = clearOtpInputs;

            function showOtpError(message) {
                // Hide server error and show client error
                const serverError = document.getElementById('serverError');
                const clientError = document.getElementById('clientError');
                
                if (serverError) {
                    serverError.style.display = 'none';
                }
                
                if (clientError) {
                    clientError.textContent = message;
                    clientError.style.display = 'block';
                    
                    // Auto-hide after 5 seconds
                    setTimeout(() => {
                        clientError.style.display = 'none';
                    }, 5000);
                }
                
                // Add visual error state to inputs
                otpInputs.forEach(input => {
                    if (!input.disabled) {
                        input.style.borderColor = '#dc3545';
                        input.style.backgroundColor = '#fff5f5';
                        input.style.animation = 'shake 0.5s ease-in-out';
                    }
                });
                
                // Also show alert for immediate attention
                // alert(message);
                
                // Remove error styling after 3 seconds
                setTimeout(() => {
                    otpInputs.forEach(input => {
                        input.style.borderColor = '#e1e5e9';
                        input.style.backgroundColor = '';
                        input.style.animation = '';
                    });
                }, 3000);
                
                // Clear inputs and focus on first
                clearOtpInputs();
            }

            // Add CSS animation for shake effect
            const style = document.createElement('style');
            style.textContent = `
                @keyframes shake {
                    0%, 100% { transform: translateX(0); }
                    25% { transform: translateX(-5px); }
                    75% { transform: translateX(5px); }
                }
            `;
            document.head.appendChild(style);

            // Handle form submission
            if (otpForm) {
                otpForm.addEventListener('submit', function(e) {
                    const otpValue = getOtpValue();
                    
                    // Check if OTP has expired
                    const expiredFlag = sessionStorage.getItem(otpExpiredFlagKey);
                    if (expiredFlag === 'true' || isOtpExpired()) {
                        e.preventDefault();
                        const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
                        showOtpError(`รหัส ${methodText} OTP หมดอายุแล้ว กรุณาขอรหัสใหม่ / ${methodText} OTP has expired. Please request a new code.`);
                        showOtpExpiredError(); // Also disable the form
                        return;
                    }
                    
                    // Basic client-side validation only
                    if (otpValue.length !== activeOtpLength) {
                        e.preventDefault();
                        const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
                        showOtpError(`กรุณากรอกรหัส ${methodText} OTP ให้ครบ ${activeOtpLength} หลัก / Please enter a complete ${activeOtpLength}-digit ${methodText} OTP code.`);
                        return;
                    }

                    // Validate that OTP contains only numbers
                    if (!/^\d+$/.test(otpValue)) {
                        e.preventDefault();
                        const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
                        showOtpError(`รหัส ${methodText} OTP ต้องเป็นตัวเลขเท่านั้น / ${methodText} OTP code must contain only numbers.`);
                        return;
                    }

                    // Optional: Check OTP against actual OTP sent (if available) for immediate feedback
                    if (actualOtpSent && actualOtpSent.trim() !== '') {
                        const cleanActualOtp = actualOtpSent.replace(/[^0-9]/g, '');
                        if (cleanActualOtp && otpValue !== cleanActualOtp) {
                            e.preventDefault();
                            const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
                            showOtpError(`รหัส ${methodText} OTP ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง / Invalid ${methodText} OTP code. Please try again.`);
                            // console.log('DEBUG: OTP Mismatch - User:', otpValue, 'Expected:', cleanActualOtp);
                            return;
                        }
                    }

                    // Let server handle OTP validation for final verification
                    // console.log('DEBUG: Submitting OTP for server validation:', otpValue);
                    // console.log('DEBUG: Expected OTP from server:', actualOtpSent);

                    // Show loading state
                    verifyBtn.textContent = 'Verifying...';
                    verifyBtn.disabled = true;
                    
                    // Add a timeout to handle potential hanging requests
                    setTimeout(() => {
                        if (verifyBtn.textContent === 'Verifying...') {
                            verifyBtn.textContent = 'Verify Code';
                            verifyBtn.disabled = false;
                            showOtpError('หมดเวลาการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง / Request timeout. Please try again.');
                        }
                    }, 30000); // 30 second timeout
                });
            }

            // OTP countdown timer - use server time if available, otherwise fallback to sessionStorage
            let otpCreationTime = null;
            const otpLabel = document.getElementById('otpLabel');
            
            // Use server-provided OTP sent time if available
            if (serverOtpSentTime) {
                otpCreationTime = serverOtpSentTime;
                // console.log('DEBUG: Using server OTP sent time:', otpCreationTime);
                // Store in sessionStorage for consistency across refreshes
                sessionStorage.setItem(otpCreationTimeKey, otpCreationTime.toString());
                // Clear any expired flag since we have fresh server data
                sessionStorage.removeItem(otpExpiredFlagKey);
            } else {
                // Check if OTP was previously marked as expired
                const expiredFlag = sessionStorage.getItem(otpExpiredFlagKey);
                
                if (expiredFlag === 'true') {
                    // OTP was previously marked as expired, keep it expired
                    // console.log('DEBUG: OTP was previously expired, maintaining expired state');
                    showOtpExpiredError();
                    return; // Don't continue with countdown
                }
                
                // Fallback to sessionStorage for creation time
                const storedTime = sessionStorage.getItem(otpCreationTimeKey);
                
                if (storedTime) {
                    otpCreationTime = parseInt(storedTime);
                    // console.log('DEBUG: Using stored OTP creation time:', otpCreationTime);
                } else {
                    // First time loading, use current time (fallback)
                    otpCreationTime = Date.now();
                    sessionStorage.setItem(otpCreationTimeKey, otpCreationTime.toString());
                    // console.log('DEBUG: No server time or stored time, using current time:', otpCreationTime);
                }
            }
            
            // Use server token validity if available, otherwise use parsed payload value
            let actualLifetimeMinutes = lifeTimeoutMinutes; // Default from payload parsing
            if (serverTokenValidityMinutes && serverTokenValidityMinutes > 0) {
                actualLifetimeMinutes = serverTokenValidityMinutes;
                // console.log('DEBUG: Using server token validity:', actualLifetimeMinutes, 'minutes');
            } else {
                // console.log('DEBUG: Using payload token validity:', actualLifetimeMinutes, 'minutes');
            }
            
            // Calculate remaining time based on actual elapsed time
            const otpLifetimeMs = actualLifetimeMinutes * 60 * 1000; // Convert to milliseconds
            const currentTime = Date.now();
            const elapsedTime = currentTime - otpCreationTime;
            let remainingTime = Math.max(0, otpLifetimeMs - elapsedTime);
            let countdown = Math.floor(remainingTime / 1000); // Convert to seconds
            
            // console.log('DEBUG: Countdown calculation:');
            // console.log('  - OTP creation time:', otpCreationTime, 'Date:', new Date(otpCreationTime));
            // console.log('  - Current time:', currentTime, 'Date:', new Date(currentTime));
            // console.log('  - Elapsed time (ms):', elapsedTime);
            // console.log('  - Lifetime (ms):', otpLifetimeMs);
            // console.log('  - Remaining time (ms):', remainingTime);
            // console.log('  - Countdown (seconds):', countdown);
            
            // Function to update label with remaining time
            function updateOtpLabel(seconds) {
                const baseMessage = otpType === 'EMAIL' ? 
                    'กรุณาใส่รหัสผ่านที่ได้รับทาง Email' : 
                    'กรุณาใส่รหัสผ่านที่ได้รับทาง SMS';
                
                let timeMessage = '';
                if (seconds > 0) {
                    const minutes = Math.floor(seconds / 60);
                    const remainingSeconds = seconds % 60;
                    if (minutes > 0) {
                        timeMessage = ` (หมดอายุใน ${minutes}:${remainingSeconds.toString().padStart(2, '0')} นาที)`;
                    } else {
                        timeMessage = ` (หมดอายุใน ${remainingSeconds} วินาที)`;
                    }
                } else {
                    timeMessage = ' (รหัสผ่านหมดอายุแล้ว)';
                    // Show error when OTP expires
                    showOtpExpiredError();
                }
                
                let contactInfo = '';
                if (maskedContactInfo && maskedContactInfo.trim() !== '') {
                    contactInfo = `<br><small style="color: #666; font-weight: normal;">Sent to: ${contactIcon} ${maskedContactInfo}</small>`;
                }
                
                otpLabel.innerHTML = baseMessage + timeMessage + contactInfo;
            }

            // Function to show OTP expired error
            function showOtpExpiredError() {
                // Mark as expired in sessionStorage to persist across refreshes
                sessionStorage.setItem(otpExpiredFlagKey, 'true');
                
                const methodText = otpType === 'EMAIL' ? 'Email' : 'SMS';
                const expiredMessage = `รหัส ${methodText} OTP หมดอายุแล้ว กรุณาขอรหัสใหม่ / ${methodText} OTP has expired. Please request a new code.`;
                
                // Show error message
                const clientError = document.getElementById('clientError');
                if (clientError) {
                    clientError.textContent = expiredMessage;
                    clientError.style.display = 'block';
                    clientError.style.backgroundColor = '#f8d7da';
                    clientError.style.color = '#721c24';
                    clientError.style.borderColor = '#f5c6cb';
                }
                
                // Disable all OTP inputs
                otpInputs.forEach(input => {
                    input.disabled = true;
                    input.style.backgroundColor = '#f8f9fa';
                    input.style.borderColor = '#dee2e6';
                    input.style.color = '#6c757d';
                    input.value = '';
                });
                
                // Disable verify button
                if (verifyBtn) {
                    verifyBtn.disabled = true;
                    verifyBtn.textContent = 'OTP Expired';
                    verifyBtn.style.backgroundColor = '#6c757d';
                    verifyBtn.style.cursor = 'not-allowed';
                }
                
                // Clear hidden input
                if (hiddenOtpInput) {
                    hiddenOtpInput.value = '';
                }
                
                // console.log('DEBUG: OTP expired, form disabled, expired flag set');
            }

            // Function to check if OTP is expired
            function isOtpExpired() {
                if (!otpCreationTime) return false;
                const elapsed = Date.now() - otpCreationTime;
                const lifetime = actualLifetimeMinutes * 60 * 1000;
                return elapsed >= lifetime;
            }
            
            // Update initial label
            updateOtpLabel(countdown);
            
            // Check if OTP is already expired when page loads
            if (countdown <= 0) {
                // console.log('DEBUG: OTP already expired on page load');
                // Mark as expired in sessionStorage
                sessionStorage.setItem(otpExpiredFlagKey, 'true');
                showOtpExpiredError();
            } else {
                // Start countdown timer for label and expiry handling
                const timer = setInterval(() => {
                    if (countdown > 0) {
                        updateOtpLabel(countdown); // Update label countdown only
                        countdown--;
                    } else {
                        updateOtpLabel(0); // Update label to expired
                        clearInterval(timer);
                        // console.log('DEBUG: OTP expired during countdown');
                        // Mark as expired in sessionStorage
                        sessionStorage.setItem(otpExpiredFlagKey, 'true');
                        // Show expired error
                        showOtpExpiredError();
                    }
                }, 1000);
            }
        });
    </script>
</body>
</html>