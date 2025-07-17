<%--
  ~ Copyright (c) 2023, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
  ~
  ~ WSO2 Inc. licenses this file to you under the Apache License,
  ~ Version 2.0 (the "License"); you may not use this file except
  ~ in compliance with the License.
  ~ You may obtain a copy of the License at
  ~
  ~ http://www.apache.org/licenses/LICENSE-2.0
  ~
  ~ Unless required by applicable law or agreed to in writing,
  ~ software distributed under the License is distributed on an
  ~ "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
  ~ KIND, either express or implied.  See the License for the
  ~ specific language governing permissions and limitations
  ~ under the License.
  --%>

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
    
    // Get actualOtpSent from authentication context (secure method)
    String actualOtpSent = null;
    try {
        AuthenticationContext authContext = FrameworkUtils.getAuthenticationContextFromCache(sessionDataKey);
        System.out.println("DEBUG: AuthenticationContext retrieved: " + (authContext != null ? "SUCCESS" : "NULL"));
        System.out.println("DEBUG: SessionDataKey: " + sessionDataKey);
        
        if (authContext != null) {
            actualOtpSent = (String) authContext.getProperty("CLIENT_OTP_VALIDATION");
            System.out.println("DEBUG: actualOtpSent from CLIENT_OTP_VALIDATION: " + actualOtpSent);
            
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
    
    // SMS Payload parameter - try to get from authentication context first
    String smsPayload = null;
    try {
        AuthenticationContext authContext = FrameworkUtils.getAuthenticationContextFromCache(sessionDataKey);
        if (authContext != null) {
            smsPayload = (String) authContext.getProperty("SMS_PAYLOAD_CONFIG");
            System.out.println("DEBUG: smsPayload from SMS_PAYLOAD_CONFIG: " + smsPayload);
        }
    } catch (Exception e) {
        System.out.println("DEBUG: Exception getting SMS payload from context: " + e.getMessage());
        // Fallback to parameter if context access fails
        smsPayload = request.getParameter("smsPayload");
        System.out.println("DEBUG: smsPayload from request parameter: " + smsPayload);
    }
    
    // If still null, try parameter fallback
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
    
    // Error handling
    String errorMessage = "";
    boolean hasError = false;
    if ("true".equals(authFailure) && authFailureMsg != null) {
        hasError = true;
        if ("authentication.fail.message".equals(authFailureMsg)) {
            errorMessage = "Authentication failed. Please check your OTP code.";
        } else if ("code.mismatch".equals(authFailureMsg)) {
            errorMessage = "Invalid OTP code. Please try again.";
        } else if ("token.expired".equals(authFailureMsg)) {
            errorMessage = "OTP has expired. Please request a new code.";
        } else {
            errorMessage = "Authentication failed. Please try again.";
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
    <title>SMS OTP Verification - WSO2 Identity Server</title>
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

        <h1>SMS OTP Verification</h1>
        <p class="subtitle">Enter the verification code sent to your mobile number</p>

        <% if (screenvalue != null && !screenvalue.isEmpty()) { %>
        <div class="mobile-info">
            <strong>Code sent to:</strong> <%= screenvalue %>
        </div>
        <% } %>

        <% if (hasError) { %>
        <div class="error-message">
            <%= errorMessage %>
        </div>
        <script>
            // Show alert for OTP error
            document.addEventListener('DOMContentLoaded', function() {
                alert('<%= Encode.forJavaScript(errorMessage) %>');
            });
        </script>
        <% } %>

        <% if ("true".equals(Code)) { %>
        <div class="success-message">
            A new verification code has been sent to your mobile number.
        </div>
        <% } %>

        <form id="otpForm" action="<%= actionUrl.toString() %>" method="POST">
            <!-- Hidden parameters -->
            <% for (Map.Entry<String, String> param : hiddenParams.entrySet()) { %>
            <input type="hidden" name="<%= param.getKey() %>" value="<%= param.getValue() %>" />
            <% } %>

            <div class="form-group">
                <label class="otp-label" for="otp1" id="otpLabel">กรุณาใส่รหัสผ่านที่ได้รับทาง SMS</label>
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
        <input type="hidden" id="smsPayloadData" value="<%= smsPayload.replace("\"", "&quot;") %>" />
        <% } %>
        
        <!-- Hidden field for actual OTP sent -->
        <% if (actualOtpSent != null && !actualOtpSent.isEmpty()) { %>
        <input type="hidden" id="actualOtpSentData" value="<%= actualOtpSent %>" />
        <% } %>
    </div>

    <script>
        document.addEventListener('DOMContentLoaded', function() {
            const otpInputs = document.querySelectorAll('.otp-input');
            const hiddenOtpInput = document.getElementById('otpToken');
            const verifyBtn = document.getElementById('verifyBtn');
            const otpForm = document.getElementById('otpForm');

            // Auto-focus on first OTP input
            otpInputs[0].focus();

            // Get actual OTP sent from backend via hidden field
            const actualOtpElement = document.getElementById('actualOtpSentData');
            let actualOtpSent = null;
            
            if (actualOtpElement && actualOtpElement.value) {
                actualOtpSent = actualOtpElement.value;
            }

            // Process SMS payload if available
            const smsPayloadElement = document.getElementById('smsPayloadData');
            let expectedOtpLength = 4; // Default OTP length
            let lifeTimeoutMinutes = 0.5; // Default 30 seconds (0.5 minutes)
            
            if (smsPayloadElement && smsPayloadElement.value) {
                try {
                    const smsPayload = JSON.parse(smsPayloadElement.value);
                    
                    // Extract OTP digit length from payload structure
                    if (smsPayload && smsPayload.sendOneTimePW && smsPayload.sendOneTimePW.otpDigit) {
                        expectedOtpLength = parseInt(smsPayload.sendOneTimePW.otpDigit);
                    }
                    // Fallback for direct format (if payload structure is different)
                    else if (smsPayload && smsPayload.otpDigit) {
                        expectedOtpLength = parseInt(smsPayload.otpDigit);
                    }
                    
                    // Extract lifeTimeoutMins from payload structure
                    if (smsPayload && smsPayload.sendOneTimePW && smsPayload.sendOneTimePW.lifeTimeoutMins) {
                        lifeTimeoutMinutes = parseFloat(smsPayload.sendOneTimePW.lifeTimeoutMins);
                    }
                    // Fallback for direct format (if payload structure is different)
                    else if (smsPayload && smsPayload.lifeTimeoutMins) {
                        lifeTimeoutMinutes = parseFloat(smsPayload.lifeTimeoutMins);
                    }
                } catch (e) {
                    // Use default values if parsing fails
                }
            }
            
            // Adjust OTP inputs based on expected length from SMS payload
            const activeOtpLength = Math.min(Math.max(expectedOtpLength, 1), 8); // Ensure between 1-8 digits
            
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
                    const originalValue = e.target.value;
                    
                    // Check if non-numeric characters were entered
                    if (originalValue && !/^\d*$/.test(originalValue)) {
                        showOtpError('รหัส OTP ต้องเป็นตัวเลขเท่านั้น / OTP code must contain only numbers.');
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
                });

                input.addEventListener('keydown', function(e) {
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
                    e.preventDefault();
                    const pasteData = e.clipboardData.getData('text').replace(/[^0-9]/g, '');
                    
                    if (pasteData.length === activeOtpLength) {
                        // Check pasted OTP against actual value from backend or fallback
                        const expectedOtp = actualOtpSent;
                        
                        // Check Invalid OTP code
                        if (pasteData !== expectedOtp) {
                            const errorMsg = 'รหัส OTP ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง / Invalid OTP code. Please try again.';
                            showOtpError(errorMsg);
                            return;
                        }
                        
                        // Fill all inputs with pasted data
                        for (let i = 0; i < activeOtpLength; i++) {
                            if (pasteData[i]) {
                                otpInputs[i].value = pasteData[i];
                                otpInputs[i].classList.add('filled');
                            }
                        }
                        updateHiddenOtpInput();
                        
                        // Show message that OTP was pasted successfully
                        // showOtpError('รหัส OTP ถูกติดตั้งแล้ว กรุณากดปุ่ม "ยืนยันรหัส" เพื่อดำเนินการต่อ / OTP code has been pasted. Please click "Verify Code" to proceed.');
                    } else {
                        showOtpError(`กรุณาใส่รหัส OTP ให้ครบ ${activeOtpLength} หลัก / Please enter a complete ${activeOtpLength}-digit OTP code.`);
                    }
                });

                input.addEventListener('focus', function() {
                    this.select();
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

            window.clearOtpInputs = function() {
                // Clear only OTP input fields
                otpInputs.forEach(input => {
                    input.value = '';
                    input.classList.remove('filled');
                });
                hiddenOtpInput.value = '';
                otpInputs[0].focus(); // Focus back to first input
            }

            function showOtpError(message) {
                // Add visual error state to inputs
                otpInputs.forEach(input => {
                    input.style.borderColor = '#dc3545';
                    input.style.backgroundColor = '#fff5f5';
                });
                
                // Show alert with error message
                alert(message);
                
                // Remove error styling after 3 seconds
                setTimeout(() => {
                    otpInputs.forEach(input => {
                        input.style.borderColor = '#e1e5e9';
                        input.style.backgroundColor = '';
                    });
                }, 3000);
                
                // Clear inputs and focus on first
                clearOtpInputs();
            }

            // Handle form submission
            if (otpForm) {
                otpForm.addEventListener('submit', function(e) {
                    const otpValue = getOtpValue();
                    
                    if (otpValue.length !== activeOtpLength) {
                        e.preventDefault();
                        alert(`กรุณากรอกรหัส OTP ให้ครบ ${activeOtpLength} หลัก / Please enter a complete ${activeOtpLength}-digit OTP code.`);
                        return;
                    }

                    // Validate that OTP contains only numbers
                    if (!/^\d+$/.test(otpValue)) {
                        e.preventDefault();
                        alert('รหัส OTP ต้องเป็นตัวเลขเท่านั้น / OTP code must contain only numbers.');
                        return;
                    }

                    // Check OTP against actual value from backend or fallback
                    const expectedOtp = actualOtpSent;

                    // Check Invalid OTP code
                    if (otpValue !== expectedOtp) {
                        e.preventDefault();
                        const errorMsg = 'รหัส OTP ไม่ถูกต้อง กรุณาลองใหม่อีกครั้ง / Invalid OTP code. Please try again.';
                        showOtpError(errorMsg);
                        return;
                    }

                    // Show loading state
                    verifyBtn.textContent = 'Verifying...';
                    verifyBtn.disabled = true;
                    
                    // Add a timeout to handle potential hanging requests
                    setTimeout(() => {
                        if (verifyBtn.textContent === 'Verifying...') {
                            verifyBtn.textContent = 'Verify Code';
                            verifyBtn.disabled = false;
                            alert('หมดเวลาการเชื่อมต่อ กรุณาลองใหม่อีกครั้ง / Request timeout. Please try again.');
                        }
                    }, 30000); // 30 second timeout
                });
            }

            // OTP countdown timer for label display
            const otpCreationTimeKey = 'otpCreationTime_' + '<%= sessionDataKey %>';
            let otpCreationTime = sessionStorage.getItem(otpCreationTimeKey);
            const otpLabel = document.getElementById('otpLabel');
            
            if (!otpCreationTime) {
                // First time loading the page, set creation time to now
                otpCreationTime = Date.now();
                sessionStorage.setItem(otpCreationTimeKey, otpCreationTime);
            } else {
                otpCreationTime = parseInt(otpCreationTime);
            }
            
            // Calculate remaining time based on actual elapsed time
            const otpLifetimeMs = lifeTimeoutMinutes * 60 * 1000; // Convert to milliseconds
            const elapsedTime = Date.now() - otpCreationTime;
            let remainingTime = Math.max(0, otpLifetimeMs - elapsedTime);
            let countdown = Math.floor(remainingTime / 1000); // Convert to seconds
            
            // Function to update label with remaining time
            function updateOtpLabel(seconds) {
                if (seconds > 0) {
                    const minutes = Math.floor(seconds / 60);
                    const remainingSeconds = seconds % 60;
                    if (minutes > 0) {
                        otpLabel.textContent = `กรุณาใส่รหัสผ่านที่ได้รับทาง SMS (หมดอายุใน ${minutes}:${remainingSeconds.toString().padStart(2, '0')} นาที)`;
                    } else {
                        otpLabel.textContent = `กรุณาใส่รหัสผ่านที่ได้รับทาง SMS (หมดอายุใน ${remainingSeconds} วินาที)`;
                    }
                } else {
                    otpLabel.textContent = 'กรุณาใส่รหัสผ่านที่ได้รับทาง SMS (รหัสผ่านหมดอายุแล้ว)';
                }
            }
            
            // Update initial label
            updateOtpLabel(countdown);
            
            // Start countdown timer for label only
            const timer = setInterval(() => {
                if (countdown > 0) {
                    updateOtpLabel(countdown); // Update label countdown only
                    countdown--;
                } else {
                    updateOtpLabel(0); // Update label to expired
                    clearInterval(timer);
                    // Clear the creation time when OTP expires
                    sessionStorage.removeItem(otpCreationTimeKey);
                }
            }, 1000);
        });
    </script>
</body>
</html>