<%--
  ~ Copyright (c) 2019, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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
<%@ page language="java" session="true" %>

<%
    String sessionDataKey = request.getParameter("sessionDataKey");
    String authenticators = request.getParameter("authenticators");
    
    if (sessionDataKey == null) sessionDataKey = "";
%>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Mobile Number Required</title>
    
    <link rel="icon" href="images/favicon.png" type="image/x-icon"/>
    <link href="libs/bootstrap_3.3.5/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/Roboto.css" rel="stylesheet">
    <link href="css/custom-common.css" rel="stylesheet">
    
    <style>
        body {
            font-family: 'Roboto', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .mobile-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.1);
            padding: 40px;
            max-width: 450px;
            width: 100%;
            backdrop-filter: blur(10px);
        }
        .mobile-header {
            text-align: center;
            margin-bottom: 30px;
        }
        .mobile-header h2 {
            color: #333;
            font-weight: 300;
            margin-bottom: 10px;
        }
        .mobile-header p {
            color: #666;
            font-size: 14px;
        }
        .form-group {
            margin-bottom: 25px;
            position: relative;
        }
        .form-group label {
            display: block;
            margin-bottom: 8px;
            font-weight: 500;
            color: #555;
        }
        .form-control {
            width: 100%;
            padding: 15px 20px;
            border: 2px solid #e1e5e9;
            border-radius: 8px;
            font-size: 16px;
            transition: all 0.3s ease;
            background: #fff;
            box-sizing: border-box;
        }
        .form-control:focus {
            border-color: #667eea;
            outline: none;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        .btn {
            width: 100%;
            padding: 15px;
            border: none;
            border-radius: 8px;
            font-size: 16px;
            font-weight: 500;
            cursor: pointer;
            transition: all 0.3s ease;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .info-message {
            background: linear-gradient(135deg, #51cf66 0%, #40c057 100%);
            color: white;
            padding: 15px 20px;
            border-radius: 8px;
            margin-bottom: 25px;
            text-align: center;
            font-weight: 500;
        }
        .phone-icon {
            position: absolute;
            left: 15px;
            top: 50%;
            transform: translateY(-50%);
            color: #999;
            font-size: 18px;
        }
        .phone-input {
            padding-left: 45px !important;
        }
        .format-hint {
            font-size: 12px;
            color: #999;
            margin-top: 5px;
        }
    </style>
</head>
<body>
    <div class="mobile-container">
        <div class="mobile-header">
            <h2>📱 Mobile Number Required</h2>
            <p>Please enter your mobile number to receive the verification code</p>
        </div>
        
        <div class="info-message">
            We need your mobile number to send you a verification code via SMS
        </div>
        
        <form method="post" action="../commonauth" id="mobileForm">
            <input type="hidden" name="sessionDataKey" value="<%= sessionDataKey %>" />
            <% if (authenticators != null) { %>
                <input type="hidden" name="authenticators" value="<%= authenticators %>" />
            <% } %>
            
            <div class="form-group">
                <label for="mobileNumber">Mobile Number:</label>
                <div style="position: relative;">
                    <span class="phone-icon">📞</span>
                    <input type="tel" 
                           id="mobileNumber" 
                           name="mobileNumber" 
                           class="form-control phone-input" 
                           placeholder="+66812345678" 
                           required>
                </div>
                <div class="format-hint">
                    Format: +country_code followed by your mobile number<br>
                    Example: +66812345678 (Thailand), +601234567890 (Malaysia)
                </div>
            </div>
            
            <button type="submit" class="btn" id="sendBtn">
                Send Verification Code
            </button>
        </form>
    </div>

    <script src="libs/jquery_1.7.1/jquery-1.7.1.js"></script>
    <script src="libs/bootstrap_3.3.5/js/bootstrap.min.js"></script>
    <script>
        $(document).ready(function() {
            // Auto-focus on mobile number input field
            $('#mobileNumber').focus();
            
            // Format mobile number input
            $('#mobileNumber').on('input', function() {
                let value = this.value;
                
                // Remove any non-digit characters except + at the beginning
                value = value.replace(/[^\d+]/g, '');
                
                // Ensure + is only at the beginning
                if (value.indexOf('+') > 0) {
                    value = value.replace(/\+/g, '');
                    value = '+' + value;
                }
                
                this.value = value;
            });
            
            // Validate mobile number format
            $('#mobileForm').on('submit', function(e) {
                var mobileNumber = $('#mobileNumber').val();
                
                // Basic validation - must start with + and have at least 10 digits
                var phoneRegex = /^\+\d{10,15}$/;
                
                if (!phoneRegex.test(mobileNumber)) {
                    e.preventDefault();
                    alert('Please enter a valid mobile number with country code.\nExample: +66812345678');
                    return false;
                }
                
                // Show loading state
                $('#sendBtn').prop('disabled', true);
                $('#sendBtn').text('Sending...');
            });
            
            // Auto-add + if user starts typing without it
            $('#mobileNumber').on('keydown', function(e) {
                if (this.value.length === 0 && e.key !== '+' && /\d/.test(e.key)) {
                    this.value = '+';
                }
            });
        });
    </script>
</body>
</html>
