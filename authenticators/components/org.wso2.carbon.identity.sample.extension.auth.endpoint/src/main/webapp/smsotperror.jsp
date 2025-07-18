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
<%@ page language="java" session="true" contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ page import="java.net.URLDecoder" %>
<%@ page import="java.nio.charset.StandardCharsets" %>

<%
    // Set response encoding to UTF-8
    response.setContentType("text/html; charset=UTF-8");
    response.setCharacterEncoding("UTF-8");
    
    String sessionDataKey = request.getParameter("sessionDataKey");
    String errorMessage = request.getParameter("authFailureMsg");
    String authenticators = request.getParameter("authenticators");
    String errorCode = request.getParameter("errorCode");
    String errorInfo = request.getParameter("errorInfo");
    String returnUrl = request.getParameter("returnUrl");
    
    if (sessionDataKey == null) sessionDataKey = "";
    if (errorMessage == null) errorMessage = "Authentication failed. Please try again.";
    if (errorCode == null) errorCode = "";
    if (errorInfo == null) errorInfo = "";
    if (returnUrl == null) returnUrl = "";
    
    // URL decode the error message and info with proper UTF-8 handling
    try {
        if (errorMessage != null && !errorMessage.isEmpty()) {
            errorMessage = URLDecoder.decode(errorMessage, "UTF-8");
        }
        if (!errorCode.isEmpty()) {
            errorCode = URLDecoder.decode(errorCode, "UTF-8");
        }
        if (!errorInfo.isEmpty()) {
            errorInfo = new String(java.util.Base64.getDecoder().decode(errorInfo), "UTF-8");
        }
        if (!returnUrl.isEmpty()) {
            returnUrl = URLDecoder.decode(returnUrl, "UTF-8");
        }
    } catch (Exception e) {
        // Keep original values if decoding fails
        System.err.println("Error decoding parameters: " + e.getMessage());
    }
%>

<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SMS OTP Authentication Error</title>
    
    <link rel="icon" href="images/favicon.png" type="image/x-icon"/>
    <link href="libs/bootstrap_3.3.5/css/bootstrap.min.css" rel="stylesheet">
    <link href="css/Roboto.css" rel="stylesheet">
    <link href="css/custom-common.css" rel="stylesheet">
    
    <style>
        body {
            font-family: 'Roboto', Arial, sans-serif;
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            min-height: 100vh;
            margin: 0;
            padding: 20px;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .error-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 15px 35px rgba(0, 0, 0, 0.2);
            padding: 40px;
            max-width: 500px;
            width: 100%;
            backdrop-filter: blur(10px);
            text-align: center;
        }
        .error-icon {
            font-size: 60px;
            color: #ff6b6b;
            margin-bottom: 20px;
        }
        .error-header h2 {
            color: #333;
            font-weight: 300;
            margin-bottom: 20px;
        }
        .error-message {
            background: linear-gradient(135deg, #ff6b6b 0%, #ee5a52 100%);
            color: white;
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            font-weight: 500;
            word-wrap: break-word;
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
            margin-bottom: 15px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .btn-primary {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
        }
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.4);
        }
        .btn-secondary {
            background: transparent;
            color: #667eea;
            border: 2px solid #667eea;
        }
        .btn-secondary:hover {
            background: #667eea;
            color: white;
            transform: translateY(-2px);
        }
    </style>
</head>
<body>
    <div class="error-container">
        <div class="error-icon">⚠️</div>
        
        <div class="error-header">
            <h2>Authentication Error</h2>
        </div>
        
        <div class="error-message">
            <%= errorMessage %>
        </div>
        
        <% if (!errorCode.isEmpty()) { %>
        <div class="error-details" style="margin-top: 15px; font-size: 14px; opacity: 0.8;">
            <strong>Error Code:</strong> <%= errorCode %>
        </div>
        <% } %>
        
        <% if (!errorInfo.isEmpty()) { %>
        <div class="error-details" style="margin-top: 10px; font-size: 12px; opacity: 0.7; word-break: break-all;">
            <strong>Details:</strong> <%= errorInfo %>
        </div>
        <% } %>
        
        <form>
            <input type="hidden" name="sessionDataKey" value="<%= sessionDataKey %>" />
            <% if (authenticators != null) { %>
                <input type="hidden" name="authenticators" value="<%= authenticators %>" />
            <% } %>
            <!-- <input type="hidden" name="retry" value="true" />
            
            <button type="submit" class="btn btn-primary">
                Try Again
            </button> -->
        </form>
        
        <!-- <button type="button" class="btn btn-secondary" onclick="window.history.back();">
            Go Back
        </button> -->
    </div>

    <script src="libs/jquery_1.7.1/jquery-1.7.1.js"></script>
    <script src="libs/bootstrap_3.3.5/js/bootstrap.min.js"></script>
</body>
</html>
