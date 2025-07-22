<%--
  ~ Copyright (c) 2025, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

<%@ page contentType="text/html;charset=UTF-8" language="java" %>
<%@ page import="org.apache.commons.lang.StringUtils" %>
<%@ page import="java.util.Map" %>
<%@ taglib prefix="layout" uri="org.wso2.carbon.identity.apps.taglibs.layout.controller" %>

<%-- Data for the layout from the page --%>
<%
    String queryString = request.getQueryString();
    Map<String, String> idpAuthenticatorMapping = null;
    if (request.getAttribute("idpAuthenticatorMapping") != null) {
        idpAuthenticatorMapping = (Map<String, String>) request.getAttribute("idpAuthenticatorMapping");
    }

    String errorMessage = "Authentication Failed! Please Retry";
    String authFailure = request.getParameter("authFailure");
    if ("true".equals(authFailure)) {
        String authFailureMsg = request.getParameter("authFailureMsg");
        if (StringUtils.isNotEmpty(authFailureMsg)) {
            errorMessage = authFailureMsg;
        }
    }

    String username = request.getParameter("username");
    String sessionDataKey = request.getParameter("sessionDataKey");
    String sp = request.getParameter("sp");
    String tenantDomain = request.getParameter("tenantDomain");
%>

<layout:main layoutName="centered" layoutFileRelativePath="/WEB-INF/layouts/centered.jsp">
    <layout:content>
        <div class="ui container large centered">
            <!-- Header Section -->
            <div class="ui text container" style="margin-bottom: 3rem; text-align: center;">
                <h1 class="ui header" style="font-size: 2.5rem; color: #333; margin-bottom: 0.5rem;">
                    ~~ Sign In ~~
                </h1>
                <p style="color: #666; font-size: 1.1rem; margin-top: 0;">
                    Choose your preferred OTP method
                </p>
            </div>

            <!-- Error Message -->
            <% if ("true".equals(authFailure)) { %>
                <div class="ui negative message" style="margin-bottom: 2rem;">
                    <div class="header">Authentication Error</div>
                    <p><%= errorMessage %></p>
                </div>
            <% } %>

            <!-- OTP Channel Selection Form -->
            <div class="ui centered card" style="max-width: 500px; margin: 0 auto; border-radius: 12px; box-shadow: 0 4px 20px rgba(0,0,0,0.1);">
                <div class="content" style="padding: 3rem 2rem;">
                    <form class="ui large form" id="otpChannelForm" method="post" 
                          action="<%=request.getContextPath()%>/commonauth">
                        
                        <!-- Hidden Fields -->
                        <% if (StringUtils.isNotEmpty(sessionDataKey)) { %>
                            <input type="hidden" name="sessionDataKey" value="<%=sessionDataKey%>"/>
                        <% } %>
                        <% if (StringUtils.isNotEmpty(username)) { %>
                            <input type="hidden" name="username" value="<%=username%>"/>
                        <% } %>
                        <% if (StringUtils.isNotEmpty(sp)) { %>
                            <input type="hidden" name="sp" value="<%=sp%>"/>
                        <% } %>
                        <% if (StringUtils.isNotEmpty(tenantDomain)) { %>
                            <input type="hidden" name="tenantDomain" value="<%=tenantDomain%>"/>
                        <% } %>
                        
                        <!-- Preserve all query parameters -->
                        <% 
                            if (StringUtils.isNotEmpty(queryString)) {
                                String[] params = queryString.split("&");
                                for (String param : params) {
                                    if (param.contains("=")) {
                                        String[] keyValue = param.split("=", 2);
                                        String key = keyValue[0];
                                        String value = keyValue.length > 1 ? java.net.URLDecoder.decode(keyValue[1], "UTF-8") : "";
                                        
                                        // Skip certain parameters we don't want to preserve
                                        if (!"authFailure".equals(key) && 
                                            !"authFailureMsg".equals(key) && 
                                            !"channelSelection".equals(key) &&
                                            !"sessionDataKey".equals(key) &&
                                            !"username".equals(key) &&
                                            !"sp".equals(key) &&
                                            !"tenantDomain".equals(key)) {
                        %>
                                            <input type="hidden" name="<%=key%>" value="<%=value%>"/>
                        <%
                                        }
                                    }
                                }
                            }
                        %>

                        <!-- SMS Option -->
                        <div class="field">
                            <button type="button" class="ui large fluid button channel-btn sms-btn" 
                                    onclick="selectChannel('SMS')"
                                    style="background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
                                           color: white; 
                                           border: none; 
                                           border-radius: 50px; 
                                           padding: 1.2rem 2rem; 
                                           margin-bottom: 1rem;
                                           transition: all 0.3s ease;
                                           box-shadow: 0 4px 15px rgba(102, 126, 234, 0.3);">
                                <div style="display: flex; align-items: center; justify-content: center;">
                                    <i class="mobile alternate icon" style="font-size: 1.5rem; margin-right: 0.8rem;"></i>
                                    <span style="font-size: 1.1rem; font-weight: 500;">Sign In With SMS OTP</span>
                                </div>
                            </button>
                        </div>

                        <!-- Email Option -->
                        <div class="field">
                            <button type="button" class="ui large fluid button channel-btn email-btn" 
                                    onclick="selectChannel('EMAIL')"
                                    style="background: linear-gradient(135deg, #f093fb 0%, #f5576c 100%); 
                                           color: white; 
                                           border: none; 
                                           border-radius: 50px; 
                                           padding: 1.2rem 2rem;
                                           transition: all 0.3s ease;
                                           box-shadow: 0 4px 15px rgba(245, 87, 108, 0.3);">
                                <div style="display: flex; align-items: center; justify-content: center;">
                                    <i class="mail icon" style="font-size: 1.5rem; margin-right: 0.8rem;"></i>
                                    <span style="font-size: 1.1rem; font-weight: 500;">Sign In With Email OTP</span>
                                </div>
                            </button>
                        </div>

                        <!-- Hidden field for selected channel -->
                        <input type="hidden" id="otpChannel" name="otpChannel" value=""/>
                    </form>
                </div>
            </div>

            <!-- Footer -->
            <!-- <div class="ui text container" style="margin-top: 3rem; text-align: center;">
                <p style="color: #999; font-size: 0.9rem;">
                    © 2025 WSO2 LLC.
                </p>
            </div> -->
        </div>

        <!-- Custom Styles -->
        <style>
            .channel-btn:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 25px rgba(0,0,0,0.15) !important;
            }

            .sms-btn:hover {
                background: linear-gradient(135deg, #5a6fd8 0%, #6a4c93 100%) !important;
            }

            .email-btn:hover {
                background: linear-gradient(135deg, #e084fc 0%, #e04e63 100%) !important;
            }

            .ui.large.form .field > button {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            }

            .ui.container {
                padding-top: 2rem;
                padding-bottom: 2rem;
            }

            /* Mobile responsiveness */
            @media only screen and (max-width: 767px) {
                .ui.container {
                    padding-left: 1rem;
                    padding-right: 1rem;
                }
                
                .ui.centered.card {
                    max-width: 100% !important;
                    margin: 0 !important;
                }
                
                .content {
                    padding: 2rem 1.5rem !important;
                }
                
                .channel-btn {
                    padding: 1rem 1.5rem !important;
                }
                
                h1.ui.header {
                    font-size: 2rem !important;
                }
            }
        </style>

        <!-- JavaScript -->
        <script type="text/javascript">
            function selectChannel(channelType) {
                console.log('Selected channel: ' + channelType);
                
                // Set the selected channel
                document.getElementById('otpChannel').value = channelType;
                
                // Add loading state to the clicked button
                const clickedBtn = event.target.closest('.channel-btn');
                const originalContent = clickedBtn.innerHTML;
                clickedBtn.innerHTML = '<i class="spinner loading icon"></i> Processing...';
                clickedBtn.disabled = true;
                
                // Submit the form
                setTimeout(function() {
                    document.getElementById('otpChannelForm').submit();
                }, 500);
            }
            
            // Add keyboard navigation
            document.addEventListener('keydown', function(event) {
                if (event.key === '1') {
                    selectChannel('SMS');
                } else if (event.key === '2') {
                    selectChannel('EMAIL');
                }
            });
            
            // Add focus styles for accessibility
            document.addEventListener('DOMContentLoaded', function() {
                const buttons = document.querySelectorAll('.channel-btn');
                buttons.forEach(function(button) {
                    button.addEventListener('focus', function() {
                        this.style.outline = '3px solid #4285f4';
                        this.style.outlineOffset = '2px';
                    });
                    
                    button.addEventListener('blur', function() {
                        this.style.outline = 'none';
                    });
                });
            });
        </script>
    </layout:content>
</layout:main>
