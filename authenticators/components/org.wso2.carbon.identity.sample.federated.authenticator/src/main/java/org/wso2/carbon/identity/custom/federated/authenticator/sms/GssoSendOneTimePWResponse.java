package org.wso2.carbon.identity.custom.federated.authenticator.sms;

import java.io.Serializable;

public class GssoSendOneTimePWResponse implements Serializable {

	/**
	 * 
	 */
	private static final long serialVersionUID = 3701194371682310122L;
	private SendOneTimePWResponse sendOneTimePWResponse;

	public SendOneTimePWResponse getSendOneTimePWResponse() {
		return sendOneTimePWResponse;
	}

	public void setSendOneTimePWResponse(
			SendOneTimePWResponse sendOneTimePWResponse) {
		this.sendOneTimePWResponse = sendOneTimePWResponse;
	}

}
