package org.wso2.carbon.identity.custom.federated.authenticator.sms;

import java.io.Serializable;

public class SendOneTimePWResponse implements Serializable {

    private static final long serialVersionUID = 7344820615508129146L;
	private String code;
	private String description;
	private String transactionID;
	private String oneTimePassword;
	private String isSuccess;
	private String orderRef;
	private String referenceNumber;
	private String operName;
	private String lifeTimeoutMins;
	private String expirePassword;
    
    public String getCode() {
		return code;
	}

	public String getTransactionID() {
		return transactionID;
	}

	public String getDescription() {
		return description;
	}

	public String getOneTimePassword() {
		return oneTimePassword;
	}

	public void setOneTimePassword(String oneTimePassword) {
		this.oneTimePassword = oneTimePassword;
	}

	public String getIsSuccess() {
		return isSuccess;
	}

	public void setIsSuccess(String isSuccess) {
		this.isSuccess = isSuccess;
	}

	public String getOrderRef() {
		return orderRef;
	}

	public void setOrderRef(String orderRef) {
		this.orderRef = orderRef;
	}

	public String getReferenceNumber() {
		return referenceNumber;
	}

	public void setReferenceNumber(String referenceNumber) {
		this.referenceNumber = referenceNumber;
	}

	public String getOperName() {
		return operName;
	}

	public void setOperName(String operName) {
		this.operName = operName;
	}

	public String getLifeTimeoutMins() {
		return lifeTimeoutMins;
	}

	public void setLifeTimeoutMins(String lifeTimeoutMins) {
		this.lifeTimeoutMins = lifeTimeoutMins;
	}

	public String getExpirePassword() {
		return expirePassword;
	}

	public void setExpirePassword(String expirePassword) {
		this.expirePassword = expirePassword;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public void setDescription(String description) {
		this.description = description;
	}

	public void setTransactionID(String transactionID) {
		this.transactionID = transactionID;
	}

}
