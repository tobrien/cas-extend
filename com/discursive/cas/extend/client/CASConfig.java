package com.discursive.cas.extend.client;

public class CASConfig {

    /** Secure URL whereat CAS offers its login service. */
    private String casLogin;
    /** Secure URL whereat CAS offers its CAS 2.0 validate service */
    private String casValidate;
    /** Filtered service URL for use as service parameter to login and validate */
    private String casServiceUrl;
    /** Name of server, for use in assembling service URL for use as service parameter to login and validate. */
    private String casServerName;
    private String multiServerName;
    /** Secure URL whereto this filter should ask CAS to send Proxy Granting Tickets. */
    private String casProxyCallbackUrl;
    
    private String casAuthorizedProxy;
    
    /** True if renew parameter should be set on login and validate */
    private boolean casRenew;
    
    /** True if this filter should wrap requests to expose authenticated user as getRemoteUser(); */
    private boolean wrapRequest;
    
    /** True if this filter should set gateway=true on login redirect */
    private boolean casGateway = false;
    
    private boolean dummyTrust = false;
    
    /** If this property is present the service URLs scheme will always be forced to this property */
    private String serviceScheme;
    
    public CASConfig() {}

	public boolean isCasGateway() {
		return casGateway;
	}

	public void setCasGateway(boolean casGateway) {
		this.casGateway = casGateway;
	}

	public String getCasLogin() {
		return casLogin;
	}

	public void setCasLogin(String casLogin) {
		this.casLogin = casLogin;
	}

	public String getCasProxyCallbackUrl() {
		return casProxyCallbackUrl;
	}

	public void setCasProxyCallbackUrl(String casProxyCallbackUrl) {
		this.casProxyCallbackUrl = casProxyCallbackUrl;
	}

	public boolean isCasRenew() {
		return casRenew;
	}

	public void setCasRenew(boolean casRenew) {
		this.casRenew = casRenew;
	}

	public String getCasServerName() {
		return casServerName;
	}

	public void setCasServerName(String casServerName) {
		this.casServerName = casServerName;
	}

	public String getCasServiceUrl() {
		return casServiceUrl;
	}

	public void setCasServiceUrl(String casServiceUrl) {
		this.casServiceUrl = casServiceUrl;
	}

	public String getCasValidate() {
		return casValidate;
	}

	public void setCasValidate(String casValidate) {
		this.casValidate = casValidate;
	}

	public boolean isWrapRequest() {
		return wrapRequest;
	}

	public void setWrapRequest(boolean wrapRequest) {
		this.wrapRequest = wrapRequest;
	}

	public String getCasAuthorizedProxy() {
		return casAuthorizedProxy;
	}

	public void setCasAuthorizedProxy(String casAuthorizedProxy) {
		this.casAuthorizedProxy = casAuthorizedProxy;
	}

	public boolean isDummyTrust() {
		return dummyTrust;
	}

	public void setDummyTrust(boolean dummyTrust) {
		this.dummyTrust = dummyTrust;
	}

	public String getMultiServerName() {
		return multiServerName;
	}

	public void setMultiServerName(String multiServerName) {
		this.multiServerName = multiServerName;
	}

	public String getServiceScheme() {
		return serviceScheme;
	}

	public void setServiceScheme(String serviceScheme) {
		this.serviceScheme = serviceScheme;
	}
	
	
    
}
