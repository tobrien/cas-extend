 /*  Copyright (c) 2000-2004 Yale University. All rights reserved. 
  *  See full notice at end.
  */

package com.discursive.cas.extend.client.filter;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.naming.Context;
import javax.naming.InitialContext;
import javax.naming.NamingException;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.beanutils.PropertyUtils;
import org.apache.commons.lang.ArrayUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import com.discursive.cas.extend.client.CASAuthenticationException;
import com.discursive.cas.extend.client.CASConfig;
import com.discursive.cas.extend.client.CASReceipt;
import com.discursive.cas.extend.client.ProxyTicketValidator;
import com.discursive.cas.extend.client.Util;
import com.discursive.cas.extend.util.SecureURL;

/**
 * <p>Protects web-accessible resources with CAS.</p>
 *
 * <p>The following filter initialization parameters are declared in 
 * <code>web.xml</code>:</p>
 *
 * <ul> 
 *   <li><code>com.discursive.cas.extend.client.filter.loginUrl</code>: URL to 
 *   login page on CAS server.  (Required)</li>
 *   <li><code>com.discursive.cas.extend.client.filter.validateUrl</code>: URL
 *   to validation URL on CAS server.  (Required)</li>
 *   <li><code>com.discursive.cas.extend.client.filter.serviceUrl</code>: URL
 *   of this service.  (Required if <code>serverName</code> is not 
 *   specified)</li>
 *   <li><code>com.discursive.cas.extend.client.filter.serverName</code>: full
 *   hostname with port number (e.g. <code>www.foo.com:8080</code>).  
 *   Port number isn't required if it is standard (80 for HTTP, 443 for 
 *   HTTPS).  (Required if <code>serviceUrl</code> is not specified)</li>
 *   <li><code>com.discursive.cas.extend.client.filter.authorizedProxy</code>:
 *   whitespace-delimited list of valid proxies through which authentication
 *   may have proceeded.  One one proxy must match.  (Optional.  If nothing
 *   is specified, the filter will only accept service tickets &#150; not
 *   proxy tickets.)</li>
 *   <li><code>com.discursive.cas.extend.client.filter.proxyCallbackUrl</code>:
 *   URL of local proxy callback listener used to acquire PGT/PGTIOU.
 *   (Optional.)</li>
 *   <li><code>com.discursive.cas.extend.client.filter.renew</code>: value of
 *   CAS "renew" parameter.  Bypasses single sign-on and requires user
 *   to provide CAS with his/her credentials again.  (Optional.  If nothing
 *   is specified, this defaults to false.)</li>
 *   <li><code>com.discursive.cas.extend.client.filter.gateway</code>: value of
 *   CAS "gateway" parameter.  Redirects initial call through CAS and if
 *   the user has logged in, validates the ticket on return.  If the user
 *   has not logged in, returns to the web application without setting
 *   the <code>CAS_FILTER_USER</code> variable.  Note that once a redirect 
 *   through CAS has occurred, the filter will not automatically try again 
 *   to log the user in.  You can then either provide an explicit CAS login
 *   link (<code>https://cas-server/cas/login?service=http://your-app</code>)
 *   or set up two instances of the filter mapped to different paths.  One
 *   instance would have gateway=true, the other wouldn't.  When you need
 *   the user to be logged in, direct him/her to the path of the other 
 *   filter.</li>
 *   <li><code>com.discursive.cas.extend.client.filter.wrapRequest</code>:
 *   wrap the <code>HttpServletRequest</code> object, overriding the
 *   <code>getRemoteUser()</code> method.  When set to "true",
 *   <code>request.getRemoteUser()</code> will return the username of the 
 *   currently logged-in CAS user.  (Optional.  If nothing is specified, 
 *   this defaults to false.)</li>
 * </ul>
 *
 * <p>The logged-in username is set in the session attribute defined by
 * the value of <code>CAS_FILTER_USER</code> and may be accessed from within
 * your application either by setting <code>wrapRequest</code> and calling
 * <code>request.getRemoteUser()</code>, or by calling
 * <code>session.getAttribute(CASFilter.CAS_FILTER_USER)</code>.</p>
 *
 * <p>If <code>proxyCallbackUrl</code> is set, the URL will be passed to
 * CAS upon validation.  If the callback URL is valid, it will receive a
 * CAS PGT and a PGTIOU.  The PGTIOU will be returned to this filter and
 * will be accessible through the session attribute, 
 * <code>CASFilter.CAS_FILTER_PGTIOU</code>.  You may then acquire
 * proxy tickets to other services by calling 
 * <code>com.discursive.cas.extend.proxy.ProxyTicketReceptor.getProxyTicket(pgtIou, targetService)</code>.
 *
 * @author Shawn Bayern
 * @author Drew Mazurek
 * @author andrew.petro@yale.edu
 */
public class CASFilter implements Filter {

    private static Log log = LogFactory.getLog(CASFilter.class);

    // Filter initialization parameters
    
    /** The name of the JNDI location of the CASConfig object.
     */
    public final static String JNDI_INIT_PARAM = "com.discursive.cas.extend.client.config.jndi";

    /** The name of the filter initialization parameter the value of which should be the https: address
     * of the CAS Login servlet.  Optional parameter, but required for successful redirection of unauthenticated
     * requests to authentication.
     */
    public final static String LOGIN_INIT_PARAM = "com.discursive.cas.extend.client.filter.loginUrl";
    
    /** The name of the filter initialization parameter the value of which must be the https: address
     * of the CAS Validate servlet.  Must be a CAS 2.0 validate servlet (CAS 1.0 non-XML won't suffice).
     * Required parameter.
     */
    public final static String VALIDATE_INIT_PARAM = "com.discursive.cas.extend.client.filter.validateUrl";
    
    /** The name of the filter initialization parameter the value of which must be the address
     * of the service this filter is filtering.  The filter will use this as
     * the service parameter for CAS login and validation. Either this parameter or SERVERNAME_INIT_PARAM must be set.
     */
    public final static String SERVICE_INIT_PARAM = "com.discursive.cas.extend.client.filter.serviceUrl";
    
    /** The name of the filter initialization parameter the vlaue of which must be the server name,
     * e.g. www.yale.edu , of the service this filter is filtering.  The filter will construct from this name
     * and the request the full service parameter for CAS login and validation.
     */
    public final static String SERVERNAME_INIT_PARAM = "com.discursive.cas.extend.client.filter.serverName";
    
    /** The name of the filter initialization parameter the value of which can be s series of server names,
     * e.g. "www.yale.edu, www.google.com", of the services this filter is filtering.  The filter will construct 
     * from the request the full service parameter for CAS login and validation.  Please note that this parameter
     * introduces security issues that could introduce insecurities because you are trusting the client to
     * properly identify its own host field.
     */
    public final static String MULTI_SERVERNAME_INIT_PARAM = "com.discursive.cas.extend.client.filter.multiServerName";

    /** The name of the filter initialization parameter the value of which must be the String
     * that should be sent as the "renew" parameter on the request for login and validation.
     * This should either be "true" or not be set.  It is mutually exclusive with GATEWAY.
     */
    public final static String RENEW_INIT_PARAM = "com.discursive.cas.extend.client.filter.renew";
    
    /** The name of the filter initialization parameter the value of which must be a whitespace
     * delimited list of services (ProxyTicketReceptors) authorized to proxy authentication to the
     * service filtered by this Filter.  These must be https: URLs.  This parameter is optional - 
     * not setting it results in no proxy tickets being acceptable.
     */
    public final static String AUTHORIZED_PROXY_INIT_PARAM = "com.discursive.cas.extend.client.filter.authorizedProxy";
    
    /** The name of the filter initialization parameter the value of which must be the https: URL
     * to which CAS should send Proxy Granting Tickets when this filter validates tickets.
     */
    public final static String PROXY_CALLBACK_INIT_PARAM = "com.discursive.cas.extend.client.filter.proxyCallbackUrl";
    
    /** The name of the filter initialization parameter the value of which indicates
     * whether this filter should wrap requests to expose the authenticated username.
     */
    public final static String WRAP_REQUESTS_INIT_PARAM = "com.discursive.cas.extend.client.filter.wrapRequest";
    
    /** The name of the filter initialization parameter the value of which is the value the Filter
     * should send for the gateway parameter on the CAS login request.
     */
    public final static String GATEWAY_INIT_PARAM = "com.discursive.cas.extend.client.filter.gateway";

    /**  */
    public final static String DUMMY_TRUST_INIT_PARAM = "com.discursive.cas.extend.client.dummy.trust";

    /**  */
    public final static String SERVICE_SCHEME_INIT_PARAM = "com.discursive.cas.extend.client.filter.serviceScheme";

    
    // Session attributes used by this filter

    /** <p>Session attribute in which the username is stored.</p> */
    public final static String CAS_FILTER_USER =
        "com.discursive.cas.extend.client.filter.user";
    
    /**
     * Session attribute in which the CASReceipt is stored.
     */
    public final static String CAS_FILTER_RECEIPT =
        "com.discursive.cas.extend.client.filter.receipt";
    
    /**
     * Session attribute in which internally used gateway
     * attribute is stored.
     */
    private static final String CAS_FILTER_GATEWAYED =
        "com.discursive.cas.extend.client.filter.didGateway";


    //*********************************************************************
    // Configuration state
    private CASConfig casConfig;
        
    /**
     * List of ProxyTicketReceptor URLs of services authorized to proxy to the path
     * behind this filter.
     */
    private List<String> authorizedProxies = new ArrayList<String>();

    //*********************************************************************
    // Initialization 

    public void init(FilterConfig config) throws ServletException {
    	String jndiInit = config.getInitParameter(JNDI_INIT_PARAM);
    	if( jndiInit != null ) {
    		log.info( "Loading CASConfig from JNDI: " + jndiInit );
    		try {
				casConfig = configureFromJNDI( jndiInit );
			} catch (NamingException e) {
				log.error( "Error getting CASConfig from container", e );
				throw new ServletException( "There was an error attempting to get CASConfig from JNDI", e );
			}
    	} else {
    		log.info( "Loading CASConfig from Init Parameters." );
    		casConfig = configureFromInitParams( config );
    	}
    		

        if (casConfig.isCasGateway() && Boolean.valueOf(casConfig.isCasRenew()).booleanValue()) {
            throw new ServletException("gateway and renew cannot both be true in filter configuration");
        }
        if (casConfig.getCasServerName() != null && casConfig.getCasServiceUrl() != null) {
            throw new ServletException("serverName and serviceUrl cannot both be set: choose one.");
        }
        if (casConfig.getCasServerName() != null && casConfig.getMultiServerName() != null) {
            throw new ServletException("serverName and multiServerName cannot both be set: choose one.");
        }
        if (casConfig.getMultiServerName() == null && casConfig.getCasServerName() == null && casConfig.getCasServiceUrl() == null) {
        	throw new ServletException( "One of Multi Server Name, Server Name, or Service URL must be specified." );
        }
        if (casConfig.getCasServiceUrl() != null){
            if (! (casConfig.getCasServiceUrl().startsWith("https://")|| (casConfig.getCasServiceUrl().startsWith("http://") ))){
                throw new ServletException("service URL must start with http:// or https://; its current value is [" + casConfig.getCasServiceUrl() + "]");
            }
        }
        
        if (casConfig.getCasValidate() == null){
            throw new ServletException("validateUrl parameter must be set.");
        }
        if (! casConfig.getCasValidate().startsWith("https://")){
            throw new ServletException("validateUrl must start with https://, its current value is [" + casConfig.getCasValidate() + "]");
        }
        
        if (casConfig.getCasAuthorizedProxy() != null){
            
            // parse and remember authorized proxies
            StringTokenizer casProxies =
                new StringTokenizer(casConfig.getCasAuthorizedProxy());
            while (casProxies.hasMoreTokens()) {
                String anAuthorizedProxy = casProxies.nextToken();
                if (!anAuthorizedProxy.startsWith("https://")){
                    throw new ServletException("CASFilter initialization parameter for authorized proxies " +
                            "must be a whitespace delimited list of authorized proxies.  " +
                            "Authorized proxies must be secure (https) addresses.  This one wasn't: [" + anAuthorizedProxy + "]");
                }
                this.authorizedProxies.add(anAuthorizedProxy);
            }
        }
        
        if( casConfig.isDummyTrust() ) {
        	log.info( "Setting Dummy trust for Secure Connections" );
        	SecureURL.setDummy( true );
        }
        
        if (log.isDebugEnabled()){
					log.debug(("CASFilter initialized as: [" + toString() + "]"));
        }
    }
    
    public CASConfig configureFromJNDI(String jndiInit) throws NamingException {
    	//    	 Obtain our environment naming context
    	Context initCtx = new InitialContext();
    	Context envCtx = (Context) initCtx.lookup("java:comp/env");

    	//    	 Look up our data source
    	// Note: this is a workaround for a situation where a JAR in common/lib contains CASConfig
    	//       and the JAR that contains CASFilter also contains the CASConfig class.  In this
    	// 		 case, the class-cast will fail so, we copy the know bean-properties instead.
    	// Note: if anyone knows a beter way to handle this please contact the developers
    	Object object = envCtx.lookup(jndiInit);
    	CASConfig casConfig = new CASConfig();
    	try {
			PropertyUtils.copyProperties( casConfig, object );
		} catch (Exception e) {
			log.error( "Error copying properties from JNDI CASConfig to Filter CASConfig", e );
		}
		return casConfig;
    }
    
    public CASConfig configureFromInitParams(FilterConfig config) {
    	CASConfig casConfig = new CASConfig();
    	casConfig.setCasLogin(
            config.getInitParameter(
                LOGIN_INIT_PARAM)
                );
        casConfig.setCasValidate(
            config.getInitParameter(
                VALIDATE_INIT_PARAM)
                );
        casConfig.setCasServiceUrl(
            config.getInitParameter(
                SERVICE_INIT_PARAM)
                );
        casConfig.setCasAuthorizedProxy(
            config.getInitParameter(
                AUTHORIZED_PROXY_INIT_PARAM)
                );
        casConfig.setCasRenew(
            Boolean.valueOf(config.getInitParameter(RENEW_INIT_PARAM)).booleanValue() );
        casConfig.setCasServerName(
            config.getInitParameter(
                SERVERNAME_INIT_PARAM)
                );
        casConfig.setMultiServerName(
                config.getInitParameter(
                    MULTI_SERVERNAME_INIT_PARAM)
                    );
        casConfig.setCasProxyCallbackUrl(
            config.getInitParameter(
                PROXY_CALLBACK_INIT_PARAM)
                );
        casConfig.setWrapRequest(
            Boolean
                .valueOf(
                    config.getInitParameter(
                        WRAP_REQUESTS_INIT_PARAM))
                .booleanValue() );
        casConfig.setCasGateway(
            Boolean
                .valueOf(
                    config.getInitParameter(
                        GATEWAY_INIT_PARAM))
                .booleanValue() );
        casConfig.setServiceScheme( 
        		config.getInitParameter( SERVICE_SCHEME_INIT_PARAM ) );
        casConfig.setDummyTrust(
                Boolean.valueOf(config.getInitParameter(DUMMY_TRUST_INIT_PARAM)).booleanValue() );
        return casConfig;
    }

    //*********************************************************************
    // Filter processing

    public void doFilter(
        ServletRequest request,
        ServletResponse response,
        FilterChain fc)
        throws ServletException, IOException {

				if (log.isTraceEnabled()){
					log.trace("entering doFilter()");
				}

        // make sure we've got an HTTP request
        if (!(request instanceof HttpServletRequest)
            || !(response instanceof HttpServletResponse)) {
            	log.error("doFilter() called on a request or response that was not an HttpServletRequest or response.");
							throw new ServletException("CASFilter protects only HTTP resources");
            }
            

        // Is this a request for the proxy callback listener?  If so, pass
        // it through
        if (casConfig.getCasProxyCallbackUrl() != null
            && casConfig.getCasProxyCallbackUrl().endsWith(
                ((HttpServletRequest) request).getRequestURI())
            && request.getParameter("pgtId") != null
            && request.getParameter("pgtIou") != null) {
            	log.trace("passing through what we hope is CAS's request for proxy ticket receptor.");
            fc.doFilter(request, response);
            return;
        }

        // Wrap the request if desired
        if (casConfig.isWrapRequest()) {
        		log.trace("Wrapping request with CASFilterRequestWrapper.");
            request = new CASFilterRequestWrapper((HttpServletRequest) request);
        }

        HttpSession session = ((HttpServletRequest) request).getSession();

        // if our attribute's already present and valid, pass through the filter chain
        CASReceipt receipt = (CASReceipt) session.getAttribute(CAS_FILTER_RECEIPT);
        if (receipt != null && isReceiptAcceptable(receipt)) {
        		log.trace("CAS_FILTER_RECEIPT attribute was present and acceptable - passing  request through filter..");
            fc.doFilter(request, response);
            return;
        }

        // otherwise, we need to authenticate via CAS
        String ticket = request.getParameter("ticket");

        // no ticket?  abort request processing and redirect
        if (ticket == null || ticket.equals("")) {
						log.trace("CAS ticket was not present on request.");
            // did we go through the gateway already?
            boolean didGateway =
                Boolean
                    .valueOf(
                        (String) session.getAttribute(
                            CAS_FILTER_GATEWAYED))
                    .booleanValue();

            if (casConfig.getCasLogin() == null) {
            		//TODO: casLogin should probably be ensured to not be null at filter initialization. -awp9
            		log.fatal("casLogin was not set, so filter cannot redirect request for authentication.");
                throw new ServletException(
                    "When CASFilter protects pages that do not receive a 'ticket' "
                        + "parameter, it needs a com.discursive.cas.extend.client.filter.loginUrl "
                        + "filter parameter");
            }
            if (!didGateway) {
            		log.trace("Did not previously gateway.  Setting session attribute to true.");
                session.setAttribute(
                    CAS_FILTER_GATEWAYED,
                    "true");
                redirectToCAS(
                    (HttpServletRequest) request,
                    (HttpServletResponse) response);
                // abort chain
                return;
            } else {
            		log.trace("Previously gatewayed.");
                // if we should be logged in, make sure validation succeeded
                if (casConfig.isCasGateway()
                    || session.getAttribute(CAS_FILTER_USER) != null) {
                    	log.trace("casGateway was true and CAS_FILTER_USER set: passing request along filter chain.");
                    // continue processing the request
                    fc.doFilter(request, response);
                    return;
                } else {
                    // unknown state... redirect to CAS
                    session.setAttribute(
                        CAS_FILTER_GATEWAYED,
                        "true");
                    redirectToCAS(
                        (HttpServletRequest) request,
                        (HttpServletResponse) response);
                    // abort chain
                    return;
                }
            }
        }


        try {
            receipt = getAuthenticatedUser((HttpServletRequest) request);
        } catch (CASAuthenticationException e) {
            log.error(e);
            throw new ServletException(e);
        }

        if (! isReceiptAcceptable(receipt)){
            throw new ServletException("Authentication was technically successful but rejected as a matter of policy. [" + receipt + "]");
        }
        
        // Store the authenticated user in the session
        if (session != null) { // probably unnecessary
            session.setAttribute(CAS_FILTER_USER, receipt.getUserName());
            session.setAttribute(CASFilter.CAS_FILTER_RECEIPT, receipt);
            // don't store extra unnecessary session state
            session.removeAttribute(
                CAS_FILTER_GATEWAYED);
        }
        if (log.isTraceEnabled()){
					log.trace("validated ticket to get authenticated receipt [" + receipt + "], now passing request along filter chain.");
        }
        
        // continue processing the request
        fc.doFilter(request, response);
        log.trace("returning from doFilter()");
    }

    /**
     * Is this receipt acceptable as evidence of authentication by
     * credentials that would have been acceptable to this path?
     * Current implementation checks whether from renew and whether proxy
     * was authorized.
     * @param receipt
     * @return true if acceptable, false otherwise
     */
    private boolean isReceiptAcceptable(CASReceipt receipt) {
        if (receipt == null)
            throw new IllegalArgumentException("Cannot evaluate a null receipt.");
        if (this.casConfig.isCasRenew() && !receipt.isPrimaryAuthentication()){
            return false;
        }
        if (receipt.isProxied()){
            if (! this.authorizedProxies.contains(receipt.getProxyingService())){
                return false;
            }
        }
        return true;
    }

    //*********************************************************************
    // Utility methods

    /**
     * Converts a ticket parameter to a CASReceipt, taking into account an
     * optionally configured trusted proxy in the tier immediately in front
     * of us.
     * @throws ServletException - when unable to get service for request
     * @throws CASAuthenticationException - on authentication failure
     */
    private CASReceipt getAuthenticatedUser(HttpServletRequest request)
        throws ServletException, CASAuthenticationException {
        log.trace("entering getAuthenticatedUser()");
        ProxyTicketValidator pv = null;
        
            pv = new ProxyTicketValidator();
            pv.setCasValidateUrl(casConfig.getCasValidate() );
            pv.setServiceTicket(request.getParameter("ticket"));
            pv.setService(getService(request));
            pv.setRenew(Boolean.valueOf(casConfig.isCasRenew()).booleanValue());
            if (casConfig.getCasProxyCallbackUrl() != null) {
                pv.setProxyCallbackUrl(casConfig.getCasProxyCallbackUrl());
            }
            if (log.isDebugEnabled()) {
                log.debug(
                    "about to validate ProxyTicketValidator: [" + pv + "]");
            }
            
            return CASReceipt.getReceipt(pv);
        
    }

    /**
     * Returns either the configured service or figures it out for the current
     * request.  The returned service is URL-encoded.
     */
    private String getService(HttpServletRequest request)
        throws ServletException {

        log.trace("entering getService()");
        String serviceString;
        	
        // use the given string if it's provided
        // One of CasServiceUrl, CasServerName, and CasMultiServerName must be populated.
        if (casConfig.getCasServiceUrl() != null)
			try {
				serviceString = URLEncoder.encode(casConfig.getCasServiceUrl(), "UTF-8");
			} catch (UnsupportedEncodingException e) {
				log.error( "UTF-8 encoding not supported" );
				throw new ServletException( "UTF-8 encoding not supported" );
			}
		else if( casConfig.getCasServerName() != null ) {
            // if we've got the server name, return our best guess at the service
            serviceString = Util.getService(request, casConfig.getCasServerName(), casConfig.getServiceScheme());
		} else {
			// otherwise, use the HOST field to support virtual hosts.
			String serverName = request.getServerName();
			if( request.getServerPort() != 80 ) {
				serverName += ":" + request.getServerPort();
			}
			// But check it against a list of multiserver names
			String[] multiServers = StringUtils.split( casConfig.getMultiServerName() );
			if( !ArrayUtils.contains( multiServers, serverName ) ) {
				log.error( "Server " + serverName + " Does not match value in " + casConfig.getMultiServerName() );
				throw new ServletException("Server name not supported." );
			}
			
			serviceString = Util.getService(request, serverName, casConfig.getServiceScheme());
		}
        if (log.isTraceEnabled()) {
            log.trace(
                "returning from getService() with service ["
                    + serviceString
                    + "]");
        }
        return serviceString;
    }

    /**
     * Redirects the user to CAS, determining the service from the request.
     */
    private void redirectToCAS(
        HttpServletRequest request,
        HttpServletResponse response)
        throws IOException, ServletException {
        if (log.isTraceEnabled()) {
            log.trace("entering redirectToCAS()");
        }

        String casLoginString =
            casConfig.getCasLogin()
                + "?service="
                + getService((HttpServletRequest) request)
                + ((casConfig.isCasRenew())
                    ? "&renew=true"
                    : "")
                + (casConfig.isCasGateway() ? "&gateway=true" : "");

        if (log.isDebugEnabled()) {
            log.debug("Redirecting browser to [" + casLoginString + ")");
        }
        ((HttpServletResponse) response).sendRedirect(casLoginString);

        if (log.isTraceEnabled()) {
            log.trace("returning from redirectToCAS()");
        }
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("[CASFilter:");
        sb.append(" casGateway=");
        sb.append(this.casConfig.isCasGateway());
        sb.append(" wrapRequest=");
        sb.append(this.casConfig.isWrapRequest());
        
        sb.append(" casAuthorizedProxies=[");
        sb.append(this.authorizedProxies);
        sb.append("]");
        
        if (this.casConfig.getCasLogin() != null) {
            sb.append(" casLogin=[");
            sb.append(this.casConfig.getCasLogin());
            sb.append("]");
        } else {
            sb.append(" casLogin=NULL!!!!!");
        }
        
        if (this.casConfig.getCasProxyCallbackUrl() != null) {
            sb.append(" casProxyCallbackUrl=[");
            sb.append(casConfig.getCasProxyCallbackUrl());
            sb.append("]");
        }
        
        if (this.casConfig.isCasRenew()) {
            sb.append(" casRenew=true");
        }
        
        if (this.casConfig.getCasServerName() != null) {
            sb.append(" casServerName=[");
            sb.append(casConfig.getCasServerName());
            sb.append("]");
        }
        
        if (this.casConfig.getCasServiceUrl() != null) {
            sb.append(" casServiceUrl=[");
            sb.append(casConfig.getCasServiceUrl());
            sb.append("]");
        }
        
        if (this.casConfig.getCasValidate() != null) {
            sb.append(" casValidate=[");
            sb.append(casConfig.getCasValidate());
            sb.append("]");
        } else {
            sb.append(" casValidate=NULL!!!");
        }

        if (this.casConfig.getServiceScheme() != null) {
            sb.append(" serviceScheme=[");
            sb.append(casConfig.getServiceScheme());
            sb.append("]");
        } else {
            sb.append(" serviceScheme=NULL!!!");
        }

        return sb.toString();
    }

    /* (non-Javadoc)
     * @see javax.servlet.Filter#destroy()
     */
    public void destroy() {
        // TODO Auto-generated method stub
        
    }
}

/*
 *  Copyright (c) 2000-2004 Yale University. All rights reserved.
 *
 *  THIS SOFTWARE IS PROVIDED "AS IS," AND ANY EXPRESS OR IMPLIED
 *  WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF
 *  MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ARE EXPRESSLY
 *  DISCLAIMED. IN NO EVENT SHALL YALE UNIVERSITY OR ITS EMPLOYEES BE
 *  LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 *  CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED, THE COSTS OF
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA OR
 *  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 *  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 *  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 *  SOFTWARE, EVEN IF ADVISED IN ADVANCE OF THE POSSIBILITY OF SUCH
 *  DAMAGE.
 *
 *  Redistribution and use of this software in source or binary forms,
 *  with or without modification, are permitted, provided that the
 *  following conditions are met:
 *
 *  1. Any redistribution must include the above copyright notice and
 *  disclaimer and this list of conditions in any related documentation
 *  and, if feasible, in the redistributed software.
 *
 *  2. Any redistribution must include the acknowledgment, "This product
 *  includes software developed by Yale University," in any related
 *  documentation and, if feasible, in the redistributed software.
 *
 *  3. The names "Yale" and "Yale University" must not be used to endorse
 *  or promote products derived from this software.
 */
