package com.discursive.cas.extend.client.filter;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * <p>Filter protects resources such that only specified usernames, as 
 * authenticated with CAS, can access.</p>
 * 
 * <p><code>com.discursive.cas.extend.client.filter.user</code> must be set before 
 * this filter in the filter chain.</p>
 * 
 * <p>This filter takes the init-param 
 * <code>com.discursive.cas.extend.client.filter.authorizedUsers</code>, a 
 * whitespace-delimited list of users authorized to pass through this 
 * filter.</p>
 *
 * @author Andrew Petro
 */
public class SimpleCASAuthorizationFilter implements Filter {

	//*********************************************************************
	// Constants

	public static final String AUTHORIZED_USER_STRING =
		"com.discursive.cas.extend.client.filter.authorizedUsers";
		
	private static final Log log = LogFactory.getLog(SimpleCASAuthorizationFilter.class);

	//*********************************************************************
	// Configuration state

	private String authorizedUsersString;
	private List<String> authorizedUsers;

	//*********************************************************************
	// Initialization 

	public void init(FilterConfig config) throws ServletException {
		log.trace("entering init()");
		this.authorizedUsersString =
			config.getInitParameter(AUTHORIZED_USER_STRING);
		StringTokenizer tokenizer = new StringTokenizer(authorizedUsersString);
		this.authorizedUsers = new ArrayList<String>();
		while (tokenizer.hasMoreTokens()) {
			this.authorizedUsers.add((String) tokenizer.nextElement());
		}
		if (log.isTraceEnabled()){
			log.trace("returning from init() having initialized filter as [" + toString() + "]");
		}
	}

	//*********************************************************************
	// Filter processing

	public void doFilter(
		ServletRequest request,
		ServletResponse response,
		FilterChain fc)
		throws ServletException, IOException {

		if (log.isTraceEnabled()){
			log.trace("entering doFilter(" + request + ", " + response + ", " + fc + ")");
		}

		// make sure we've got an HTTP request
		if (!(request instanceof HttpServletRequest)
			|| !(response instanceof HttpServletResponse)) {
				log.error("doFilter() called on instance of HttpServletRequest or HttpServletResponse.");
			throw new ServletException(
				SimpleCASAuthorizationFilter.class.getName() + ": protects only HTTP resources");
		}

		HttpSession session = ((HttpServletRequest) request).getSession();
		String currentUser = (String) session.getAttribute(CASFilter.CAS_FILTER_USER);
		if (this.authorizedUsers.isEmpty()) {
			//TODO: this may be a configuration error we wish to detect in init() -awp9
			log.error("User cannot be authorized if no users are authorized.");
			// break the fiter chain by throwing exception
			throw new ServletException(SimpleCASAuthorizationFilter.class.getName() + ": no authorized users set.");

		} else if (!this.authorizedUsers.contains(currentUser)) {
			log.info("Current user [" + currentUser + "] not among authorized users.");
			// break the filter chain by throwing exception
			throw new ServletException(
				SimpleCASAuthorizationFilter.class.getName()
					+ ": user "
					+ session.getAttribute(CASFilter.CAS_FILTER_USER)
					+ " not authorized.");
		}
		if (log.isTraceEnabled()){
			log.trace("User [" + currentUser + "] was authorized.  Passing request along filter chain.");
		}
		// continue processing the request
		fc.doFilter(request, response);
		log.trace("returning from doFilter()");
	}

	//*********************************************************************
	// Destruction

	public void destroy() {
	}

}
