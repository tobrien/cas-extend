/*
 *  Copyright (c) 2000-2003 Yale University. All rights reserved.
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

package com.discursive.cas.extend.client;

import java.io.UnsupportedEncodingException;
import java.net.URLEncoder;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Provides utility functions in support of CAS clients.
 */
public class Util {

	private static Log log = LogFactory.getLog(Util.class);

	/**
	 * Returns a service ID (URL) as a composite of the preconfigured server
	 * name and the runtime request, removing the request parameter "ticket".
	 */
	public static String getService(HttpServletRequest request, String server,
			String serviceScheme) throws ServletException {
		if (log.isTraceEnabled()) {
			log.trace("entering getService(" + request + ", " + server + ")");
		}

		// ensure we have a server name
		if (server == null) {
			log.error("getService() argument \"server\" was illegally null.");
			throw new IllegalArgumentException("name of server is required");
		}

		// now, construct our best guess at the string
		StringBuffer sb = new StringBuffer();
		if (!StringUtils.isEmpty(serviceScheme)) {
			log.debug("Service Scheme not empty, setting service scheme to: "
					+ serviceScheme);
			sb.append(serviceScheme + "://");
		} else {
			if (request.isSecure()) {
				log.debug("Request is Secure, setting to https");
				sb.append("https://");
			} else {
				log.debug("Request is Not Secure, setting to http");
				sb.append("http://");
			}
		}
		
		log.debug( "Appending Server: " + server );
		sb.append(server);
		
		log.debug( "Appending Request URI: " + request.getRequestURI());
		sb.append(request.getRequestURI());

		if (!StringUtils.isEmpty(request.getQueryString())) {
			// first, see whether we've got a 'ticket' at all
			int ticketLoc = request.getQueryString().indexOf("ticket=");

			// if ticketLoc == 0, then it's the only parameter and we ignore
			// the whole query string

			// if no ticket is present, we use the query string wholesale
			if (ticketLoc == -1) {
				log.debug( "no ticket present, appending query string: " + request.getQueryString());
				sb.append("?" + request.getQueryString());
			} else if (ticketLoc > 0) {
				ticketLoc = request.getQueryString().indexOf("&ticket=");
				if (ticketLoc == -1) {
					// there was a 'ticket=' unrelated to a parameter named
					// 'ticket'
					sb.append("?" + request.getQueryString());
				} else if (ticketLoc > 0) {
					// otherwise, we use the query string up to "&ticket="
					sb.append("?"
							+ request.getQueryString().substring(0, ticketLoc));
				}
			}
		}
		String encodedService;
		try {
			encodedService = URLEncoder.encode(sb.toString(), "UTF-8");
		} catch (UnsupportedEncodingException e) {
			log.error("UTF-8 encoding not supported");
			throw new ServletException(
					"Error get CAS Service, UTF-8 encoding of service not supported.");
		}
		if (log.isTraceEnabled()) {
			log.trace("returning from getService() with encoded service ["
					+ encodedService + "]");
		}
		return encodedService;
	}
}
