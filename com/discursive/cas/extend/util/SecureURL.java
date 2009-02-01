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

package com.discursive.cas.extend.util;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;
import java.net.URLConnection;

import javax.net.ssl.HttpsURLConnection;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * A class housing some utility functions exposing secure URL validation
 * and content retrieval.  The rules are intended to be about as restrictive
 * as a common browser with respect to server-certificate validation.
 */
public class SecureURL {

	private static Log log = LogFactory.getLog(SecureURL.class);
	
	private static boolean dummy;
	
    /**
     * For testing only...
     */
    public static void main(String args[]) throws IOException {
        System.setProperty(
            "java.protocol.handler.pkgs",
            "com.sun.net.ssl.internal.www.protocol");
        System.out.println(SecureURL.retrieve(args[0]));
    }

    /** 
     * Retrieve the contents from the given URL as a String, assuming the
     * URL's server matches what we expect it to match.
     */
    public static String retrieve(String url) throws IOException {
    	if (log.isTraceEnabled()){
    		log.trace("entering retrieve(" + url + ")");
    	}
        BufferedReader r = null;
        try {
            URL u = new URL(url);
            if (!u.getProtocol().equals("https")){
            	// IOException may not be the best exception we could throw here
            	// since the problem is with the URL argument we were passed, not
            	// IO. -awp9
            	log.error("retrieve(" + url + ") on an illegal URL since protocol was not https.");
							throw new IOException("only 'https' URLs are valid for this method");
            }
                
            URLConnection uc = u.openConnection();
            if( dummy ) {
            	((HttpsURLConnection)uc).setSSLSocketFactory(new DummySSLSocketFactory());
            	((HttpsURLConnection)uc).setHostnameVerifier(new DummyHostnameVerifier());
            }
            uc.setRequestProperty("Connection", "close");
            r = new BufferedReader(new InputStreamReader(uc.getInputStream()));
            String line;
            StringBuffer buf = new StringBuffer();
            while ((line = r.readLine()) != null)
                buf.append(line + "\n");
            return buf.toString();
        } finally {
            try {
                if (r != null)
                    r.close();
            } catch (IOException ex) {
                // ignore
            }
        }
    }
    
    public static void setDummy(boolean flag) {
    	dummy = flag;
    }
}
