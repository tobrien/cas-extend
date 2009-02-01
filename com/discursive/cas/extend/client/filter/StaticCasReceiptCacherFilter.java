/*  Copyright (c) 2000-2004 Yale University. All rights reserved. 
 *  See full notice at end.
 */

package com.discursive.cas.extend.client.filter;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

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

import com.discursive.cas.extend.client.CASReceipt;

/**
 * <p>
 * Static filter class which caches CASReceipts, keyed by the tickets the
 * validation of which the receipts represent.
 * </p>
 * 
 * @author andrew.petro@yale.edu
 */
public class StaticCasReceiptCacherFilter implements Filter {

    private static Log log = LogFactory
            .getLog(StaticCasReceiptCacherFilter.class);

    private static Map<String,CASReceipt> ticketsToReceipts = Collections
            .synchronizedMap(new HashMap<String,CASReceipt>());

    public void init(FilterConfig config) throws ServletException {

    }

    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain fc) throws ServletException, IOException {

        if (log.isTraceEnabled()) {
            log.trace("entering doFilter()");
        }

        // make sure we've got an HTTP request
        if (!(request instanceof HttpServletRequest)
                || !(response instanceof HttpServletResponse)) {
            log
                    .error("doFilter() called on a request or response that was not an HttpServletRequest or response.");
            throw new ServletException(
                    "StaticCasReceiptCacherFilter applies to only HTTP resources");
        }

        HttpSession session = ((HttpServletRequest) request).getSession();

        // if our attribute's already present and valid, pass through the filter
        // chain
        CASReceipt receipt = (CASReceipt) session
                .getAttribute(CASFilter.CAS_FILTER_RECEIPT);

        // otherwise, we need to authenticate via CAS
        String ticket = request.getParameter("ticket");

        if (ticket != null && receipt != null) {
            StaticCasReceiptCacherFilter.ticketsToReceipts.put(ticket, receipt);
        }

        // continue processing the request
        fc.doFilter(request, response);
        log.trace("returning from doFilter()");
    }

    public String toString() {
        StringBuffer sb = new StringBuffer();
        sb.append("[CASFilter:");
        sb.append(StaticCasReceiptCacherFilter.ticketsToReceipts);
        sb.append("]");
        return sb.toString();
    }

    /**
     * Get the cached CASReceipt, if any, for a given service or proxy ticket string,
     * the validation of which yielded the receipt.
     * @param ticket - a service or proxy ticket previously validated by the CASFilter.
     * @return the CASReceipt representing the prior validation of the ticket, or null.
     */
    public static CASReceipt receiptForTicket(String ticket) {
        return (CASReceipt) StaticCasReceiptCacherFilter.ticketsToReceipts
                .get(ticket);
    }

    /*
     * (non-Javadoc)
     * 
     * @see javax.servlet.Filter#destroy()
     */
    public void destroy() {
    }
}

/*
 * Copyright (c) 2000-2004 Yale University. All rights reserved.
 * 
 * THIS SOFTWARE IS PROVIDED "AS IS," AND ANY EXPRESS OR IMPLIED WARRANTIES,
 * INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE, ARE EXPRESSLY DISCLAIMED. IN NO EVENT SHALL
 * YALE UNIVERSITY OR ITS EMPLOYEES BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED, THE COSTS OF PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED IN ADVANCE OF THE POSSIBILITY OF SUCH DAMAGE.
 * 
 * Redistribution and use of this software in source or binary forms, with or
 * without modification, are permitted, provided that the following conditions
 * are met:
 * 
 * 1. Any redistribution must include the above copyright notice and disclaimer
 * and this list of conditions in any related documentation and, if feasible, in
 * the redistributed software.
 * 
 * 2. Any redistribution must include the acknowledgment, "This product includes
 * software developed by Yale University," in any related documentation and, if
 * feasible, in the redistributed software.
 * 
 * 3. The names "Yale" and "Yale University" must not be used to endorse or
 * promote products derived from this software.
 */
