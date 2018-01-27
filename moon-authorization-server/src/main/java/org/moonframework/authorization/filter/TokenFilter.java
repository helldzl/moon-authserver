package org.moonframework.authorization.filter;

import javax.servlet.*;
import java.io.IOException;

/**
 * @author quzile
 * @version 1.0
 * @since 2018/1/27
 */
public class TokenFilter implements Filter {

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {
        System.out.println();
    }

    @Override
    public void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain filterChain) throws IOException, ServletException {

        // TODO something else
        System.out.println("start");
        filterChain.doFilter(servletRequest, servletResponse);
        System.out.println("end");
    }

    @Override
    public void destroy() {

    }

}