package rmontag.jsfexample.common;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Enumeration;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The HTTP Header Security Filter supports the following initialization parameters:
* <ul>
* <li>hstsEnabled - 
* Will an HTTP Strict Transport Security (HSTS) header (Strict-Transport-Security) be set on the response for secure requests. 
* Any HSTS header already present will be replaced. See RFC 6797 for further details of HSTS. If not specified, the default value of true will be used.
* </li>
* <li>hstsMaxAgeSeconds -
* The max age value that should be used in the HSTS header. Negative values will be treated as zero. If not specified, the default value of 0 will be used.
* </li>
* <li>hstsIncludeSubDomains -
* Should the includeSubDomains parameter be included in the HSTS header. If not specified, the default value of false will be used.
* </li>
* <li>antiClickJackingEnabled -
* Should the anti click-jacking header (X-Frame-Options) be set on the response. Any anti click-jacking header already present will be replaced. If not specified, the default value of true will be used.
* </li>
* <li>antiClickJackingOption -
* What value should be used for the ant click-jacking header? Must be one of DENY, SAMEORIGIN, ALLOW-FROM (case-insensitive). If not specified, the default value of DENY will be used.
* </li>
* <li>antiClickJackingUri -
* If ALLOW-FROM is used for antiClickJackingOption, what URI should be allowed? If not specified, the default value of an empty string will be used.
* </li>
* <li>blockContentTypeSniffingEnabled -
* Should the header that blocks content type sniffing (X-Content-Type-Options) be set on every response. If already present, the header will be replaced. If not specified, the default value of true will be used.
* </li>
* <li>xssProtectionEnabled -
* Should the header that enables the browser's cross-site scripting filter protection (X-XSS-Protection: 1; mode=block) be set on every response. If already present, the header will be replaced. If not specified, the default value of true will be used.
* </li>
* </ul>
* 
 * @author ex532
 *
 */
public class HttpHeaderSecurityFilter implements Filter {

	@SuppressWarnings("unused")
	private static final Logger LOG = LoggerFactory.getLogger(HttpHeaderSecurityFilter.class);

	// parameter names
    private static final String HSTS_ENABLED_INIT_PARAM = "hstsEnabled";
    private static final String HSTS_MAX_AGE_SECONDS_INIT_PARAM = "hstsMaxAgeSeconds";
    private static final String HSTS_INCLUDE_SUB_DOMAINS_INIT_PARAM = "hstsIncludeSubDomains";
    private static final String ANTI_CLICK_JACKING_ENABLED_INIT_PARAM = "antiClickJackingEnabled";
    private static final String ANTI_CLICK_JACKING_OPTION_INIT_PARAM = "antiClickJackingOption";
    private static final String ANTI_CLICK_JACKING_URI_INIT_PARAM = "antiClickJackingUri";
    private static final String BLOCK_CONTENT_TYPE_SNIFFING_ENABLED_INIT_PARAM = "blockContentTypeSniffingEnabled";
    private static final String XSS_PROTECTION_ENABLED_INIT_PARAM = "xssProtectionEnabled";

    // HSTS
    private static final String HSTS_HEADER_NAME = "Strict-Transport-Security";
    private boolean hstsEnabled = true;
    private int hstsMaxAgeSeconds = 0;
    private boolean hstsIncludeSubDomains = false;
    private String hstsHeaderValue;

    // Click-jacking protection
    private static final String ANTI_CLICK_JACKING_HEADER_NAME = "X-Frame-Options";
    private boolean antiClickJackingEnabled = true;
    private XFrameOption antiClickJackingOption = XFrameOption.DENY;
    private URI antiClickJackingUri;
    private String antiClickJackingHeaderValue;

    // Block content sniffing
    private static final String BLOCK_CONTENT_TYPE_SNIFFING_HEADER_NAME = "X-Content-Type-Options";
    private static final String BLOCK_CONTENT_TYPE_SNIFFING_HEADER_VALUE = "nosniff";
    private boolean blockContentTypeSniffingEnabled = true;

    // Cross-site scripting filter protection
    private static final String XSS_PROTECTION_HEADER_NAME = "X-XSS-Protection";
    private static final String XSS_PROTECTION_HEADER_VALUE = "1; mode=block";
    private boolean xssProtectionEnabled = true;

    @Override
    public void init(FilterConfig filterConfig) throws ServletException {

    	doInit(filterConfig);

        // Build HSTS header value
        StringBuilder hstsValue = new StringBuilder("max-age=");
        hstsValue.append(hstsMaxAgeSeconds);
        if (hstsIncludeSubDomains) {
            hstsValue.append(";includeSubDomains");
        }
        hstsHeaderValue = hstsValue.toString();

        // Anti click-jacking
        StringBuilder cjValue = new StringBuilder(antiClickJackingOption.headerValue);
        if (antiClickJackingOption == XFrameOption.ALLOW_FROM) {
            cjValue.append(' ');
            cjValue.append(antiClickJackingUri);
        }
        antiClickJackingHeaderValue = cjValue.toString();
    }


    @Override
    public void doFilter(ServletRequest request, ServletResponse response,
            FilterChain chain) throws IOException, ServletException {

        if (response instanceof HttpServletResponse) {
            HttpServletResponse httpResponse = (HttpServletResponse) response;

            if (response.isCommitted()) {
                throw new ServletException("Unable to add HTTP headers since response is already committed on entry to the HTTP header security Filter");
            }

            // HSTS
            if (hstsEnabled && request.isSecure()) {
                httpResponse.setHeader(HSTS_HEADER_NAME, hstsHeaderValue);
            }

            // anti click-jacking
            if (antiClickJackingEnabled) {
                httpResponse.setHeader(ANTI_CLICK_JACKING_HEADER_NAME, antiClickJackingHeaderValue);
            }

            // Block content type sniffing
            if (blockContentTypeSniffingEnabled) {
                httpResponse.setHeader(BLOCK_CONTENT_TYPE_SNIFFING_HEADER_NAME,
                        BLOCK_CONTENT_TYPE_SNIFFING_HEADER_VALUE);
            }

            // cross-site scripting filter protection
            if (xssProtectionEnabled) {
                httpResponse.setHeader(XSS_PROTECTION_HEADER_NAME, XSS_PROTECTION_HEADER_VALUE);
            }
        }

        chain.doFilter(request, response);
    }


    public boolean isHstsEnabled() {
        return hstsEnabled;
    }


    public void setHstsEnabled(boolean hstsEnabled) {
        this.hstsEnabled = hstsEnabled;
    }


    public int getHstsMaxAgeSeconds() {
        return hstsMaxAgeSeconds;
    }


    public void setHstsMaxAgeSeconds(int hstsMaxAgeSeconds) {
        if (hstsMaxAgeSeconds < 0) {
            this.hstsMaxAgeSeconds = 0;
        } else {
            this.hstsMaxAgeSeconds = hstsMaxAgeSeconds;
        }
    }


    public boolean isHstsIncludeSubDomains() {
        return hstsIncludeSubDomains;
    }


    public void setHstsIncludeSubDomains(boolean hstsIncludeSubDomains) {
        this.hstsIncludeSubDomains = hstsIncludeSubDomains;
    }



    public boolean isAntiClickJackingEnabled() {
        return antiClickJackingEnabled;
    }



    public void setAntiClickJackingEnabled(boolean antiClickJackingEnabled) {
        this.antiClickJackingEnabled = antiClickJackingEnabled;
    }



    public String getAntiClickJackingOption() {
        return antiClickJackingOption.toString();
    }


    public void setAntiClickJackingOption(String antiClickJackingOption) {
        for (XFrameOption option : XFrameOption.values()) {
            if (option.getHeaderValue().equalsIgnoreCase(antiClickJackingOption)) {
                this.antiClickJackingOption = option;
                return;
            }
        }
        throw new IllegalArgumentException("An invalid value [" + antiClickJackingOption + "] was specified for the anti click-jacking header");
    }



    public String getAntiClickJackingUri() {
        return antiClickJackingUri.toString();
    }


    public boolean isBlockContentTypeSniffingEnabled() {
        return blockContentTypeSniffingEnabled;
    }


    public void setBlockContentTypeSniffingEnabled(
            boolean blockContentTypeSniffingEnabled) {
        this.blockContentTypeSniffingEnabled = blockContentTypeSniffingEnabled;
    }


    public void setAntiClickJackingUri(String antiClickJackingUri) {
        URI uri;
        try {
            uri = new URI(antiClickJackingUri);
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(e);
        }
        this.antiClickJackingUri = uri;
    }

    public boolean isXssProtectionEnabled() {
        return xssProtectionEnabled;
    }

    public void setXssProtectionEnabled(boolean xssProtectionEnabled) {
        this.xssProtectionEnabled = xssProtectionEnabled;
    }

    private static enum XFrameOption {
        DENY("DENY"),
        SAME_ORIGIN("SAMEORIGIN"),
        ALLOW_FROM("ALLOW-FROM");


        private final String headerValue;

        private XFrameOption(String headerValue) {
            this.headerValue = headerValue;
        }

        public String getHeaderValue() {
            return headerValue;
        }
    }
    
    private void doInit(FilterConfig filterConfig) throws ServletException {

		Enumeration<String> paramNames = filterConfig.getInitParameterNames();
        while (paramNames.hasMoreElements()) {
            String paramName = paramNames.nextElement();
            switch (paramName) {
            // hstsEnabled
            case HSTS_ENABLED_INIT_PARAM: {
            	String initParameter = filterConfig.getInitParameter(paramName);
            	if (initParameter != null) {
            		setHstsEnabled(Boolean.parseBoolean(initParameter));
            	}
            	break;
            }
            // hstsMaxAgeSeconds
            case HSTS_MAX_AGE_SECONDS_INIT_PARAM: {
            	String initParameter = filterConfig.getInitParameter(paramName);
            	if (initParameter != null) {
            		setHstsMaxAgeSeconds(Integer.parseInt(initParameter));
            	}
            	break;
            }
            // hstsIncludeSubDomains
            case HSTS_INCLUDE_SUB_DOMAINS_INIT_PARAM: {
            	String initParameter = filterConfig.getInitParameter(paramName);
            	if (initParameter != null) {
            		setHstsIncludeSubDomains(Boolean.parseBoolean(initParameter));
            	}
            	break;
            }
            // antiClickJackingEnabled
            case ANTI_CLICK_JACKING_ENABLED_INIT_PARAM: {
            	String initParameter = filterConfig.getInitParameter(paramName);
            	if (initParameter != null) {
            		setAntiClickJackingEnabled(Boolean.parseBoolean(initParameter));
            	}
            	break;
            }
            // antiClickJackingOption
            case ANTI_CLICK_JACKING_OPTION_INIT_PARAM: {
            	String initParameter = filterConfig.getInitParameter(paramName);
            	if (initParameter != null) {
            		setAntiClickJackingOption(initParameter);
            	}
            	break;
            }
            // antiClickJackingUri
            case ANTI_CLICK_JACKING_URI_INIT_PARAM: {
            	String initParameter = filterConfig.getInitParameter(paramName);
            	if (initParameter != null) {
            		setAntiClickJackingUri(initParameter);
            	}
            	break;
            }
            // blockContentTypeSniffingEnabled
            case BLOCK_CONTENT_TYPE_SNIFFING_ENABLED_INIT_PARAM: {
            	String initParameter = filterConfig.getInitParameter(paramName);
            	if (initParameter != null) {
            		setBlockContentTypeSniffingEnabled(Boolean.parseBoolean(initParameter));
            	}
            	break;
            }
            // xssProtectionEnabled
            case XSS_PROTECTION_ENABLED_INIT_PARAM: {
            	String initParameter = filterConfig.getInitParameter(paramName);
            	if (initParameter != null) {
            		setXssProtectionEnabled(Boolean.parseBoolean(initParameter));
            	}
            	break;
            }
            // unknown
            default: {
                String msg = "The property " + paramName + " is not defined for filters of type " + this.getClass().getName();
                throw new ServletException(msg);
            }
        }
        }            
        
	}

	@Override
	public void destroy() {
	}

}
