package rmontag.jsfexample.common;

import java.io.IOException;

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
 * Filter zum Einstellen des Response-Headers 'Content-Security-Policy'.
 * 
 * Bietet ebenfalls Unterstuetzung f�r die (deprecated) Header
 * <ul>
 * <li>'X-Content-Security-Policy'</li>
 * <li>'X-Webkit-CSP'</li>
 * </ul>
 * Hier muss man jeweils aktuell pruefen, welche Browser und welcher Browser-Versionen welchen der Header unterstuetzen. 
 * Insbesondere f�r die "alten" Microsoft Internet Explorer Versionen 10/11 und f�r iOS bzw. Safari-Browser ist es teilweise
 * noch notwendig, die entsprechenden Deprecated-Header zu setzen.
 * 
 * 
 * Supported init params:
 * <ul>
 * <li>contentSecurityPolicyEnabled: Value: [true|false] Description: Should Response-Header 'Content-Security-Policy' be set or not (Default: true).</li>
 * <li>headerXcontentSecurityPolicyEnabled: Value: [true|false] Description: Should Response-Header 'X-Content-Security-Policy' additionally be set or not. 
 * If contentSecurityPolicyEnabled is set to false, then this Response-Header is not set, even if this property is set to true (Default: true).</li>
 * <li>headerXwebkitCSPEnabled: Value: [true|false] Description: Should Response-Header 'X-Webkit-CSP' additionally be set or not.
 * If contentSecurityPolicyEnabled is set to false, then this Response-Header is not set, even if this property is set to true (Default: true).</li>
 * <li>contentSecurityPolicyReportOnlyEnabled: Value: [true|false] Description: Should Response-Header 'Content-Security-Policy-Report-Only' be set or not (Default: true).</li>
 * 
 * <li>contentSecurityPolicy: In case of contentSecurityPolicyEnabled=true the Header value to set for
 * - 'Content-Security-Policy'
 * - 'X-Content-Security-Policy', if headerXcontentSecurityPolicyEnabled=true
 * - 'X-Webkit-CSP', if headerXwebkitCSPEnabled=true  
 * (Default: "default-src 'self';").
 * </li>
 * <li>contentSecurityPolicyReportOnly: In case of contentSecurityPolicyEnabled=true the Header value to set for 'Content-Security-Policy' (Default: "default-src 'self';").</li>
 * </ul>
 * If no values are provided, but enabled is set to 'true', then the (strict) default value "default-src 'self';" is used. 
 * Using this default value will result in a LOT of errors regarding "inline styles" and "inline scripts"!
 * 
 */
public class ContentSecurityPolicyFilter implements Filter {

	/**
	 * Klassenspezifischer Logger
	 */
	private static final Logger LOG = LoggerFactory.getLogger(ContentSecurityPolicyFilter.class);
	
	// HEADER values
	private static final String CONTENT_SECURITY_POLICY_HEADER = "Content-Security-Policy";
	// Report-Only
	private static final String CONTENT_SECURITY_POLICY_HEADER_REPORT_ONLY = "Content-Security-Policy-Report-Only";
	// For IE 10,11
	private static final String X_CONTENT_SECURITY_POLICY_HEADER = "X-Content-Security-Policy";
	// For iOS, Safari
	private static final String X_WEBKIT_CSP_HEADER = "X-Webkit-CSP";

	// init params for Filter to set in web.xml
	public static final String INIT_PARAM_CONTENT_SECURITY_POLICY = "contentSecurityPolicy";
	public static final String INIT_PARAM_CONTENT_SECURITY_POLICY_REPORT_ONLY = "contentSecurityPolicyReportOnly";

	public static final String INIT_PARAM_CONTENT_SECURITY_POLICY_ENABLED = "contentSecurityPolicyEnabled";
	public static final String INIT_PARAM_CONTENT_SECURITY_POLICY_REPORT_ONLY_ENABLED = "contentSecurityPolicyReportOnlyEnabled";
	public static final String INIT_PARAM_HEADER_X_CONTENT_SECURITY_POLICY_ENABLED = "headerXcontentSecurityPolicyEnabled";
	public static final String INIT_PARAM_HEADER_X_WEBKIT_CSP_ENABLED = "headerXwebkitCSPEnabled";

	// default values
	private static final String DEFAULT_VALUE = "default-src 'self';";
	private static final String CONTENT_SECURITY_POLICY_DEFAULT_VALUE = DEFAULT_VALUE;
	private static final String CONTENT_SECURITY_POLICY_REPORT_ONLY_DEFAULT_VALUE = DEFAULT_VALUE;

	private String valueContentSecurityPolicyHeader = CONTENT_SECURITY_POLICY_DEFAULT_VALUE;
	private String valueContentSecurityPolicyReportOnlyHeader = CONTENT_SECURITY_POLICY_REPORT_ONLY_DEFAULT_VALUE;
	private String valueXWebkitCSPHeader = CONTENT_SECURITY_POLICY_DEFAULT_VALUE;
	private String valueXContentSecurityPolicyHeader = CONTENT_SECURITY_POLICY_DEFAULT_VALUE;

	private boolean contentSecurityPolicyEnabled = true;
	private boolean contentSecurityPolicyReportOnlyEnabled = true;
	private boolean headerXcontentSecurityPolicyEnabled = true;
	private boolean headerXwebkitCSPEnabled = true;

	@Override
	public void init(FilterConfig filterConfig) throws ServletException {
		// Content-Security-Policy
		initContentSecurityPolicy(filterConfig);
		// Content-Security-Policy-Report-Only
		initContentSecurityPolicyReportOnly(filterConfig);
		// X-Content-Security-Policy
		initXContentSecurityPolicy(filterConfig);
		// X-Webkit-CSP
		initXWebkitCSP(filterConfig);
	}

	private void initContentSecurityPolicy(FilterConfig filterConfig) {
		// contentSecurityPolicy enabled?
		String valueContentSecurityPolicyEnabled = filterConfig.getInitParameter(
				INIT_PARAM_CONTENT_SECURITY_POLICY_ENABLED);
		if (valueContentSecurityPolicyEnabled != null) {
			// set output variable
			contentSecurityPolicyEnabled = Boolean.parseBoolean(valueContentSecurityPolicyEnabled);
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("contentSecurityPolicyEnabled is " + contentSecurityPolicyEnabled 
					+ (valueContentSecurityPolicyEnabled != null ?  "." : "by default."));
		}

		if (contentSecurityPolicyEnabled) {
			String valueInitContentSecurityPolicy = filterConfig.getInitParameter(INIT_PARAM_CONTENT_SECURITY_POLICY);
			if (valueInitContentSecurityPolicy != null) {
				// set output variable
				valueContentSecurityPolicyHeader = valueInitContentSecurityPolicy;
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug((valueInitContentSecurityPolicy != null) ? "using init value " : "using default value " 
			+ valueContentSecurityPolicyHeader + " for header " + CONTENT_SECURITY_POLICY_HEADER);
			}
		}
	}

	/**
	 * Sets valueContentSecurityPolicyReportOnlyHeader
	 * @param filterConfig
	 */
	private void initContentSecurityPolicyReportOnly(FilterConfig filterConfig) {
		// ContentSecurityPolicyReportOnly enabled?
		String valueContentSecurityPolicyReportOnlyEnabled = filterConfig.getInitParameter(
				INIT_PARAM_CONTENT_SECURITY_POLICY_REPORT_ONLY_ENABLED);
		if (valueContentSecurityPolicyReportOnlyEnabled != null) {
			// set output variable
			contentSecurityPolicyReportOnlyEnabled = Boolean.parseBoolean(valueContentSecurityPolicyReportOnlyEnabled);
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("contentSecurityPolicyReportOnlyEnabled is " + contentSecurityPolicyReportOnlyEnabled 
					+ (valueContentSecurityPolicyReportOnlyEnabled != null ?  "." : "by default."));
		}
		
		if (contentSecurityPolicyReportOnlyEnabled) {
			String valueInitContentSecurityPolicyReportOnly = filterConfig.getInitParameter(INIT_PARAM_CONTENT_SECURITY_POLICY_REPORT_ONLY);
			if (valueInitContentSecurityPolicyReportOnly != null) {
				// set output variable
				valueContentSecurityPolicyReportOnlyHeader = valueInitContentSecurityPolicyReportOnly;
			}
			if (LOG.isDebugEnabled()) {
				LOG.debug((valueInitContentSecurityPolicyReportOnly != null) ? "using init value " : "using default value " 
			+ valueContentSecurityPolicyReportOnlyHeader + " for header " + CONTENT_SECURITY_POLICY_HEADER_REPORT_ONLY);
			}
		}
	}

	private void initXWebkitCSP(FilterConfig filterConfig) {
		// CSP && xwebkitCSP enabled?
		String valueHeaderXwebkitCSPEnabled = filterConfig.getInitParameter(INIT_PARAM_HEADER_X_WEBKIT_CSP_ENABLED);
		if (valueHeaderXwebkitCSPEnabled != null) {
			// set output variable
			headerXwebkitCSPEnabled = Boolean.parseBoolean(valueHeaderXwebkitCSPEnabled);
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("headerXwebkitCSPEnabled is " + headerXwebkitCSPEnabled
					+ (valueHeaderXwebkitCSPEnabled != null ? "." : "by default."));
		}
		
		if (contentSecurityPolicyEnabled && headerXwebkitCSPEnabled) {
			// set output variable
			valueXWebkitCSPHeader = valueContentSecurityPolicyHeader;
			if (LOG.isDebugEnabled()) {
				LOG.debug("using init value " + valueXWebkitCSPHeader + " for header " + X_WEBKIT_CSP_HEADER);
			}
		}
	}

	private void initXContentSecurityPolicy(FilterConfig filterConfig) {
		// CSP && xcontentSecurityPolicy enabled?
		String valueHeaderXcontentSecurityPolicyEnabled = filterConfig.getInitParameter(INIT_PARAM_HEADER_X_CONTENT_SECURITY_POLICY_ENABLED);
		if (valueHeaderXcontentSecurityPolicyEnabled != null) {
			// set output variable
			headerXcontentSecurityPolicyEnabled = Boolean.parseBoolean(valueHeaderXcontentSecurityPolicyEnabled);
		}
		if (LOG.isDebugEnabled()) {
			LOG.debug("headerXcontentSecurityPolicyEnabled is " + headerXcontentSecurityPolicyEnabled
					+ (valueHeaderXcontentSecurityPolicyEnabled != null ? "." : "by default."));
		}
		
		if (contentSecurityPolicyEnabled && headerXcontentSecurityPolicyEnabled) {
			// set output variable
			valueXContentSecurityPolicyHeader = valueContentSecurityPolicyHeader;
			if (LOG.isDebugEnabled()) {
				LOG.debug("using init value " + valueXContentSecurityPolicyHeader + " for header " + X_CONTENT_SECURITY_POLICY_HEADER);
			}
		}
	}

	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
			throws IOException, ServletException {
		HttpServletResponse httpResponse = (HttpServletResponse) response;

		if (contentSecurityPolicyEnabled) {
			httpResponse.setHeader(CONTENT_SECURITY_POLICY_HEADER, valueContentSecurityPolicyHeader);
		}
		if (contentSecurityPolicyReportOnlyEnabled) {
			httpResponse.setHeader(CONTENT_SECURITY_POLICY_HEADER_REPORT_ONLY, valueContentSecurityPolicyReportOnlyHeader); 
		}
		if (contentSecurityPolicyEnabled && headerXcontentSecurityPolicyEnabled) {
			httpResponse.setHeader(X_CONTENT_SECURITY_POLICY_HEADER, valueXContentSecurityPolicyHeader);
		}
		if (contentSecurityPolicyEnabled && headerXwebkitCSPEnabled) {
			httpResponse.setHeader(X_WEBKIT_CSP_HEADER, valueXWebkitCSPHeader);
		}

		chain.doFilter(request, response);
	}

	@Override
	public void destroy() {
	}

}
