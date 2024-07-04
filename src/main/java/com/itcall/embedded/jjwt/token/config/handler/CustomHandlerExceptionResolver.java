package com.itcall.embedded.jjwt.token.config.handler;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.access.AuthorizationServiceException;
import org.springframework.security.authentication.AccountExpiredException;
import org.springframework.security.authentication.AccountStatusException;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationServiceException;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.CredentialsExpiredException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.security.authentication.InsufficientAuthenticationException;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.authentication.LockedException;
import org.springframework.security.authentication.ProviderNotFoundException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedCredentialsNotFoundException;
import org.springframework.security.web.authentication.rememberme.CookieTheftException;
import org.springframework.security.web.authentication.rememberme.InvalidCookieException;
import org.springframework.security.web.authentication.rememberme.RememberMeAuthenticationException;
import org.springframework.security.web.authentication.session.SessionAuthenticationException;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import org.springframework.security.web.csrf.InvalidCsrfTokenException;
import org.springframework.security.web.csrf.MissingCsrfTokenException;
import org.springframework.security.web.server.csrf.CsrfException;
import org.springframework.stereotype.Component;
import org.springframework.web.servlet.ModelAndView;
import org.springframework.web.servlet.mvc.method.annotation.ExceptionHandlerExceptionResolver;

import com.google.common.collect.ImmutableMap;
import com.itcall.embedded.jjwt.token.utils.CommonUtils;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;

/**
 * 
 * <pre>
 * 개정이력(Modification Information)
 * 
 *     수정일           수정자     수정내용
 * ------------------------------------------
 * 2024. 7. 4.    KUEE-HAENG LEE :   최초작성
 * </pre>
 * 
 * @author KUEE-HAENG LEE
 * @version 1.0.0
 * @see
 * @since 2024. 7. 4.
 */
@Slf4j
@Component
public class CustomHandlerExceptionResolver extends ExceptionHandlerExceptionResolver {

	@Override
	public ModelAndView resolveException(HttpServletRequest request, HttpServletResponse response, Object handler,
			Exception ex) {
		Class<?> exClass = ex.getClass();
		try {
			if (AuthenticationException.class.isAssignableFrom(exClass)) {
				/** 인증 처리 중 에러... **/
				response.setStatus(HttpStatus.UNAUTHORIZED.value());

				log.debug("ExceptionName: {}", exClass.getName());
				response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.toString());

				response.getOutputStream().flush();

				if (UsernameNotFoundException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (SessionAuthenticationException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (InvalidCookieException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (CookieTheftException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (RememberMeAuthenticationException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (ProviderNotFoundException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (PreAuthenticatedCredentialsNotFoundException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (InvalidBearerTokenException.class.isAssignableFrom(exClass)) {

					log.debug("ExceptionName: {}", exClass.getName());
				} else if (OAuth2AuthenticationException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (NonceExpiredException.class.isAssignableFrom(exClass)) {

					log.debug("ExceptionName: {}", exClass.getName());
				} else if (InsufficientAuthenticationException.class.isAssignableFrom(exClass)) {

					log.debug("ExceptionName: {}", exClass.getName());
				} else if (BadCredentialsException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (InternalAuthenticationServiceException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (AuthenticationServiceException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (AuthenticationCredentialsNotFoundException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (LockedException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (DisabledException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (CredentialsExpiredException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (AccountExpiredException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (AccountStatusException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else {
					log.debug("Unkown.ExceptionName: {}", exClass.getName());
				}
				response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.toString());
				response.getOutputStream().write(CommonUtils.MAPPER
						.writeValueAsString(ImmutableMap.of("issue", exClass.getSimpleName(), "class",
								exClass.getName(), "message", ex.getMessage(), "localMsg", ex.getLocalizedMessage()))
						.getBytes());
				response.getOutputStream().flush();

			} else if (AccessDeniedException.class.isAssignableFrom(exClass)) {
				/** 인증 권한 없음... **/
				response.setStatus(HttpStatus.NOT_ACCEPTABLE.value());
				if (AuthorizationServiceException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (CsrfException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (InvalidCsrfTokenException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (MissingCsrfTokenException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else if (org.springframework.security.web.csrf.CsrfException.class.isAssignableFrom(exClass)) {
					log.debug("ExceptionName: {}", exClass.getName());
				} else {
					log.debug("Unkown.ExceptionName: {}", exClass.getName());
				}
				response.setHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON.toString());
				response.getOutputStream().write(CommonUtils.MAPPER
						.writeValueAsString(ImmutableMap.of("issue", exClass.getSimpleName(), "class",
								exClass.getName(), "message", ex.getMessage(), "localMsg", ex.getLocalizedMessage()))
						.getBytes());
				response.getOutputStream().flush();
			} else {
				return super.resolveException(request, response, handler, ex);
			}
		} catch (Exception e) {
			log.error("ExceptionResolver.Error: message[{}]", e.getMessage(), e);
		}
		return super.resolveException(request, response, handler, ex);
	}

}
