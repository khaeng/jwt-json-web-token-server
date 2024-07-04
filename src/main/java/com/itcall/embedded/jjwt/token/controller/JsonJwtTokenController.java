package com.itcall.embedded.jjwt.token.controller;

import java.util.Base64;

import org.springframework.http.MediaType;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.util.Assert;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import com.itcall.embedded.jjwt.token.service.JsonJwtTokenService;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;

/**
 * <pre>개정이력(Modification Information)
 * 
 *     수정일           수정자     수정내용
 * ------------------------------------------
 * 2024. 7. 4.    KUEE-HAENG LEE :   최초작성
 * </pre>
 * @author KUEE-HAENG LEE
 * @version 1.0.0
 * @see
 * @since 2024. 7. 4.
 */
@RestController
@RequiredArgsConstructor
@RequestMapping({ "/oauth", "/oauth2" })
public class JsonJwtTokenController {

	private static final String AUTH_HEADER_NAME = "Authorization";
	private static final String CLIENT_ID = "client_id";
	private static final String CLIENT_SECRET = "client_secret";
	private static final String GRANT_TYPE = "grant_type";
	private static final String AVAILABLE_GRANT_TYPE = "client_credentials, password, refresh_token";
	private static final String SCOPE = "scope";
	private static final String USERNAME = "username";
	private static final String PASSWORD = "password";
	private static final String TOKEN = "token";
	private static final String REFRESH_TOKEN = "refresh_token";

	private final JsonJwtTokenService jsonJwtTokenService;

	/**
	 * 토큰 생성 요청
	 * @return
	 * @throws Exception 
	 */
	@PostMapping(value = { "/token" })
	public void createToken(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader(name = AUTH_HEADER_NAME, required = true) String headerAuthorization,
			@RequestParam(name = GRANT_TYPE, required = true) String grantType,
			@RequestParam(name = SCOPE, required = false) String scope,
			@RequestParam(name = USERNAME, required = false) String username,
			@RequestParam(name = PASSWORD, required = false) String password,
			@RequestParam(name = REFRESH_TOKEN, required = false) String refreshToken
			) throws Exception {
		Assert.isTrue(headerAuthorization.toLowerCase().startsWith("basic "), "CasAuthenticationProvider.incorrectKey");
		
		String clientId = null;
		String clientSecret = null;
		try {
			String encBasicToken = headerAuthorization.split(" ", 2)[1];
			String basicTokens[] = new String(Base64.getDecoder().decode(encBasicToken)).split(":",2);
			clientId = basicTokens[0];
			clientSecret = basicTokens[1];
		} catch (Exception e) {
			throw new OAuth2AuthenticationException(
					new OAuth2Error(
							OAuth2ErrorCodes.INVALID_REQUEST
							, "AbstractUserDetailsAuthenticationProvider.badCredentials"
							, request.getRequestURL().toString())); // Authentication[인증-증명-입증], Authorization[권한부여-승인-허가]
		}
		String result = this.jsonJwtTokenService.createToken(grantType, scope, clientId, clientSecret, username, password, refreshToken);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.getOutputStream().write(result.getBytes());
		response.getOutputStream().flush();
		return;
	}

	/**
	 * 토큰 validate 요청
	 * @return
	 * @throws Exception 
	 */
	@PostMapping(value = { "/check_token" })
	public void validateToken(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader(name = AUTH_HEADER_NAME, required = true) String headerAuthorization,
			@RequestParam(name = TOKEN, required = true) String token
			) throws Exception {
		Assert.isTrue(headerAuthorization.toLowerCase().startsWith("basic "), "CasAuthenticationProvider.incorrectKey");
		
		String clientId = null;
		String clientSecret = null;
		try {
			String encBasicToken = headerAuthorization.split(" ", 2)[1];
			String basicTokens[] = new String(Base64.getDecoder().decode(encBasicToken)).split(":",2);
			clientId = basicTokens[0];
			clientSecret = basicTokens[1];
		} catch (Exception e) {
			throw new OAuth2AuthenticationException(
					new OAuth2Error(
							OAuth2ErrorCodes.INVALID_REQUEST
							, "AbstractUserDetailsAuthenticationProvider.badCredentials"
							, request.getRequestURL().toString())); // Authentication[인증-증명-입증], Authorization[권한부여-승인-허가]
		}
		String result = this.jsonJwtTokenService.validateToken(clientId, clientSecret, token);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.getOutputStream().write(result.getBytes());
		response.getOutputStream().flush();
		return;
	}

	/**
	 * 토큰 revoke 요청
	 * @return
	 * @throws Exception 
	 */
	@PostMapping(value = { "/revoke", "/revoke_token", "/remove", "/remove_token", "/logout" })
	public void revokeToken(HttpServletRequest request, HttpServletResponse response,
			@RequestHeader(name = AUTH_HEADER_NAME, required = true) String headerAuthorization,
			@RequestParam(name = TOKEN, required = true) String token
			) throws Exception {
		Assert.isTrue(headerAuthorization.toLowerCase().startsWith("basic "), "CasAuthenticationProvider.incorrectKey");
		
		String clientId = null;
		String clientSecret = null;
		try {
			String encBasicToken = headerAuthorization.split(" ", 2)[1];
			String basicTokens[] = new String(Base64.getDecoder().decode(encBasicToken)).split(":",2);
			clientId = basicTokens[0];
			clientSecret = basicTokens[1];
		} catch (Exception e) {
			throw new OAuth2AuthenticationException(
					new OAuth2Error(
							OAuth2ErrorCodes.INVALID_REQUEST
							, "AbstractUserDetailsAuthenticationProvider.badCredentials"
							, request.getRequestURL().toString())); // Authentication[인증-증명-입증], Authorization[권한부여-승인-허가]
		}
		String result = this.jsonJwtTokenService.revokeToken(clientId, clientSecret, token);
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.getOutputStream().write(result.getBytes());
		response.getOutputStream().flush();
		return;
	}

}
