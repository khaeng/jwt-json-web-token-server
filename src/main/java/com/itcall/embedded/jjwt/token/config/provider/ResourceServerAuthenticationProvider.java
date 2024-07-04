package com.itcall.embedded.jjwt.token.config.provider;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

import org.springframework.cache.annotation.EnableCaching;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authentication.AuthenticationCredentialsNotFoundException;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.RememberMeAuthenticationToken;
import org.springframework.security.authentication.TestingAuthenticationToken;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.authentication.jaas.JaasAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.core.DefaultOAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.OAuth2AccessToken.TokenType;
import org.springframework.security.oauth2.core.OAuth2AuthenticatedPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.InvalidBearerTokenException;
import org.springframework.security.oauth2.server.resource.authentication.AbstractOAuth2TokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthentication;
import org.springframework.security.oauth2.server.resource.authentication.BearerTokenAuthenticationToken;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.authentication.preauth.PreAuthenticatedAuthenticationToken;
import org.springframework.security.web.authentication.www.NonceExpiredException;
import org.springframework.stereotype.Component;

import com.fasterxml.jackson.core.type.TypeReference;
import com.itcall.embedded.jjwt.token.utils.CommonUtils;
import com.itcall.embedded.jjwt.token.utils.JJwtTokenUtils;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * <pre>개정이력(Modification Information)
 * Provider를 Bean으로 등록하면 인증관련 AutoConfiguration이 멈춘다. UserDetailsService 등을 직접 구현해야 한다.
 *     수정일           수정자     수정내용
 * ------------------------------------------
 * 2024. 7. 4.    KUEE-HAENG LEE :   최초작성
 * </pre>
 * @author KUEE-HAENG LEE
 * @version 1.0.0
 * @see
 * @since 2024. 7. 4.
 */
@Slf4j
@RequiredArgsConstructor
@EnableCaching
@Component
public class ResourceServerAuthenticationProvider implements AuthenticationProvider {

	@Override
	public Authentication authenticate(Authentication authentication) throws AuthenticationException {
		try {
			Object principal = null;
			String clientId = null;
			String username = null;
			String password = null;
			Collection<GrantedAuthority> authorities = null;
			String token = null;
			Object claims = null;
			
			if(authentication.getClass().isAssignableFrom(BearerTokenAuthenticationToken.class)){
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				BearerTokenAuthenticationToken oAuth2Token = BearerTokenAuthenticationToken.class.cast(authentication);
				principal = oAuth2Token.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(oAuth2Token.getAuthorities());
				username = oAuth2Token.getName();
				password = Objects.nonNull(oAuth2Token.getCredentials()) ? oAuth2Token.getCredentials().toString() : null;
				token = oAuth2Token.getToken();
			} else if(authentication.getClass().isAssignableFrom(JwtAuthenticationToken.class)){
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				JwtAuthenticationToken oAuth2Token = JwtAuthenticationToken.class.cast(authentication);
				principal = oAuth2Token.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(oAuth2Token.getAuthorities());
				username = oAuth2Token.getName();
				password = Objects.nonNull(oAuth2Token.getCredentials()) ? oAuth2Token.getCredentials().toString() : null;
				Jwt jwt = oAuth2Token.getToken();
				claims = jwt.getClaims();
				log.debug("AuthenticationToken Jwt Token-Claims: {}", claims);
				token = jwt.getTokenValue();
			} else if(authentication.getClass().isAssignableFrom(UsernamePasswordAuthenticationToken.class)){
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				UsernamePasswordAuthenticationToken usernamePasswordToken = UsernamePasswordAuthenticationToken.class.cast(authentication);
				principal = usernamePasswordToken.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(usernamePasswordToken.getAuthorities());
				username = usernamePasswordToken.getName();
				password = Objects.nonNull(usernamePasswordToken.getCredentials()) ? usernamePasswordToken.getCredentials().toString() : null;
			} else if(authentication.getClass().isAssignableFrom(JaasAuthenticationToken.class)){
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				JaasAuthenticationToken jaasToken = JaasAuthenticationToken.class.cast(authentication);
				principal = jaasToken.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(jaasToken.getAuthorities());
				username = jaasToken.getName();
				password = Objects.nonNull(jaasToken.getCredentials()) ? jaasToken.getCredentials().toString() : null;
			} else if(authentication.getClass().isAssignableFrom(PreAuthenticatedAuthenticationToken.class)){
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				PreAuthenticatedAuthenticationToken preAuthToken = PreAuthenticatedAuthenticationToken.class.cast(authentication);
				principal = preAuthToken.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(preAuthToken.getAuthorities());
				username = preAuthToken.getName();
				password = Objects.nonNull(preAuthToken.getCredentials()) ? preAuthToken.getCredentials().toString() : null;
			} else if(authentication.getClass().isAssignableFrom(RememberMeAuthenticationToken.class)){
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				RememberMeAuthenticationToken authToken = RememberMeAuthenticationToken.class.cast(authentication);
				principal = authToken.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(authToken.getAuthorities());
				username = authToken.getName();
				password = Objects.nonNull(authToken.getCredentials()) ? authToken.getCredentials().toString() : null;
			} else if(authentication.getClass().isAssignableFrom(TestingAuthenticationToken.class)){
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				TestingAuthenticationToken authToken = TestingAuthenticationToken.class.cast(authentication);
				principal = authToken.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(authToken.getAuthorities());
				username = authToken.getName();
				password = Objects.nonNull(authToken.getCredentials()) ? authToken.getCredentials().toString() : null;
			} else if(authentication.getClass().isAssignableFrom(AnonymousAuthenticationToken.class)){
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				AnonymousAuthenticationToken authToken = AnonymousAuthenticationToken.class.cast(authentication);
				principal = authToken.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(authToken.getAuthorities());
				username = authToken.getName();
				password = Objects.nonNull(authToken.getCredentials()) ? authToken.getCredentials().toString() : null;
//			} else if(authentication.getClass().isAssignableFrom(RunAsUserToken.class)) {
//				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
//				RunAsUserToken authToken = RunAsUserToken.class.cast(authentication);
//				principal = authToken.getPrincipal();
//				authorities = new ArrayList<GrantedAuthority>(authToken.getAuthorities());
//				username = authToken.getName();
//				password = Objects.nonNull(authToken.getCredentials()) ? authToken.getCredentials().toString() : null;
			} else if(AbstractOAuth2TokenAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				AbstractOAuth2TokenAuthenticationToken<?> authToken = AbstractOAuth2TokenAuthenticationToken.class.cast(authentication);
				principal = authToken.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(authToken.getAuthorities());
				username = authToken.getName();
				password = Objects.nonNull(authToken.getCredentials()) ? authToken.getCredentials().toString() : null;
			} else if(AbstractAuthenticationToken.class.isAssignableFrom(authentication.getClass())) {
				log.debug("AuthenticationToken class: {}", authentication.getClass().getName());
				AbstractAuthenticationToken authToken = AbstractAuthenticationToken.class.cast(authentication);
				principal = authToken.getPrincipal();
				authorities = new ArrayList<GrantedAuthority>(authToken.getAuthorities());
				username = authToken.getName();
				password = Objects.nonNull(authToken.getCredentials()) ? authToken.getCredentials().toString() : null;
			}
			log.debug("Found from token-info: principal[{}], clientId[{}], username[{}], password[{}]", principal, clientId, username, password);
			if(Objects.isNull(token)) {
				// return null; // ResourceServer에 Token이 없는 경우 인증 불가.
				throw new AuthenticationCredentialsNotFoundException("Authentication token not found.");
			}
			Map<String, Object> tokenInfo = convertBearerToken(token);
			if (Objects.isNull(tokenInfo) || Objects.isNull(tokenInfo.get("expireTime"))) {
				log.debug("LOGLOG : here");
				throw new InvalidBearerTokenException("Insufficient authentication exception");
			}
			if(isValidateTokenExpireTime((Long)tokenInfo.get("expireTime")) == false) {
				throw new NonceExpiredException("Authentication information has expired."); // Token유효시각 만료로 인증 불가.
			}
			if(JJwtTokenUtils.validateToken(token) == false) {
				log.debug("Embedded token validate is false. tokenInfo [{}]", tokenInfo);
				throw new InvalidBearerTokenException("Unable to check authentication token cannot be verified.");
			}
			// {aud=[aicentro-resource], scope=[read], exp=1705690180, authorities=[ROLE_AICENTRO_CLIENT], jti=440b2050-06f6-4144-a089-b2d30f98fcee, client_id=aicentro-app, clientId=aicentro-app, userId=null, expireTime=1705690180000}
			clientId = (String) tokenInfo.get("clientId");
			username = (String) tokenInfo.get("userId");
			
			Collection<String> scopes = CommonUtils.MAPPER.convertValue(
					tokenInfo.get("scope"), new TypeReference<List<Object>>() { }).stream().map(
							r -> /** "SCOPE_message:"+ **/
							r.toString()).collect(Collectors.toList());
			if((Objects.isNull(authorities) || authorities.isEmpty()) && tokenInfo.get("authorities") instanceof List) {
				authorities = CommonUtils.MAPPER.convertValue(
						tokenInfo.get("authorities"), new TypeReference<List<Object>>() { }).stream().map(
								r -> new SimpleGrantedAuthority(r.toString())).collect(Collectors.toList());
			}
			if(Objects.isNull(claims)) {
				claims = tokenInfo;
			}
			
			/** 인증 자동처리 **/
			OAuth2AuthenticatedPrincipal oAuth2Principal = null;
			AbstractAuthenticationToken authenticationToken = null;

			oAuth2Principal = new DefaultOAuth2AuthenticatedPrincipal(
					Objects.nonNull(username) && username.isBlank() == false ? username : null
							, tokenInfo, authorities);
			OAuth2AccessToken oAuth2AccessToken = new OAuth2AccessToken(TokenType.BEARER
					, token
					, Instant.now(),
					Instant.ofEpochMilli((long) tokenInfo.get("expireTime")),
					Set.copyOf(scopes));
			authenticationToken = new BearerTokenAuthentication(oAuth2Principal, oAuth2AccessToken, authorities);
			// authenticationToken = new BearerTokenAuthenticationToken(token);
			authenticationToken.setAuthenticated(true);
			authenticationToken.setDetails(claims);
			
			/** MessageConfig.resolveArgument에서 처리함 ==> 인증 서비스에 대한 Message 상시 사용처리
			 * GenericMessage message = RestMessage.OK().setParameterMap(request.getParameterMap());
			 * RequestContextHolder.getRequestAttributes().setAttribute(GENERIC_MESSAGE, message, RequestAttributes.SCOPE_REQUEST);
			 * // log.debug("", request, authenticationLoad, oAuth2Token);
			 **/ 
			return authenticationToken;
		} catch (Exception e) {
			log.info("Error During Authentication Process: exception[{}], message[{}]", e.getClass().getSimpleName(), e.getMessage(), e);
			throw e;
		}
	}

	@Override
	public boolean supports(Class<?> authentication) {
		/** ResourceServer의 모든 연결에 대해서 인증체크를 진행한다. **/
		return true;
	}

	/**
	 * Check Token Info: JWT Token Payload Decoding...
	 * @param token
	 * @return 
	 */
	private Map<String, Object> convertBearerToken(String token) {
		try {
			String[] tokenArr = token.split("[.]");
			String payload = new String(Base64.getDecoder().decode(tokenArr[1]));
			Map<String, Object> tokenPayload = CommonUtils.MAPPER.readValue(payload, new TypeReference<Map<String, Object>>() {});
			String userId = (String) tokenPayload.get("username");
			String clientId = (String) tokenPayload.get("client_id");
			Long expireTime = 1000L * (int) tokenPayload.get("exp");
			tokenPayload.put("clientId", clientId);
			tokenPayload.put("userId", userId);
			tokenPayload.put("expireTime", expireTime);
			return tokenPayload;
		} catch (Exception e) {
			log.debug("주입된 Token정보가 없습니다.");
			return null;
		}
	}
	private boolean isValidateTokenExpireTime(Long expireTime) {
		log.debug("Token정보를 이용하여 Access-Token이 만료시간 이내인지 체크.");
		return System.currentTimeMillis() <= expireTime;
	}

}
