/**
 * 
 */
package com.itcall.embedded.jjwt.token.utils;

import java.time.ZonedDateTime;
import java.util.Date;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.util.Assert;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonMappingException;
import com.google.common.collect.ImmutableList;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.MalformedJwtException;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.UnsupportedJwtException;
import lombok.Getter;
import lombok.extern.slf4j.Slf4j;

/**
 * <pre>
 * 개정이력(Modification Information)
 * Json Web Token Utils.
 *     수정일           수정자     수정내용
 * ------------------------------------------
 * 2024. 7. 2.    KUEE-HAENG LEE :   최초작성
 * </pre>
 * 
 * @author KUEE-HAENG LEE
 * @version 1.0.0
 * @see
 * @since 2024. 7. 2.
 */
@Slf4j
public class JJwtTokenUtils {

	private static final int DEF_ACCESS_TOKEN_EXPIRATIONS = 20 * 60 * 1000;
	private static final int DEF_REFRESH_TOKEN_EXPIRATIONS = 120 * 60 * 1000;

	private static final ConcurrentHashMap<String, Map<String, Object>> TOKEN_CACHER
	= new ConcurrentHashMap<String, Map<String, Object>>(
			new LinkedHashMap<String, Map<String, Object>>());
	// private static final LinkedHashMap<String, String> TOKEN_CACHER = new
	// LinkedHashMap<String, String>();
	
	@Getter
	private static boolean isUseEmbeddedOAuth2;
	
	private static Object dummyObject;
	
	private static String secretKey;
	private static String issuer; // APP_NAME
//	private static String redisType; // Token저장소 사용여부.
//	private static String resourceIds; // client_id에 허용된 Resource서버 영역들... 콤마구분
	private static int accessTokenExpireAfterSeconds;
	private static int refreshTokenExpireAfterSeconds;

	public static final void initialize(String secretKey, String issuer, // String redisType, String resourceIds,
			int accessTokenExpireAfterSeconds, int refreshTokenExpireAfterSeconds) {
		Assert.isTrue(Objects.isNull(dummyObject), "내장형 OAuth2 Token 사용 여부는 실행 시 1회만 설정할 수 있습니다.");
		if(Objects.isNull(secretKey) || Objects.isNull(issuer)) {
			isUseEmbeddedOAuth2 = false;
		} else {
			isUseEmbeddedOAuth2 = true;
		}
		JJwtTokenUtils.dummyObject = new Object();
		JJwtTokenUtils.secretKey = secretKey;
		JJwtTokenUtils.issuer = issuer;
//		JJwtTokenUtils.redisType = redisType;
//		JJwtTokenUtils.resourceIds = resourceIds;
		JJwtTokenUtils.accessTokenExpireAfterSeconds = accessTokenExpireAfterSeconds <= 0
				? DEF_ACCESS_TOKEN_EXPIRATIONS
				: accessTokenExpireAfterSeconds;
		JJwtTokenUtils.refreshTokenExpireAfterSeconds = refreshTokenExpireAfterSeconds <= 0
				? DEF_REFRESH_TOKEN_EXPIRATIONS
				: DEF_REFRESH_TOKEN_EXPIRATIONS;
	}

	public static Map<String, Object> createAccessToken(Claims claims, int accessTokenExpiration, int refreshTokenExpiration)
			throws JsonMappingException, JsonProcessingException {
		String key = getKey(claims);
		Map<String, Object> tokenStoreMap = getUsingCacher(key);
		if (Objects.nonNull(tokenStoreMap)) {
			String oldAccessToken = tokenStoreMap.get("access_token").toString();
			if (validateToken(oldAccessToken)) {
				log.info("ReUse token");
				Claims oldClaims = parseClaims(oldAccessToken);
				tokenStoreMap.put("issued_at", (oldClaims.getIssuedAt().getTime())); // Unix_TimeStamp 기준. 초단위.
				tokenStoreMap.put("expires_in", (oldClaims.getExpiration().getTime() - System.currentTimeMillis()) / 1000); // Unix_TimeStamp 기준. 초단위.
				return tokenStoreMap;
			}
		}
		tokenStoreMap = new HashMap<String, Object>();
		// tokenStoreMap.putAll(claims);
		tokenStoreMap.put("token_type", "bearer");
		tokenStoreMap.put("scope", claims.getOrDefault("scope", ImmutableList.of()));
		String accessToken = createToken(claims, accessTokenExpiration <= 0 ? accessTokenExpireAfterSeconds : accessTokenExpiration);
		tokenStoreMap.put("access_token", accessToken);
		Object username = claims.getOrDefault("username", null);
		if (Objects.nonNull(username)) {
			tokenStoreMap.put("username", username);
			tokenStoreMap.put("refresh_token", createToken(claims, refreshTokenExpiration <= 0 ? refreshTokenExpireAfterSeconds : refreshTokenExpiration));
			setUsingCacher(key, tokenStoreMap, refreshTokenExpiration <= 0 ? refreshTokenExpireAfterSeconds : refreshTokenExpiration);
		} else {
			setUsingCacher(key, tokenStoreMap, accessTokenExpiration <= 0 ? accessTokenExpireAfterSeconds : accessTokenExpiration);
		}
		Claims newClaims = parseClaims(accessToken);
		tokenStoreMap.put("issued_at", newClaims.getIssuedAt().getTime()); // / 1000); // Unix_TimeStamp 기준. 초단위.
		tokenStoreMap.put("expires_in", (newClaims.getExpiration().getTime() - System.currentTimeMillis()) / 1000); // Unix_TimeStamp 기준. 초단위.
		return tokenStoreMap;
	}

	public static Map<String, Object> recreateAccessToken(String refreshToken, int accessTokenExpiration, int refreshTokenExpiration) throws Exception {
		if (validateToken(refreshToken)) {
			return createAccessToken(parseClaims(refreshToken), accessTokenExpiration, refreshTokenExpiration);
		}
		throw new Exception("Cannot created access_token using refresh_token.");
	}

	private static String getKey(String token) {
		Claims claims = parseClaims(token);
		return getKey(claims);
	}

	private static String getKey(Claims claims) {
		String usernameOrClientId = claims.get("username", String.class);
		if (Objects.isNull(usernameOrClientId)) {
			usernameOrClientId = claims.get("client_id", String.class);
		}
		return String.format("%s::%s", issuer, usernameOrClientId);
	}

	private static Map<String, Object> getUsingCacher(String key) throws JsonMappingException, JsonProcessingException {
//		if (Objects.nonNull(redisType)) {
//			String redisCacheContents = RedisUtil.get(key, String.class);
//			if(Objects.nonNull(redisCacheContents)) {
//				return CommonUtils.MAPPER.readValue(redisCacheContents, new TypeReference<Map<String, Object>>() { });
//			} else { 
//				return null;
//			}
//		} else {
			return TOKEN_CACHER.get(key);
//		}
	}

	private static void setUsingCacher(String key, Map<String, Object> value, int expireAfterSeconds)
			throws JsonProcessingException {
//		if (Objects.nonNull(redisType)) {
//			RedisUtil.put(key, CommonUtils.MAPPER.writeValueAsString(value), expireAfterSeconds * 1000L);
//		} else {
			TOKEN_CACHER.put(key, value);
//		}
	}

	private static void removeUsingCacher(String key) {
//		if (Objects.nonNull(redisType)) {
//			RedisUtil.delete(key);
//		} else {
			TOKEN_CACHER.remove(key);
//		}
	}

	/**
	 * <pre>
	 * JJWT 규격으로 Token을 생성합니다.
	 * </pre>
	 * 
	 * @author KUEE-HAENG LEE
	 * @param claims
	 * @param expireAfterSeconds
	 * @return
	 */
	private static String createToken(Claims claims, int expireAfterSeconds) {
//			Claims claims = Jwts.claims()
//					.add("username", userDetails.getUsername())
//					.add("authorities", userDetails.getAuthorities().stream().map(g -> g.getAuthority()).collect(Collectors.toSet()))
//					.add("sub", "sub-info")
//					.build();
		ZonedDateTime now = ZonedDateTime.now();
		ZonedDateTime tokenValidity = now.plusSeconds(expireAfterSeconds);
		String token = Jwts.builder().setClaims(claims).setIssuedAt(Date.from(now.toInstant()))
				.setExpiration(Date.from(tokenValidity.toInstant())).signWith(SignatureAlgorithm.HS256, secretKey)
				.compact();
		return token;
	}

	/**
	 * Token에서 client_id 추출
	 * 
	 * @param token
	 * @return client_id
	 */
	public static String getClientId(String token) {
		if (Objects.isNull(secretKey)) {
			throw new RuntimeException();
		}
		return parseClaims(token).get("client_id", String.class);
	}

	/**
	 * Token에서 Username 추출
	 * 
	 * @param token
	 * @return Username
	 */
	public static String getUsername(String token) {
		if (Objects.isNull(secretKey)) {
			throw new RuntimeException();
		}
		return parseClaims(token).get("username", String.class);
	}

	/**
	 * JWT Claims 추출
	 * 
	 * @param token
	 * @return JWT Claims
	 */
	public static Claims parseClaims(String token) {
		try {
			return Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(token).getBody();
		} catch (ExpiredJwtException e) {
			return e.getClaims();
		}
	}

	/**
	 * JWT 검증
	 * 
	 * @param token
	 * @return IsValidate
	 * @throws JsonProcessingException
	 * @throws JsonMappingException
	 */
	public static boolean validateToken(String token) {
		try {
			String key = getKey(token);
			if (Objects.nonNull(getUsingCacher(key))) {
				Jwts.parser().setSigningKey(secretKey).build().parseClaimsJws(token);
				return true;
			}
			log.info("Token removed.");
		} catch (io.jsonwebtoken.security.SecurityException | MalformedJwtException e) {
			log.info("Invalid JWT Token", e);
		} catch (ExpiredJwtException e) {
			log.info("Expired JWT Token", e);
		} catch (UnsupportedJwtException e) {
			log.info("Unsupported JWT Token", e);
		} catch (IllegalArgumentException e) {
			log.info("JWT claims string is empty.", e);
		} catch (JsonMappingException e) {
			log.info("JWT claims string is cannot converting.", e);
		} catch (JsonProcessingException e) {
			log.info("JWT claims string is not Json string.", e);
		}
		return false;
	}

	/**
	 * JWT 삭제
	 * 
	 * @param token
	 * @return Deleting Token
	 * @throws JsonProcessingException
	 * @throws JsonMappingException
	 */
	public static boolean revokeToken(String token) throws JsonMappingException, JsonProcessingException {
		String key = getKey(token);
		if (Objects.nonNull(getUsingCacher(key))) {
			removeUsingCacher(key);
			return true;
		}
		log.info("Token already revokation: token[{}]", token);
		return false;
	}

}
