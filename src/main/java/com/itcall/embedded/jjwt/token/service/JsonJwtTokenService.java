package com.itcall.embedded.jjwt.token.service;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.stream.Collectors;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.Pageable;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import com.google.common.collect.ImmutableList;
import com.itcall.embedded.jjwt.token.entity.Clients;
import com.itcall.embedded.jjwt.token.entity.UsersEntity;
import com.itcall.embedded.jjwt.token.repository.ClientsRepository;
import com.itcall.embedded.jjwt.token.repository.UsersRepository;
import com.itcall.embedded.jjwt.token.utils.CommonUtils;
import com.itcall.embedded.jjwt.token.utils.JJwtTokenUtils;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.ClaimsBuilder;
import io.jsonwebtoken.Jwts;
import jakarta.security.auth.message.AuthException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

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
@Slf4j
@RequiredArgsConstructor
@Service
public class JsonJwtTokenService {

	private final UsersRepository userRepository;
	private final ClientsRepository clientsRepository;
	private final PasswordEncoder passwordEncoder;

	public Clients registerClient(Clients client) {
		return clientsRepository.save(client);
	}

	public Page<Clients> listClients(Pageable pageable) {
		return clientsRepository.findAll(pageable);
	}

	public String createToken(String grantType, String scope, String clientId, String clientSecret, String username, String password, String refreshToken) throws Exception {
		Map<String,Object> result = null;
		Optional<Clients> client = this.clientsRepository.findByClientId(clientId);
		if (client.isPresent() == false) throw new AuthException("등록된 클라이언트 정보가 존재하지 않습니다.");
		// scope은 필수로 처리하지 않는다. 권한으로 scope을 사용하는 경우만 등록하기로 함.
//		if (grantType.toLowerCase().equals("refresh_token") == false &&
//				Arrays.asList(scope.split(",")).stream().filter(s -> client.get().getScope().contains(s)).count() <= 0 )
//			throw new AuthException("요청된 Scope이 존재하지 않습니다.");
		if(this.passwordEncoder.matches(clientSecret, client.get().getClientSecret()) == false && 
				client.get().getClientSecret().equals(clientSecret) == false)
			throw new AuthException("등록된 클라이언트 정보와 다릅니다.");
		
		ClaimsBuilder claims = Jwts.claims()
				.add("client_id", clientId)
				;
		if(grantType.toLowerCase().equals("password")) {
			Optional<UsersEntity> user = this.userRepository.findByUsername(username);
			if (user.isPresent() == false) throw new AuthException("등록된 사용자 정보가 존재하지 않습니다.");
			if (user.get().isAccountExpired()) throw new AuthException("사용자 계정의 유효 기간이 만료 되었습니다.");
			if (user.get().isAccountLocked()) throw new AuthException("사용자 계정이 잠겨 있습니다.");
			if (user.get().isCredentialsExpired()) throw new AuthException("자격 증명 유효 기간이 만료되었습니다.");
			if (user.get().isEnabled() == false) throw new AuthException("사용자 계정이 잠겨 있습니다.");
			if (user.get().getIsDeleted()) throw new AuthException("삭제된 사용자입니다.");
			if (Objects.isNull(password) || password.isBlank()) throw new AuthException("비밀번호 항목이 비어 있습니다.");
			if (this.passwordEncoder.matches(password, user.get().getPassword()) == false) throw new AuthException("비밀번호가 맞지 않습니다.");
			claims.add("scope", Objects.isNull(scope) || scope.isBlank() ? ImmutableList.of() : Arrays.asList(scope.split(",")));
			claims.add("username", username);
			claims.add("authorities", user.get().getAuthorities().stream().map(g -> g.getAuthority()).collect(Collectors.toSet()));
			result = JJwtTokenUtils.createAccessToken(claims.build(), client.get().getAccessTokenValiditySeconds(), client.get().getRefreshTokenValiditySeconds());
			log.debug("최초 사용자[{}] 토큰 생성:\n{}", username, result);
		} else if(grantType.toLowerCase().equals("refresh_token")) {
			String tokenUsername = JJwtTokenUtils.getUsername(refreshToken);
			if(Objects.isNull(tokenUsername) || tokenUsername.isBlank()) throw new AuthException("등록된 사용자 정보가 존재하지 않습니다.");
			Optional<UsersEntity> user = this.userRepository.findByUsername(tokenUsername);
			if (user.isPresent() == false) throw new AuthException("등록된 사용자 정보가 존재하지 않습니다.");
			result = JJwtTokenUtils.recreateAccessToken(refreshToken, client.get().getAccessTokenValiditySeconds(), client.get().getRefreshTokenValiditySeconds());
			log.debug("refresh to access: 사용자[{}] 토큰 재생성:\n{}", tokenUsername, result);
		} else if(grantType.toLowerCase().equals("client_credentials")) {
			claims.add("scope", Objects.isNull(scope) || scope.isBlank() ? ImmutableList.of() : Arrays.asList(scope.split(",")));
			claims.add("authorities", Arrays.asList(client.get().getAuthorities().split(",")));
			result = JJwtTokenUtils.createAccessToken(claims.build(), client.get().getAccessTokenValiditySeconds(), client.get().getRefreshTokenValiditySeconds());
			log.debug("최초 API 토큰 생성:\n{}", result);
		} else {
			throw new AuthException("자격 증명에 실패하였습니다.");
		}
		return CommonUtils.MAPPER.writeValueAsString(result);
	}

	public String validateToken(String clientId, String clientSecret, String token) throws Exception {
		Map<String,Object> result = null;
		Optional<Clients> client = this.clientsRepository.findByClientId(clientId);
		if (client.isPresent() == false) throw new AuthException("등록된 클라이언트 정보가 존재하지 않습니다.");
		if(this.passwordEncoder.matches(clientSecret, client.get().getClientSecret()) == false && 
				client.get().getClientSecret().equals(clientSecret) == false)
			throw new AuthException("등록된 클라이언트 정보와 다릅니다.");
		boolean isActive = JJwtTokenUtils.validateToken(token);
		if(isActive) {
			Claims claims = JJwtTokenUtils.parseClaims(token);
			result = new HashMap<String, Object>(claims);
			result.put("active", isActive);
		} else {
			log.debug("Token validate is {}. token[{}]", false, token);
			throw new AuthException("자격 증명 유효 기간이 만료되었습니다.");
		}
		return CommonUtils.MAPPER.writeValueAsString(result);
	}

	public String revokeToken(String clientId, String clientSecret, String token) throws Exception {
		Map<String,Object> result = null;
		Optional<Clients> client = this.clientsRepository.findByClientId(clientId);
		if (client.isPresent() == false) throw new AuthException("등록된 클라이언트 정보가 존재하지 않습니다.");
		if(this.passwordEncoder.matches(clientSecret, client.get().getClientSecret()) == false && 
				client.get().getClientSecret().equals(clientSecret) == false)
			throw new AuthException("등록된 클라이언트 정보와 다릅니다.");
		boolean isRevoke = JJwtTokenUtils.revokeToken(token);
		if(isRevoke) {
			Claims claims = JJwtTokenUtils.parseClaims(token);
			result = new HashMap<String, Object>(claims);
			result.put("active", !isRevoke);
			result.put("revoke", isRevoke);
		} else {
			log.debug("Token revoke is {}. token[{}]", false, token);
			throw new AuthException("발생된 Token이 없습니다.");
		}
		return CommonUtils.MAPPER.writeValueAsString(result);
	}

}
