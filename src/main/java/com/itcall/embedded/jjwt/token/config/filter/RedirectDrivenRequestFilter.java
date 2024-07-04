package com.itcall.embedded.jjwt.token.config.filter;

import java.io.IOException;

import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * API로 요청들어온 URL패턴 중 OAuth 서버로 요청되는 것을 별도 처리한다.
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
@RequiredArgsConstructor
@Component
public class RedirectDrivenRequestFilter extends OncePerRequestFilter {

	@Override
	protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
		String requestUri = request.getRequestURI();
		if(requestUri.startsWith("/oauth/token") || requestUri.startsWith("/oauth2/token")){
			// token 발급, refresh토큰으로 토큰 신규발급.
			log.debug("goto /oauth/token method");
			filterChain.doFilter(request, response); // Redirect 대상이 아님.
			return;
		} else if(requestUri.startsWith("/oauth/check_token") || requestUri.startsWith("/oauth2/check_token")) {
			// token 체크
			log.debug("goto /oauth/check_token method");
			filterChain.doFilter(request, response); // Redirect 대상이 아님.
			return;
		} else if(requestUri.startsWith("/oauth/revoke") || requestUri.startsWith("/oauth2/revoke")) {
			// token 삭제
			log.debug("goto /oauth/revoke method");
			filterChain.doFilter(request, response); // Redirect 대상이 아님.
			return;
		}
		filterChain.doFilter(request, response); // Redirect 대상이 아님.
	}

}
