package com.itcall.embedded.jjwt.token.config;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.autoconfigure.security.SecurityProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.filter.OncePerRequestFilter;

import com.itcall.embedded.jjwt.token.config.filter.RedirectDrivenRequestFilter;
import com.itcall.embedded.jjwt.token.config.handler.CustomHandlerExceptionResolver;
import com.itcall.embedded.jjwt.token.config.provider.ResourceServerAuthenticationProvider;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Resource서버 설정.
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
@RequiredArgsConstructor
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

	private static final String DEF_PERMIT_MATCHER_URI_PATTERNS = "/static/**,/login,/logout,/img/**,/image/**,/about/**,/css/**,/lib*/**,/js/**,/media/**,/public/**,/sso/**";
	private static final String OAUTH_URI_PATTERNS = "/oauth/*,/oauth2/*";
	private final ResourceServerAuthenticationProvider authenticationProvider;
	private final RedirectDrivenRequestFilter redirectDrivenRequestFilter;
	private final CustomHandlerExceptionResolver handlerExceptionResolver;

	@Value("${spring.security.cors.origins}")
	private List<String> corsAllowedOrigins;

	@Bean
	public FilterRegistrationBean<OncePerRequestFilter> myFilterRegistration() {
		FilterRegistrationBean<OncePerRequestFilter> regBean = new FilterRegistrationBean<>();
		regBean.setFilter(this.redirectDrivenRequestFilter);
		regBean.addUrlPatterns(OAUTH_URI_PATTERNS.split(","));
		regBean.setOrder(SecurityProperties.DEFAULT_FILTER_ORDER - 1); // 최상위 필터:
		// regBean.setOrder(SecurityProperties.BASIC_AUTH_ORDER - 1); // 마지막임 필터:
		log.debug("Redirect to OAuth-Server Url-Patterns: {}", Arrays.asList(OAUTH_URI_PATTERNS.split(",")));
		return regBean;
	}

	@Bean
	public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
		http.csrf(AbstractHttpConfigurer::disable);

		List<String> exposedHeaders = new ArrayList<String>();
		exposedHeaders.add("Content-Disposition");
		http.cors(corsConfigurer -> corsConfigurer.configurationSource(request -> {
			var cors = new CorsConfiguration();
			// cors.setAllowedOriginPatterns(this.corsAllowedOrigins);
			cors.setAllowedOriginPatterns(Arrays.asList("*"));
			cors.setAllowedMethods(List.of("GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"));
			cors.setAllowedHeaders(List.of(CorsConfiguration.ALL));
			cors.setExposedHeaders(exposedHeaders);
			cors.setAllowCredentials(true);
			return cors;
		})).authorizeHttpRequests(authorizeRequests -> authorizeRequests
				.requestMatchers(DEF_PERMIT_MATCHER_URI_PATTERNS.split(",")).permitAll().anyRequest().authenticated())
//			.authenticationManager(authenticationProvider::authenticate)
				.oauth2ResourceServer(oAuth2ResourceServerConfigurer -> oAuth2ResourceServerConfigurer.jwt(
						jwtConfigurer -> jwtConfigurer.authenticationManager(this.authenticationProvider::authenticate))
						.authenticationEntryPoint((request, response, authException) -> this.handlerExceptionResolver
								.resolveException(request, response, oAuth2ResourceServerConfigurer, authException))
						.accessDeniedHandler((request, response, accessDeniedException) -> this.handlerExceptionResolver
								.resolveException(request, response, oAuth2ResourceServerConfigurer,
										accessDeniedException)))
				.exceptionHandling(handler -> handler
						.authenticationEntryPoint((request, response, authException) -> this.handlerExceptionResolver
								.resolveException(request, response, handler, authException)))
				.sessionManagement(sessionManagementCustomizer -> sessionManagementCustomizer
						.sessionCreationPolicy(SessionCreationPolicy.STATELESS));

		return http.build();
	}

}
