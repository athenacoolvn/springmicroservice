package com.gateway;



import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.client.oidc.web.server.logout.OidcClientInitiatedServerLogoutSuccessHandler;
import org.springframework.security.oauth2.client.registration.ReactiveClientRegistrationRepository;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.WebFilterExchange;
import org.springframework.security.web.server.authentication.logout.ServerLogoutHandler;
import org.springframework.security.web.server.header.XFrameOptionsServerHttpHeadersWriter.Mode;

import reactor.core.publisher.Mono;

@Configuration
public class SecurityConfig  {

	@Bean
	public SecurityWebFilterChain springSecurityFilterChain(ServerHttpSecurity http,
			ReactiveClientRegistrationRepository clientRegistrationRepository) {
		// Authenticate through configured OpenID Provider
		http.oauth2Login();
		// Also logout at the OpenID Connect provider
		OidcClientInitiatedServerLogoutSuccessHandler logoutSuccess = new OidcClientInitiatedServerLogoutSuccessHandler(clientRegistrationRepository);
		logoutSuccess.setPostLogoutRedirectUri("{baseUrl}/login");
		
		http.logout(logout -> logout.logoutSuccessHandler(logoutSuccess));
		// Require authentication for all requests
		http.authorizeExchange().anyExchange().authenticated();
		// Allow showing /home within a frame
		http.headers().frameOptions().mode(Mode.SAMEORIGIN);
		// Disable CSRF in the gateway to prevent conflicts with proxied service CSRF
		http.csrf().disable();
		return http.build();
	}

}
