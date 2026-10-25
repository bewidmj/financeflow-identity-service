
package com.learning.financeflow.identity.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpStatus;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.HttpStatusEntryPoint;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

@Configuration
public class SecurityConfig {

  private final RestAuthenticationEntryPoint authenticationEntryPoint;

  private final RestAccessDeniedHandler accessDeniedHandler;

  public SecurityConfig(RestAuthenticationEntryPoint authenticationEntryPoint, RestAccessDeniedHandler accessDeniedHandler) {
    this.authenticationEntryPoint = authenticationEntryPoint;
    this.accessDeniedHandler = accessDeniedHandler;
  }

    @Bean
    SecurityFilterChain securityFilterChain(
            HttpSecurity http,
            JwtAuthenticationFilter filter) throws Exception {

        return http
            .csrf(c -> c.disable())
            .httpBasic(c -> c.disable())
            .formLogin(c -> c.disable())
            .sessionManagement(c ->
                c.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                            .exceptionHandling(ex -> ex
                    .authenticationEntryPoint(
                        new HttpStatusEntryPoint(HttpStatus.UNAUTHORIZED)
                    )
                )
            .exceptionHandling(exceptions -> exceptions
              .authenticationEntryPoint(authenticationEntryPoint)
              .accessDeniedHandler(accessDeniedHandler)
                )
            .authorizeHttpRequests(c -> c
                .requestMatchers(
                    "/api/v1/auth/**",
                    "/.well-known/jwks.json",
                    "/actuator/health",
                    "/swagger-ui/**",
                    "/swagger-ui.html",
                    "/v3/api-docs/**",
                    "/v3/api-docs.yaml"
                ).permitAll()
                .anyRequest().authenticated())
            .addFilterBefore(
                filter,
                UsernamePasswordAuthenticationFilter.class)
            .build();
    }

    @Bean
    PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }
}
