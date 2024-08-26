package com.hkit.stt.member;

import java.util.Arrays;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.dao.DaoAuthenticationProvider;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;

import com.hkit.stt.jwt.JwtAuthenticationFilter;
import com.hkit.stt.jwt.JwtTokenProvider;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity(prePostEnabled = true)
public class SecurityConfig {

	   private final MemberSecurityService memberSecurityService;
	   private final JwtTokenProvider jwtTokenProvider;

	    public SecurityConfig(MemberSecurityService memberSecurityService, JwtTokenProvider jwtTokenProvider) {
	        this.memberSecurityService = memberSecurityService;
	        this.jwtTokenProvider = jwtTokenProvider;
	    }


	    @Bean
	    public CorsConfigurationSource corsConfigurationSource() {
	        CorsConfiguration configuration = new CorsConfiguration();
	        configuration.setAllowedOrigins(Arrays.asList("http://localhost:8282", "http://192.168.0.176:8282"));
	        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS"));
	        configuration.setAllowedHeaders(Arrays.asList("*"));
	        configuration.setAllowCredentials(true);

	        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
	        source.registerCorsConfiguration("/**", configuration);
	        return source;
	    }	    
	    


	    @Bean
	    SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
	        http
	            .authorizeHttpRequests((authorizeHttpRequests) -> authorizeHttpRequests
	                .requestMatchers(new AntPathRequestMatcher("/css/**")).permitAll()
	                .requestMatchers(new AntPathRequestMatcher("/js/**")).permitAll()
	                .requestMatchers(new AntPathRequestMatcher("/img/**")).permitAll()
            		.requestMatchers(new AntPathRequestMatcher("/members/login-api")).permitAll()
            		.requestMatchers(new AntPathRequestMatcher("/members/check-access-token")).permitAll()
	            	.requestMatchers(new AntPathRequestMatcher("/members/checkId")).permitAll()
	                .requestMatchers(new AntPathRequestMatcher("/admins/**")).hasRole("ADMIN")
	                .requestMatchers(new AntPathRequestMatcher("/members/signup")).permitAll()
	                .requestMatchers(new AntPathRequestMatcher("/members/login")).permitAll()
	                .requestMatchers(new AntPathRequestMatcher("/members/generate-api-key")).authenticated()
	                .requestMatchers(new AntPathRequestMatcher("/api/**")).permitAll()
	                .requestMatchers(new AntPathRequestMatcher("/dadeum/**")).permitAll()
	                .requestMatchers(new AntPathRequestMatcher("/*.css")).permitAll()
	                .requestMatchers(new AntPathRequestMatcher("/dadeum/transcribe/file")).authenticated()

	                .anyRequest().authenticated()
	            )
//	            .formLogin((formLogin) -> formLogin
//	                .loginPage("/members/login")
//	                .successHandler((request, response, authentication) -> {
//	                    response.sendRedirect("/");  // 항상 홈으로 리다이렉트
//	                })
//	                .failureUrl("/members/login?error")
//	            )
	            .logout((logout) -> logout
	                .logoutRequestMatcher(new AntPathRequestMatcher("/members/logout"))
	                .logoutSuccessUrl("/")
	                .invalidateHttpSession(true)
	                .deleteCookies("JSESSIONID")
	                .deleteCookies("accessToken")
	                .permitAll()
	            )
	            .csrf(csrf -> csrf.disable())
	            .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider), UsernamePasswordAuthenticationFilter.class)
	            .sessionManagement(management -> management
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));
	            
	            
	        return http.build();
	    }

	    @Bean
	    public AuthenticationManager authenticationManager(AuthenticationConfiguration authenticationConfiguration) throws Exception {
	        return authenticationConfiguration.getAuthenticationManager();
	    }
	    
	    @Bean
	    public DaoAuthenticationProvider authenticationProvider() {
	        DaoAuthenticationProvider authProvider = new DaoAuthenticationProvider();
	        authProvider.setUserDetailsService(memberSecurityService);
	        authProvider.setPasswordEncoder(passwordEncoder());
	        return authProvider;
	    }
	    @Bean
	    public PasswordEncoder passwordEncoder() {
	        return new BCryptPasswordEncoder();
	    }
	}