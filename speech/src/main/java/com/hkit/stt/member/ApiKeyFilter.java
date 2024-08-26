package com.hkit.stt.member;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.filter.OncePerRequestFilter;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.io.IOException;

public class ApiKeyFilter extends OncePerRequestFilter {

	private final MemberRepository memberRepository;

    public ApiKeyFilter(MemberRepository memberRepository) {
        this.memberRepository = memberRepository;
    }

	    @Override
	    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
	            throws ServletException, IOException {
	        String path = request.getRequestURI();
	        
	        // /vito/trans 경로에 대해서는 API 키 검증을 건너뜁니다.
	        if (path.equals("/vito/trans")) {
	            filterChain.doFilter(request, response);
	            return;
	        }

	        String apiKey = request.getHeader("X-API-KEY");
	        if (path.startsWith("/vito/") && !validateApiKey(apiKey)) {
	            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
	            return;
	        }
	        filterChain.doFilter(request, response);
	    }
	    
	    private boolean validateApiKey(String apiKey) {
	        if (apiKey == null || apiKey.isEmpty()) {
	            return false;
	        }
	        return memberRepository.findByApiKey(apiKey).isPresent();
	    }
	}