package com.hkit.stt.member;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Lazy;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.userdetails.User;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;


@Service
public class MemberSecurityService implements UserDetailsService {
	 private final MemberRepository memberRepository;

	    public MemberSecurityService(MemberRepository memberRepository) {
	        this.memberRepository = memberRepository;
	    }

	    @Override
	    public UserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
	        if ("admin".equals(username)) {
	            return User.withUsername("admin")
	                       .password("$2a$10$bH.O/chGpeze0enKJUTXl.hDmAkDbVBzqqY79vq88jYTCujtwnEaG") // BCrypt로 인코딩된 비밀번호
	                       .roles("ADMIN")
	                       .build();
	        }

	        Member member = memberRepository.findById(username)
	            .orElseThrow(() -> new UsernameNotFoundException("User not found with username: " + username));

	        List<GrantedAuthority> authorities = new ArrayList<>();
	        authorities.add(new SimpleGrantedAuthority(MemberRole.USER.getValue()));

	        return new User(member.getId(), member.getPassword(), authorities);
	    }
	}