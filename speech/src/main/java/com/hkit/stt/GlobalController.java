package com.hkit.stt;

import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ModelAttribute;

import com.hkit.stt.member.Member;
import com.hkit.stt.member.MemberService;

import lombok.RequiredArgsConstructor;

@RequiredArgsConstructor
@ControllerAdvice
public class GlobalController {
	private final MemberService ms;

	@ModelAttribute("loginMember")
	public Member userInfo(Authentication authentication) {
		if (authentication != null && authentication.isAuthenticated()) {
			return ms.findByUsername(authentication.getName());
		}
		return null;
	}
}
