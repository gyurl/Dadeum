package com.hkit.stt;

import java.security.Principal;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import com.hkit.stt.jwt.JwtTokenProvider;
import com.hkit.stt.member.Member;
import com.hkit.stt.member.MemberService;

import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;


@RequiredArgsConstructor
@Controller
public class MainController {
	private final MemberService ms;


	 @GetMapping("/")
	    public String root(HttpServletRequest request, Model model, Principal pc) {    

	        if (pc != null) {
	            String username = pc.getName();
	            Member member = ms.getMember(username);
	            model.addAttribute("member", member);
	        } else {
	            model.addAttribute("member", null);
	        }
	        
	        return "main";
	    }



}