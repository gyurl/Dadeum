package com.hkit.stt.member;

import java.security.Principal;
import java.time.LocalDateTime;
import java.time.YearMonth;
import java.util.Enumeration;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.SecurityContextLogoutHandler;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.BindingResult;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.servlet.mvc.support.RedirectAttributes;

import com.hkit.stt.jwt.JwtResponse;
import com.hkit.stt.jwt.JwtTokenProvider;
import com.hkit.stt.jwt.LoginRequest;
import com.hkit.stt.trans.TutorialService;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequestMapping("/members")
@RequiredArgsConstructor
@Slf4j
public class MemberController {

	private final MemberService ms;
    private final AuthenticationManager authenticationManager;
    private final JwtTokenProvider jwtTokenProvider;
	private final TutorialService tutorialService;
	
	private static final Logger logger = LoggerFactory.getLogger(MemberController.class);
	
	@PostMapping("/checkId")
	@ResponseBody
	public String checkId(@RequestParam String id) {
		logger.debug("Received request to check ID: {}", id);
        boolean isAvailable = ms.isIdAvailable(id);
        logger.debug("ID {} is available: {}", id, isAvailable);
        return isAvailable ? "available" : "duplicate";
		}

	@GetMapping("/modify")
	public String ViewModifyForm(Model model, Principal pc) {
		String memberId = pc.getName();
		Member member = ms.getMember(ms.getMemberNum(memberId));
		model.addAttribute("memberForm", member);
		return "modify_form";
	}

	@PostMapping("/modify")
	public String ProModifyForm(@ModelAttribute("memberForm") Member memberForm, @RequestParam("id") String id,
			@RequestParam("password") String password, @RequestParam("name") String name,
			@RequestParam("email") String email, @RequestParam("phoneNumber") String phoneNumber) {
		ms.modify(memberForm, id, password, name, email, phoneNumber);
		return "redirect:/members/mypage";
	}
	
	//마이페이지 그래프
	@PreAuthorize("isAuthenticated()")
	@GetMapping("/mypage")
	public String mypage(
	        Model model,
	        Principal principal,
	        @RequestParam(name = "startDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
	        @RequestParam(name = "endDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {
	    
	    if (startDate == null) {
	        startDate = LocalDateTime.of(1999, 1, 1, 0, 0, 0);
	    }
	    if (endDate == null) {
	        endDate = LocalDateTime.now();
	    }
	    
	    String memberId = principal.getName();
	    Member member = ms.getMember(ms.getMemberNum(memberId));
	    
	    // 회원 정보 설정
	    model.addAttribute("MemberId", member.getId());
	    model.addAttribute("MemberName", member.getName());
	    model.addAttribute("MemberEmail", member.getEmail());
	    model.addAttribute("MemberPhone", member.getPhoneNumber());
	    model.addAttribute("apiKey", member.getApiKey());
	    
	    // 월별 사용량 데이터 가져오기
	    Map<YearMonth, Map<String, Double>> monthlyUsage = tutorialService.getMonthlyUsageForMember(member.getMemberNum(), startDate, endDate);
	    model.addAttribute("monthlyUsage", monthlyUsage);
	    
	    // Open API 총 사용 시간 계산
	    double totalOpenApiUsage = monthlyUsage.values().stream()
	            .mapToDouble(m -> m.getOrDefault("Open API 사용", 0.0))
	            .sum();
	    
	    // 시간으로 변환하고 소수점 둘째 자리까지 반올림
	    String formattedTotalOpenApiUsage = String.format("%.2f", totalOpenApiUsage / 60);
	    model.addAttribute("totalOpenApiUsage", formattedTotalOpenApiUsage);
	    return "mypage";
	}


    // 웹 브라우저에서의 로그인 페이지 요청 처리
    @GetMapping("/login")
    public String loginPage() {
        return "login_form";
    }

    
    
    @PostMapping("/login-api")
    @ResponseBody
    public ResponseEntity<?> loginApi(@RequestBody LoginRequest loginRequest, HttpServletRequest request, HttpServletResponse response) {
        System.out.println("login-api");
        try {
            log.info("Attempting login for user: {}", loginRequest.getId());

            // 요청 헤더 로깅
            logRequestHeaders(request);

            Authentication authentication = authenticationManager.authenticate(
                new UsernamePasswordAuthenticationToken(loginRequest.getId(), loginRequest.getPassword())
            );

            String jwt = jwtTokenProvider.createToken(authentication);
            log.info("Login successful for user: {}", loginRequest.getId());
            System.out.println(jwt);
            // 쿠키 설정
            Cookie cookie = new Cookie("accessToken", jwt);
            cookie.setHttpOnly(true); // JavaScript로 접근 불가하게 설정
            // 개발환경에서만 FALSE 실제로는 TRUE 사용해야함
            cookie.setSecure(false); // HTTPS에서만 쿠키 전송 (프로덕션 환경에서 추천)
            cookie.setPath("/"); // 쿠키의 유효 경로 설정
            cookie.setMaxAge(60 * 10); // 쿠키의 유효 기간을 10분으로 설정
            //cookie.setMaxAge(60 * 60 * 24); // 쿠키의 유효 기간을 1일로 설정
            response.addCookie(cookie);
            
            

            return ResponseEntity.ok(new JwtResponse(jwt));
        } catch (AuthenticationException e) {
            log.error("Login failed for user: {}", loginRequest.getId(), e);
            return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid ID or password");
        } catch (Exception e) {
            log.error("Unexpected error during login", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred");
        }
    }
	
    private void logRequestHeaders(HttpServletRequest request) {
        log.info("Request Headers:");
        Enumeration<String> headerNames = request.getHeaderNames();
        while (headerNames.hasMoreElements()) {
            String headerName = headerNames.nextElement();
            String headerValue = request.getHeader(headerName);
            log.info("{}: {}", headerName, headerValue);
        }
    }
   
    // 인증된 accessToken인지 확인
    @PostMapping("/check-access-token")
    public ResponseEntity<String> checkAccessToken(HttpServletRequest request) {
        System.out.println("/check-access-token");
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("accessToken".equals(cookie.getName())) {
                    String accessToken = cookie.getValue();
                    if (jwtTokenProvider.validateToken(accessToken)) {
                        // 토큰이 유효한 경우, 토큰에서 사용자 ID를 추출하여 비교
                        String userIdFromToken = jwtTokenProvider.getUsernameFromToken(accessToken); // getUserIdFromToken 메소드가 필요함
                        System.out.println("fromToken : "+userIdFromToken);
                        // 사용자 정보에서 현재 로그인된 사용자의 ID를 가져오는 메소드 (예시)
                        
                        if (ms.doesUserExist(userIdFromToken)) {
                            return ResponseEntity.ok("Token is valid and user ID matches");
                        } else {
                            return ResponseEntity.status(403).body("Token is valid but user ID does not match");
                        }
                    } else {
                        return ResponseEntity.status(401).body("Token is invalid or expired");
                    }
                }
            }
        }
        return ResponseEntity.status(400).body("No accessToken found in cookies");
    }
    public boolean isAccessTokenValid(HttpServletRequest request) {
        System.out.println("/check-access-token");
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if ("accessToken".equals(cookie.getName())) {
                    String accessToken = cookie.getValue();
                    if (jwtTokenProvider.validateToken(accessToken)) {
                        // 토큰이 유효한 경우, 토큰에서 사용자 ID를 추출하여 비교
                        String userIdFromToken = jwtTokenProvider.getUsernameFromToken(accessToken); // getUserIdFromToken 메소드가 필요함
                        System.out.println("fromToken : " + userIdFromToken);
                        // 사용자 정보에서 현재 로그인된 사용자의 ID를 가져오는 메소드 (예시)

                        if (ms.doesUserExist(userIdFromToken)) {
                            return true; // Token is valid and user exists
                        } else {
                            return false; // Token is valid but user does not exist
                        }
                    } else {
                        return false; // Token is invalid or expired
                    }
                }
            }
        }
        return false; // No accessToken found in cookies
    }
    
    
    // 로그아웃 처리
    @GetMapping("/logout")
    public String logout(HttpServletRequest request, HttpServletResponse response) {
    	System.out.println("logout");
        // Invalidate session and clear security context
        new SecurityContextLogoutHandler().logout(request, response, SecurityContextHolder.getContext().getAuthentication());

        Cookie cookie = new Cookie("accessToken", null);
        cookie.setPath("/");
        cookie.setMaxAge(0);
        cookie.setHttpOnly(true); // 쿠키가 HttpOnly로 설정되어 있다면 일치시켜야 합니다.
        cookie.setSecure(true); // 쿠키가 Secure로 설정되어 있다면 일치시켜야 합니다.
        response.addCookie(cookie);


        return "redirect:/";
    }

    @GetMapping("/guide")
	public String page() {
		return "guide";
	}
    
	@GetMapping("/signup")
	public String create(MemberForm memberForm) {
		return "sign_form";
	}

	@PostMapping("/signup")
	public String create(@Valid MemberForm mf, BindingResult br, Model model) {

		if (br.hasErrors()) {
			return "sign_form";
		}

		if (!mf.getPassword().equals(mf.getPassword2())) {
			br.rejectValue("password2", "passwordInCorrect", "비밀번호가 일치하지 않습니다.");
			return "sign_form";
		}

		try {
			ms.create(mf.getId(), mf.getPassword(), mf.getName(), mf.getEmail(), mf.getPhoneNumber());

		} catch (RuntimeException e) {
			model.addAttribute("errorMessage", e.getMessage());
			return "sign_form";
		}

		return "redirect:/";
	}

	// api키발급
	@PostMapping("/generate-api-key")
	public String generateApiKey(Principal principal, Model model, RedirectAttributes redirectAttributes) {
		String id = principal.getName();
		log.info(id);

		
		 String apiKey = ms.generateApiKey(id);
		 redirectAttributes.addFlashAttribute("apiKey", apiKey);
		
		return "redirect:/members/mypage";
	}

	@GetMapping("/api-key")
	@ResponseBody
	public String getApiKey(Principal principal) {
		if (principal != null) {
			String id = principal.getName();
			String apiKey = ms.getApiKey(id);
			if (apiKey != null) {
				return apiKey;
			} else {
				return "API 키가 아직 생성되지 않았습니다.";
			}
		}
		return "로그인이 필요합니다.";
	}
	
    @GetMapping
    public String getAllMembers(Model model) {
        List<Member> members = ms.getAllMembers();
        model.addAttribute("members", members);
        return "members";
    }
	
	@PostMapping
	public Member addMember(@RequestBody Member member) {
		return ms.addMember(member);
	}
}
