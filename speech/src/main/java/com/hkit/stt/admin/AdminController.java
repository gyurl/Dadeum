package com.hkit.stt.admin;

import java.security.Principal;
import java.time.LocalDateTime;
import java.time.YearMonth;
import java.util.List;
import java.util.Map;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;

import com.hkit.stt.member.Member;
import com.hkit.stt.member.MemberService;
import com.hkit.stt.member.MemberUsageDTO;
import com.hkit.stt.trans.TutorialService;

@Controller
@RequestMapping("/admin")
@PreAuthorize("hasRole('ADMIN')")
public class AdminController {


	@Autowired
    private AdminService adminService;
	
	@Autowired
	private MemberService ms;
	
	@Autowired
	private TutorialService  tutorialService;

	

	@GetMapping("/members")
    public String listMembers(@RequestParam(defaultValue = "0") int page, 
                              @RequestParam(required = false) String searchId,
                              Model model) {
        int pageSize = 10;
        Page<MemberUsageDTO> memberPage;
        
        if (searchId != null && !searchId.isEmpty()) {
            memberPage = adminService.searchMemberUsageWithPagination(searchId, page, pageSize);
        } else {
            memberPage = adminService.getMemberUsageWithPagination(page, pageSize);
        }
        
        model.addAttribute("memberPage", memberPage);
        model.addAttribute("searchId", searchId);
        return "admin_list";
    }
	
	/* @PreAuthorize("isAuthenticated()") */
	@GetMapping("/list_detail")
	public String listDetail(
	    Model model,
	    @RequestParam("id") String id,
	    @RequestParam(name = "startDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime startDate,
	    @RequestParam(name = "endDate", required = false) @DateTimeFormat(iso = DateTimeFormat.ISO.DATE_TIME) LocalDateTime endDate) {

	    if (startDate == null) {
	        startDate = LocalDateTime.of(1999, 1, 1, 0, 0, 0);
	    }
	    if (endDate == null) {
	        endDate = LocalDateTime.now();
	    }

	    Member member = ms.getMemberById(id);

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

	    return "admin_list_detail";
	}
}



