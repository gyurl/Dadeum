package com.hkit.stt.admin;

import java.math.BigDecimal;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.stereotype.Service;

import com.hkit.stt.member.Member;
import com.hkit.stt.member.MemberRepository;
import com.hkit.stt.member.MemberUsageDTO;
import com.hkit.stt.text.STTResultRepository;

@Service
public class AdminService {
	@Autowired
    private MemberRepository memberRepository;
	
    @Autowired
    private STTResultRepository sttResultRepository;

	public List<Member> getAllMembers(){
		return memberRepository.findAll();
	}
	
	 public Page<MemberUsageDTO> getMemberUsageWithPagination(int page, int size) {
	        int start = page * size + 1;
	        int end = (page + 1) * size;
	        
	        List<Object[]> results = memberRepository.findMembersWithUsage(start, end);
	        List<MemberUsageDTO> memberUsageDTOs = results.stream()
	            .map(this::convertToMemberUsageDTO)
	            .collect(Collectors.toList());
	        
	        long total = memberRepository.countMembers();

	        return new PageImpl<>(memberUsageDTOs, PageRequest.of(page, size), total);
	    }

	    private MemberUsageDTO convertToMemberUsageDTO(Object[] result) {
	        return new MemberUsageDTO(
	            ((Number) result[0]).longValue(),  // member_num
	            (String) result[1],  // id
	            ((Number) result[2]).doubleValue(),  // internal_usage
	            ((Number) result[3]).doubleValue()   // external_usage
	        );
	    }
	    
	    public Page<MemberUsageDTO> searchMemberUsageWithPagination(String searchId, int page, int size) {
	        int start = page * size + 1;
	        int end = (page + 1) * size;
	        
	        List<Object[]> results = memberRepository.findMembersWithUsageByIdContaining(searchId, start, end);
	        List<MemberUsageDTO> memberUsageDTOs = results.stream()
	            .map(this::convertToMemberUsageDTO)
	            .collect(Collectors.toList());
	        
	        long total = memberRepository.countMembersByIdContaining(searchId);

	        return new PageImpl<>(memberUsageDTOs, PageRequest.of(page, size), total);
	    }
	}
