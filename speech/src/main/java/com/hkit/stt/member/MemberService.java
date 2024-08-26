package com.hkit.stt.member;

import java.time.YearMonth;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

import lombok.RequiredArgsConstructor;
import lombok.extern.log4j.Log4j2;

@Log4j2
@Service
@RequiredArgsConstructor
public class MemberService {

	 private final MemberRepository mr;
	 private final PasswordEncoder pw;
	 private static final Logger logger = LoggerFactory.getLogger(MemberService.class);
	 

	    public void modify(Member m, String id, String password, String name, String email, String phoneNumber) {
			m.setId(id);
			m.setPassword(pw.encode(password));
			m.setName(name);
			m.setEmail(email);
			m.setPhoneNumber(phoneNumber);
			mr.save(m);
		}
		public Long getMemberNum(String id) {
			Optional<Member> member = this.mr.findById(id);
			return member.get().getMemberNum();
		}
		
		public Member getMemberById(String id) {
			Optional<Member> member = this.mr.findById(id);
			return member.get();
		}
		
		public Member getMember(Long memberNum) {
			Optional<Member> m = mr.findByMemberNum(memberNum);
			return m.get();
		}
		
		
		public Member getMember(String name) {
			Member m = mr.findByName(name);
			return m;
		}
		
		public boolean isIdAvailable(String id) {
		
			    return mr.countById(id) == 0;
			}
	    
		
		
	
		public Member create(String id, String password, String name, String email, String phoneNumber) {

		Member m = new Member();
		m.setId(id);
		m.setPassword(pw.encode(password));
		m.setName(name);
		m.setEmail(email);
		m.setPhoneNumber(phoneNumber);
		m.setRole(MemberRole.USER);
		this.mr.save(m);
		return m;
	}
	
	public List<Member> getAllMembers() {
		return mr.findAll();
	}
	
	public Member addMember(Member member) {
		return mr.save(member);
	}
	
	public Member findByUsername(String username) {
        Optional<Member> member = this.mr.findById(username);
        if (member.isPresent()) {
            return member.get();
        } else {
            throw new RuntimeException("User not found with username: " + username);
        }
    }
	

    public String generateApiKey(String id) {
    	
        	Optional<Member> member = mr.findById(id);
        	
            String apiKey = UUID.randomUUID().toString();
            member.get().setApiKey(apiKey);
            mr.save(member.get());
            return apiKey;
        
        
    }

	 public boolean validateApiKey(String apiKey) {
	        if (apiKey == null || apiKey.isEmpty()) {
	            return false;
	        }
	        return mr.findByApiKey(apiKey).isPresent();
	    }
	
	public boolean hasValidApiKey(String apiKey) {
        return mr.findByApiKey(apiKey).isPresent();
    }
	
	public String getApiKey(String id) {
        Member member = getMember(id);
        if (member != null) {
            return member.getApiKey();
        }
        return null;
    }
	
	public boolean hasApiKey(String id) {
        Member member = getMember(id);
        return member != null && member.getApiKey() != null && !member.getApiKey().isEmpty();
    }
	
	public Member findByApiKey(String apiKey) {
		Optional<Member> member = this.mr.findByApiKey(apiKey);
		if (member.isPresent()) {
            return member.get();
        } else {
            throw new RuntimeException("User not found with apiKey: " + apiKey);
        }
		
	}
	
	public Boolean doesUserExist(String id) {
	    // MemberService를 사용하여 사용자 정보 확인
	    System.out.println("doesUserExist input:"+ id);
	    Optional<Member> member = mr.findById(id);
	    
	    // Optional 객체에서 값이 존재하는지 확인하여 Boolean 값을 반환
	    System.out.println(member.isPresent());
	    return member.isPresent();
	}
	
	
	
	
}
