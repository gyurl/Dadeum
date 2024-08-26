package com.hkit.stt.member;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface MemberRepository extends JpaRepository<Member, Long>{
	

	
	Optional<Member> findByApiKey(String apiKey);
	
	Optional<Member> findByMemberNum(Long memberNum);
	Member findByName(String name);
	Optional<Member> findById(String id);

	boolean existsById(String id);
	boolean existsByEmail(String email);
	
	//중복확인용
	 @Query(value = "SELECT CASE WHEN COUNT(*) > 0 THEN 1 ELSE 0 END FROM members WHERE id = :id", nativeQuery = true)
	    int countById(@Param("id") String id);
	
	
	
	//admin memberlist
	 @Query(value = "SELECT * FROM ( " +
             "    SELECT m.member_num, m.id, " +
             "           NVL(internal_usage.usage, 0) as internal_usage, " +
             "           NVL(external_usage.usage, 0) as external_usage, " +
             "           ROWNUM AS rn " +
             "    FROM members m " +
             "    LEFT JOIN (SELECT member_num, SUM(file_duration) as usage " +
             "               FROM stt_result " +
             "               WHERE external = 0 " +
             "               GROUP BY member_num) internal_usage ON m.member_num = internal_usage.member_num " +
             "    LEFT JOIN (SELECT member_num, SUM(file_duration) as usage " +
             "               FROM stt_result " +
             "               WHERE external = 1 " +
             "               GROUP BY member_num) external_usage ON m.member_num = external_usage.member_num " +
             "    WHERE ROWNUM <= :end " +
             ") WHERE rn >= :start", 
      nativeQuery = true)
List<Object[]> findMembersWithUsage(@Param("start") int start, @Param("end") int end);

@Query(value = "SELECT COUNT(*) FROM members", nativeQuery = true)
long countMembers();
	
@Query(value = "SELECT * FROM ( " +
        "    SELECT m.member_num, m.id, " +
        "           NVL(internal_usage.usage, 0) as internal_usage, " +
        "           NVL(external_usage.usage, 0) as external_usage, " +
        "           ROWNUM AS rn " +
        "    FROM members m " +
        "    LEFT JOIN (SELECT member_num, SUM(file_duration) as usage " +
        "               FROM stt_result " +
        "               WHERE external = 0 " +
        "               GROUP BY member_num) internal_usage ON m.member_num = internal_usage.member_num " +
        "    LEFT JOIN (SELECT member_num, SUM(file_duration) as usage " +
        "               FROM stt_result " +
        "               WHERE external = 1 " +
        "               GROUP BY member_num) external_usage ON m.member_num = external_usage.member_num " +
        "    WHERE LOWER(m.id) LIKE LOWER('%' || :searchId || '%') " +
        "    AND ROWNUM <= :end " +
        ") WHERE rn >= :start", 
 nativeQuery = true)
List<Object[]> findMembersWithUsageByIdContaining(@Param("searchId") String searchId, 
                                           @Param("start") int start, 
                                           @Param("end") int end);

@Query(value = "SELECT COUNT(*) FROM members WHERE LOWER(id) LIKE LOWER('%' || :searchId || '%')", 
nativeQuery = true)
long countMembersByIdContaining(@Param("searchId") String searchId);
}

	
	

