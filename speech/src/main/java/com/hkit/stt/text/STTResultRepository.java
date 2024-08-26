package com.hkit.stt.text;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

public interface STTResultRepository extends JpaRepository<STTResult, Long> {
    @Query(value = "SELECT * FROM (SELECT a.*, ROWNUM rnum FROM (SELECT * FROM stt_result WHERE member_num = :memberNum ORDER BY created_at DESC) a WHERE ROWNUM <= :maxRow) WHERE rnum > :minRow",
            nativeQuery = true)
     List<STTResult> findByMemberMemberNumWithPagination(@Param("memberNum") Long memberNum, 
                                                         @Param("minRow") int minRow, 
                                                         @Param("maxRow") int maxRow);

     @Query(value = "SELECT COUNT(*) FROM stt_result WHERE member_num = :memberNum", 
            nativeQuery = true)
     long countByMemberMemberNum(@Param("memberNum") Long memberNum);
	Optional<STTResult> findByMemberMemberNumAndId(Long memberNum, Long id);
	
	//마이페이지 그래프 쿼리
	@Query(value = "SELECT TRUNC(s.created_at, 'MM') as month, SUM(s.file_duration), s.external " +
		       "FROM STT_RESULT s " +
		       "WHERE s.member_num = :memberNum AND s.created_at >= :startDate AND s.created_at < :endDate " +
		       "GROUP BY TRUNC(s.created_at, 'MM'), s.external", 
		       nativeQuery = true)
		List<Object[]> getMonthlySumDurationForMemberWithExternal(@Param("memberNum") Long memberNum, 
		                                                          @Param("startDate") LocalDateTime startDate, 
		                                                          @Param("endDate") LocalDateTime endDate);
		//admin memberlist
		@Query("SELECT SUM(s.fileDurationSeconds) FROM STTResult s WHERE s.member.memberNum = :memberNum AND s.external = :external")
		double sumFileDurationByMemberAndExternal(@Param("memberNum") Long memberNum, @Param("external") boolean external);

}
