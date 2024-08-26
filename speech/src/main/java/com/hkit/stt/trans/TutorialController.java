package com.hkit.stt.trans;

import java.io.IOException;
import java.time.LocalDateTime;
import java.time.YearMonth;
import java.util.Map;

import javax.sound.sampled.UnsupportedAudioFileException;


import org.json.JSONObject;
import org.springframework.data.domain.Page;
import org.springframework.format.annotation.DateTimeFormat;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestHeader;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RequestPart;
import org.springframework.web.multipart.MultipartFile;

import com.hkit.stt.member.Member;
import com.hkit.stt.member.MemberService;
import com.hkit.stt.text.STTResult;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Controller
@RequestMapping("/dadeum")
@RequiredArgsConstructor
@Slf4j
public class TutorialController {

    private final TutorialService tutorialService;
    private final MemberService memberService;

    @GetMapping("/api-key-validation")
    public ResponseEntity<Boolean> validateApiKey(@RequestParam("apiKey") String apiKey) {
        boolean isValid = memberService.hasValidApiKey(apiKey);
        return ResponseEntity.ok(isValid);
    }
    
    @GetMapping("/UseSTT")
    public String UseSTT(@AuthenticationPrincipal UserDetails userDetails,
            @RequestParam(defaultValue = "0") int page,
            @RequestParam(defaultValue = "3") int size,
            Model model,
            HttpSession session) {
    	// index 메서드의 기능

    	Member member = memberService.findByUsername(userDetails.getUsername());

    	model.addAttribute("member", member);
    	return "usestt";
    }


    @PostMapping(value = "/transcribe/file", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<?> transcribeFile(@RequestParam("file") MultipartFile file,
                                            Authentication authentication) {
        try {
            // 파일 유효성 검사
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("Please select a file to upload");
            }

            // 인증된 사용자 정보 가져오기
            UserDetails userDetails = (UserDetails) authentication.getPrincipal();
            Member member = memberService.findByUsername(userDetails.getUsername());
            Long memberNum = member.getMemberNum();

            // Transcribe 실행
            STTResult result = tutorialService.transcribeFile(file, memberNum);

            if (result.getResultText() == null || result.getResultText().isEmpty()) {
                return ResponseEntity.status(HttpStatus.NO_CONTENT).body("No transcription result");
            }

            return ResponseEntity.ok(result);
        } catch (IOException e) {
            log.error("File processing error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("File processing error: " + e.getMessage());
        } catch (InterruptedException e) {
            log.error("Transcription process interrupted", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Transcription process interrupted");
        } catch (Exception e) {
            log.error("Unexpected error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred: " + e.getMessage());
        }
    }
    
    
    @PostMapping(value = "/openapi/file", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
	 public ResponseEntity<?> transcribeFile1(@RequestParam("file") MultipartFile file,
	                                          @RequestHeader(value = "X-API-KEY", required = false) String apiKey) {
	     try {
	         if (apiKey == null || apiKey.isEmpty()) {
	             return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("API key is required");
	         }

	         if (!memberService.hasValidApiKey(apiKey)) {
	             return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid API key");
	         }

	         Member member = memberService.findByApiKey(apiKey);
	         if (member == null) {
	             return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Member not found for this API key");
	         }

	         STTResult result = tutorialService.transcribeFile(file, member.getMemberNum());

	         if (result == null || result.getResultText() == null || result.getResultText().isEmpty()) {
	             return ResponseEntity.ok().contentType(MediaType.APPLICATION_JSON)
	                     .body("{\"message\":\"Transcription completed, but no text was generated.\"}");
	         }
	         
	         tutorialService.checkExternal(member, result);

	         // JSON 객체 생성
	         JSONObject jsonResponse = new JSONObject();
	         jsonResponse.put("transcription", result.getResultText());
	         jsonResponse.put("fileName", result.getFileName());
	         jsonResponse.put("duration", result.getFileDurationSeconds());
	         jsonResponse.put("fileSize", result.getFileSizeBytes());
	         jsonResponse.put("processingTime", result.getTotalProcessingTimeSeconds());

	         return ResponseEntity.ok()
	                 .contentType(MediaType.APPLICATION_JSON)
	                 .body(jsonResponse.toString());

	     } catch (IOException e) {
	         log.error("File processing error", e);
	         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                 .body("{\"error\":\"File processing error: " + e.getMessage() + "\"}");
	     } catch (InterruptedException e) {
	         log.error("Transcription process interrupted", e);
	         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                 .body("{\"error\":\"Transcription process interrupted\"}");
	     } catch (Exception e) {
	         log.error("Unexpected error", e);
	         return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
	                 .body("{\"error\":\"An unexpected error occurred: " + e.getMessage() + "\"}");
	     }
	 }


    @PostMapping(value = "/transcribe/websocket/file", consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public ResponseEntity<?> transcribeWebsocketFile(@RequestPart MultipartFile file,
                                                     @RequestHeader(value = "X-API-KEY", required = false) String apiKey) throws UnsupportedAudioFileException {
        try {
            // API 키 검증
            if (apiKey != null && !apiKey.isEmpty() && !memberService.hasValidApiKey(apiKey)) {
                return ResponseEntity.status(HttpStatus.UNAUTHORIZED).body("Invalid API key");
            }

            // 파일 유효성 검사
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("Please select a file to upload");
            }

            // WebSocket Transcribe 실행
            tutorialService.transcribeWebSocketFile(file);
            return ResponseEntity.ok().body("WebSocket transcription initiated");
        } catch (IOException e) {
            log.error("File processing error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("File processing error: " + e.getMessage());
        } catch (InterruptedException e) {
            log.error("Transcription process interrupted", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Transcription process interrupted");
        } catch (Exception e) {
            log.error("Unexpected error", e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("An unexpected error occurred: " + e.getMessage());
        }
    }
    
    @GetMapping("/results")
    public String getSTTResults(@AuthenticationPrincipal UserDetails userDetails,
                                @RequestParam(defaultValue = "0") int page,
                                @RequestParam(defaultValue = "3") int size,
                                Model model,
                                HttpSession session) {
        // index 메서드의 기능
        String apiKey = (String) session.getAttribute("apiKey");
        Member member = memberService.findByUsername(userDetails.getUsername());
        model.addAttribute("apiKey", apiKey);
        model.addAttribute("member", member);

        // getSTTResults 메서드의 기능
        Page<STTResult> resultPage = tutorialService.getSTTResultsByMemberNum(member.getMemberNum(), page, size);
        
        model.addAttribute("results", resultPage.getContent());
        model.addAttribute("currentPage", resultPage.getNumber());
        model.addAttribute("totalPages", Math.max(resultPage.getTotalPages(), 1));
        model.addAttribute("totalItems", resultPage.getTotalElements());
        model.addAttribute("size", size);
        
        return "resultlist";  // resultlist 뷰를 반환
    }
    
    @GetMapping("/results/detail/{id}")
    public String getSTTResultDetail(@AuthenticationPrincipal UserDetails userDetails, @PathVariable("id") Long id, Model model) {
        Member member = memberService.findByUsername(userDetails.getUsername());
        STTResult result = tutorialService.getSTTResultByMemberNumAndId(member.getMemberNum(), id);
        model.addAttribute("result", result);
        return "resultdetail";
    }
}