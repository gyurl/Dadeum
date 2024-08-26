package com.hkit.stt.trans;


import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.sql.Timestamp;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.YearMonth;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.CountDownLatch;
import java.util.logging.Level;
import java.util.logging.Logger;

import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.FileSystemResource;
import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageImpl;
import org.springframework.data.domain.PageRequest;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.client.MultipartBodyBuilder;
import org.springframework.stereotype.Service;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.multipart.MultipartFile;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.reactive.function.client.WebClientResponseException;

import com.hkit.stt.member.Member;
import com.hkit.stt.member.MemberRepository;

import com.hkit.stt.text.STTResult;
import com.hkit.stt.text.STTResultRepository;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.WebSocket;
import okhttp3.WebSocketListener;
import okio.ByteString;
import ws.schild.jave.EncoderException;
import ws.schild.jave.MultimediaObject;


@Service
@Slf4j
@RequiredArgsConstructor
public class TutorialService {

    private final STTResultRepository sttResultRepository;
    private final MemberRepository memberRepository;

    private boolean stopPolling = false;
    private String transcribeId = null;
    private String accessToken = null;
    
    private String getFileExtension(String filename) {
        return filename.substring(filename.lastIndexOf(".") + 1);
    }

    @Value("${vito.client_id}")
    String client_id;

    @Value("${vito.client_secret}")
    String client_secret;

    public String getAccessToken() {
        WebClient webClient = WebClient.builder()
                .baseUrl("https://openapi.vito.ai")
                .build();

        MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
        formData.add("client_id", client_id);
        formData.add("client_secret", client_secret);

        String response = webClient
                .post()
                .uri("/v1/authenticate")
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .body(BodyInserters.fromFormData(formData))
                .retrieve()
                .bodyToMono(String.class)
                .block();

        log.info(response);
        JSONObject jsonObject = new JSONObject(response);
        return jsonObject.getString("access_token");
    }

    public STTResult transcribeFile(MultipartFile multipartFile, Long memberNum) throws IOException, InterruptedException {
        File tempFile = null;
        try {
            tempFile = File.createTempFile("audio_", "." + getFileExtension(multipartFile.getOriginalFilename()));
            multipartFile.transferTo(tempFile);

            accessToken = getAccessToken();
            WebClient webClient = WebClient.builder()
                    .baseUrl("https://openapi.vito.ai/v1")
                    .defaultHeader(HttpHeaders.CONTENT_TYPE, MediaType.MULTIPART_FORM_DATA_VALUE)
                    .defaultHeader(HttpHeaders.AUTHORIZATION, "bearer " + accessToken)
                    .build();

            MultipartBodyBuilder multipartBodyBuilder = new MultipartBodyBuilder();
            multipartBodyBuilder.part("file", new FileSystemResource(tempFile));
            multipartBodyBuilder.part("config", "{}");

            String response = null;
            try {
                response = webClient.post()
                        .uri("/transcribe")
                        .body(BodyInserters.fromMultipartData(multipartBodyBuilder.build()))
                        .retrieve()
                        .bodyToMono(String.class)
                        .block();
                log.info("Transcription request completed");
            } catch (WebClientResponseException e) {
                log.error("Error during transcription request: ", e);
                throw new RuntimeException("Transcription request failed", e);
            }

        JSONObject jsonObject = new JSONObject(response);

        if (jsonObject.has("code") && jsonObject.getString("code").equals("H0002")) {
            log.info("Access token expired. Refreshing token.");
            accessToken = getAccessToken();
            response = webClient.post()
                    .uri("/transcribe")
                    .body(BodyInserters.fromMultipartData(multipartBodyBuilder.build()))
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();
        }

        String transcribeId = jsonObject.getString("id");
        log.info("Transcribe request ID: {}", transcribeId);

        long startTime = System.currentTimeMillis();
        String transcribedText = pollForResult(transcribeId);
        long endTime = System.currentTimeMillis();

        String fileName = multipartFile.getOriginalFilename();
        long fileSizeBytes = multipartFile.getSize();
        String fileExtension = fileName.substring(fileName.lastIndexOf('.') + 1);
        double totalProcessingTimeSeconds = (endTime - startTime) / 1000.0;

        double fileDurationSeconds = getFileDuration(tempFile);

        Member member = memberRepository.findByMemberNum(memberNum)
                .orElseThrow(() -> new RuntimeException("Member not found"));

        STTResult result = STTResult.builder()
                .fileName(fileName)
                .fileDurationSeconds(fileDurationSeconds)
                .fileSizeBytes(fileSizeBytes)
                .fileExtension(fileExtension)
                .executionTimeSeconds(totalProcessingTimeSeconds)
                .totalProcessingTimeSeconds(totalProcessingTimeSeconds)
                .resultText(transcribedText)
                .createdAt(LocalDateTime.now())
                .member(member)
                .build();

        return sttResultRepository.save(result);
        } finally {
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }
    

    public Page<STTResult> getSTTResultsByMemberNum(Long memberNum, int page, int size) {
        int minRow = page * size;
        int maxRow = (page + 1) * size;
        List<STTResult> results = sttResultRepository.findByMemberMemberNumWithPagination(memberNum, minRow, maxRow);
        long total = sttResultRepository.countByMemberMemberNum(memberNum);

        return new PageImpl<>(results, PageRequest.of(page, size), total);
    }

    public STTResult getSTTResultByMemberNumAndId(Long memberNum, Long id) {
        return sttResultRepository.findByMemberMemberNumAndId(memberNum, id)
                .orElseThrow(() -> new RuntimeException("STTResult not found"));
    }
    
    
    private double getFileDuration(File file) {
        try {
            MultimediaObject multimediaObject = new MultimediaObject(file);
            long durationInMilliseconds = multimediaObject.getInfo().getDuration();
            return durationInMilliseconds / 1000.0;
        } catch (EncoderException e) {
            log.error("Error getting file duration: ", e);
            return 0.0;
        }
    }
    
    private String pollForResult(String transcribeId) throws InterruptedException {
        WebClient webClient = WebClient.builder()
                .baseUrl("https://openapi.vito.ai/v1")
                .defaultHeader(HttpHeaders.AUTHORIZATION, "bearer " + accessToken)
                .build();

        String response = null;
        boolean completed = false;
        int attempts = 0;
        int maxAttempts = 60; // 5분 (5초 간격으로 60번 시도)

        while (!completed && attempts < maxAttempts) {
            log.info("Polling for transcription result. Attempt: {}", attempts + 1);
            response = webClient.get()
                    .uri("/transcribe/" + transcribeId)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();

            log.info("Poll response: {}", response);

            JSONObject jsonObject = new JSONObject(response);
            if (jsonObject.getString("status").equals("completed")) {
                completed = true;
            } else {
                attempts++;
                Thread.sleep(5000); // Wait for 5 seconds before next poll
            }
        }

        if (!completed) {
            log.warn("Transcription did not complete within the expected time.");
            return "";
        }

        log.info("Transcription completed");
        JSONObject jsonObject = new JSONObject(response);
        JSONArray utterances = jsonObject.getJSONObject("results").getJSONArray("utterances");
        
        StringBuilder fullText = new StringBuilder();
        for (int i = 0; i < utterances.length(); i++) {
            JSONObject utterance = utterances.getJSONObject(i);
            fullText.append(utterance.getString("msg")).append(" ");
        }
        
        return fullText.toString().trim();
    }





     // 5초마다 실행 (주기는 필요에 따라 조절)
    public void startPolling() throws InterruptedException {
        log.info("Polling 함수 첫 시작");
        String response = null;
        Thread.sleep(5000);
        while (!stopPolling) {
            log.info("while polling 시작 반복중");
            WebClient webClient = WebClient.builder()
                    .baseUrl("https://openapi.vito.ai/v1")
                    .defaultHeader(HttpHeaders.AUTHORIZATION, "bearer " + accessToken)
                    .build();


            String uri = "/transcribe/" + transcribeId;
            response = webClient.get()
                    .uri(uri)
                    .retrieve()
                    .bodyToMono(String.class)
                    .block();



            JSONObject jsonObject = new JSONObject(response.toString());
            // status 확인하여 폴링 중단 여부 결정
            if (jsonObject.getString("status").equals("completed")) {
                stopPolling = true;
            }

            try {
                Thread.sleep(5000); // 폴링 주기 (5초)를 설정
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            }
            log.info("while polling 끝 반복중");
        }

        log.info("폴링함수 끝");
        log.info(response.toString());
    }






    public void transcribeWebSocketFile(MultipartFile multipartFile) throws IOException, InterruptedException {
        Logger logger = Logger.getLogger(TutorialService.class.getName());
        OkHttpClient client = new OkHttpClient();
        String token = getAccessToken();

        HttpUrl.Builder httpBuilder = HttpUrl.get("https://openapi.vito.ai/v1/transcribe:streaming").newBuilder();
        httpBuilder.addQueryParameter("sample_rate", "44100");
        httpBuilder.addQueryParameter("encoding", "WAV");
        httpBuilder.addQueryParameter("use_itn", "true");
        httpBuilder.addQueryParameter("use_disfluency_filter", "true");
        httpBuilder.addQueryParameter("use_profanity_filter", "true");

        String url = httpBuilder.toString().replace("https://", "wss://");

        Request request = new Request.Builder()
                .url(url)
                .addHeader("Authorization", "Bearer " + token)
                .build();

        VitoWebSocketListener webSocketListener = new VitoWebSocketListener();
        WebSocket vitoWebSocket = client.newWebSocket(request, webSocketListener);

        File tempFile = null;
        try {
            tempFile = File.createTempFile("audio_", "." + getFileExtension(multipartFile.getOriginalFilename()));
            multipartFile.transferTo(tempFile);

            try (FileInputStream fis = new FileInputStream(tempFile)) {
                byte[] buffer = new byte[1024];
                int readBytes;
                while ((readBytes = fis.read(buffer)) != -1) {
                    boolean sent = vitoWebSocket.send(ByteString.of(buffer, 0, readBytes));
                    if (!sent) {
                        logger.log(Level.WARNING, "Send buffer is full. Cannot complete request. Increase sleep interval.");
                        System.exit(1);
                    }
                    Thread.sleep(0, 100);
                }
            }

            vitoWebSocket.send("EOS");

            webSocketListener.waitClose();
            client.dispatcher().executorService().shutdown();

        } finally {
            if (tempFile != null && tempFile.exists()) {
                tempFile.delete();
            }
        }
    }
    public void checkExternal(Member member, STTResult sttResult) {
		
		sttResult.setExternal(true);
		this.sttResultRepository.save(sttResult);
	}
    
    //마이페이지 그래프
    public Map<YearMonth, Map<String, Double>> getMonthlyUsageForMember(Long memberNum, LocalDateTime startDate, LocalDateTime endDate) {
        List<Object[]> results = sttResultRepository.getMonthlySumDurationForMemberWithExternal(memberNum, startDate, endDate);
        
        Map<YearMonth, Map<String, Double>> monthlyUsage = new TreeMap<>();

        for (Object[] result : results) {
            LocalDateTime dateTime = ((Timestamp) result[0]).toLocalDateTime();
            YearMonth yearMonth = YearMonth.from(dateTime);
            Double durationInMinutes = ((Number) result[1]).doubleValue() / 60.0;
            
            // Integer를 Boolean으로 변환
            boolean isExternal = (Integer) result[2] != 0;
            
            monthlyUsage.computeIfAbsent(yearMonth, k -> new HashMap<>());
            String usageType = isExternal ? "Open API 사용" : "내부 사용";
            monthlyUsage.get(yearMonth).put(usageType, durationInMinutes);
        }

        return monthlyUsage;
    }
}






@Slf4j
class VitoWebSocketListener extends WebSocketListener {
    private static final Logger logger = Logger.getLogger(TutorialService.class.getName());
    private static final int NORMAL_CLOSURE_STATUS = 1000;
    private CountDownLatch latch = null;

    private static void log(Level level, String msg, Object... args) {
        logger.log(level, msg, args);
    }

    @Override
    public void onOpen(WebSocket webSocket, Response response) {
        log(Level.INFO, "Open " + response.message());
        latch = new CountDownLatch(1);
    }

    @Override
    public void onMessage(WebSocket webSocket, String text) {
        System.out.println(text);
        log.info(text);
    }

    @Override
    public void onMessage(WebSocket webSocket, ByteString bytes) {
        System.out.println(bytes.hex());
        log.info(bytes.hex());
    }

    @Override
    public void onClosing(WebSocket webSocket, int code, String reason) {
        webSocket.close(NORMAL_CLOSURE_STATUS, null);
        log(Level.INFO, "Closing {0} {1}", code, reason);
    }

    @Override
    public void onClosed(WebSocket webSocket, int code, String reason) {
        webSocket.close(NORMAL_CLOSURE_STATUS, null);
        log(Level.INFO, "Closed {0} {1}", code, reason);
        latch.countDown();
    }

    @Override
    public void onFailure(WebSocket webSocket, Throwable t, Response response) {
        t.printStackTrace();
        latch.countDown();
    }

    public void waitClose() throws InterruptedException {
        log(Level.INFO, "Wait for finish");
        latch.await();
    }
}