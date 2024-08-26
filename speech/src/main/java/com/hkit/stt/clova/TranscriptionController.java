package com.hkit.stt.clova;

import java.nio.file.Files;
import java.nio.file.attribute.BasicFileAttributes;
import java.time.Duration;
import java.time.Instant;

import org.bytedeco.javacv.FFmpegFrameGrabber;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import lombok.RequiredArgsConstructor;

@Controller
@RequestMapping("/api")
@RequiredArgsConstructor
public class TranscriptionController {

    private final ClovaSpeechService cs;
    private final TranscriptionRepository tr;

    @GetMapping("/upload")
    public String showUploadForm(Model model) {
        return "upload";
    }

    @PostMapping("/transcribe")
    public String transcribeAudio(@RequestParam("file") MultipartFile file, Model model) {
        Instant startTotal = Instant.now();
        System.out.println("시작");

        try {
            // 1. 파일 정보 추출
            String fileName = file.getOriginalFilename();
            String fileExtension = fileName.substring(fileName.lastIndexOf(".") + 1);
            long fileSize = file.getSize();
            byte[] audioData = file.getBytes();

            // 임시 파일로 저장하여 파일 속성 읽기
            java.nio.file.Path tempFile = Files.createTempFile("audio", "." + fileExtension);
            Files.write(tempFile, audioData);
            BasicFileAttributes attrs = Files.readAttributes(tempFile, BasicFileAttributes.class);
            System.out.println("Creation time: " + attrs.creationTime());
            long durationMillis = Files.probeContentType(tempFile).contains("audio") ? getAudioDurationMillis(tempFile) : 0;
            Files.delete(tempFile);

            Instant startStt = Instant.now();
            // 2. STT 처리
            String transcriptionText = cs.getSpeechToText(audioData);
            Instant endStt = Instant.now();

            // 3. DB에 저장
            Transcription transcription = new Transcription();
            transcription.setText(transcriptionText);
            tr.save(transcription);

            model.addAttribute("transcriptionText", transcriptionText);
            Instant endTotal = Instant.now();

            // 4. 로그 출력
            System.out.println("파일 이름: " + fileName);
            System.out.println("음성 파일 길이: " + durationMillis / 1000 + "초");
            System.out.println("파일 용량: " + formatFileSize(fileSize));
            System.out.println("확장자명: " + fileExtension);
            System.out.println("STT 실행 시간: " + formatDuration(Duration.between(startStt, endStt).toMillis()));
            System.out.println("총 처리 시간: " + formatDuration(Duration.between(startTotal, endTotal).toMillis()));
            System.out.println("결과 텍스트: " + transcriptionText);

            System.out.println("끝");
            return "result";
        } catch (Exception e) {
            e.printStackTrace();
            model.addAttribute("error", "Error occurred");
            return "upload";
        }
    }

    private long getAudioDurationMillis(java.nio.file.Path path) {
        try (FFmpegFrameGrabber grabber = new FFmpegFrameGrabber(path.toFile())) {
            grabber.start();
            long duration = grabber.getLengthInTime() / 1000; // microseconds to milliseconds
            grabber.stop();
            return duration;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    private String formatFileSize(long bytes) {
        double size = bytes;
        String[] units = {"B", "KB", "MB", "GB", "TB"};
        int unitIndex = 0;

        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex++;
        }

        return String.format("%.2f %s", size, units[unitIndex]);
    }

    private String formatDuration(long millis) {
        long seconds = millis / 1000;
        long minutes = seconds / 60;
        seconds = seconds % 60;
        double millisPart = millis % 1000 / 1000.0;

        if (minutes > 0) {
            return String.format("%d분 %06.3f초", minutes, seconds + millisPart);
        } else {
            return String.format("%06.3f초", seconds + millisPart);
        }
    }
}
