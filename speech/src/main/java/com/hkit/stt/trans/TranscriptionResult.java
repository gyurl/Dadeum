package com.hkit.stt.trans;

import java.time.LocalDateTime;
import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;
import org.hibernate.annotations.Type;

@Entity
@Table(name = "TRANSCRIPTION_RESULT")
@Getter
@Setter

public class TranscriptionResult {
    
    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "transcription_seq")
    @SequenceGenerator(name = "transcription_seq", sequenceName = "TRANSCRIPTION_SEQ", allocationSize = 50)
    private Long id;
    
    @Column(name = "SOURCE")
    private String source;
    
    @Lob
    @Column(name = "TEXT", columnDefinition = "CLOB")
    private String text;
    
    @Column(name = "CREATED_AT")
    private LocalDateTime createdAt;

    public TranscriptionResult(String source, String text) {
        this.source = source;
        this.text = text;
        this.createdAt = LocalDateTime.now();
    }
}