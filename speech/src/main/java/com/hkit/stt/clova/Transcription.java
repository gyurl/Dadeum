package com.hkit.stt.clova;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.Lob;
import jakarta.persistence.SequenceGenerator;
import lombok.Data;

@Entity
@Data
public class Transcription {

    @Id
    @GeneratedValue(strategy = GenerationType.SEQUENCE, generator = "transcription_seq2")
    @SequenceGenerator(name = "transcription_seq2", sequenceName = "TRANSCRIPTION_SEQ2", allocationSize = 10)
    private Long id;
    
    @Lob
    @Column(name = "TEXT2", columnDefinition = "CLOB")
    private String text;

}