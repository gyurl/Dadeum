package com.hkit.stt.audio;

import java.util.Optional;

import org.springframework.data.jpa.repository.JpaRepository;

import com.hkit.stt.text.STTResult;

public interface AudioFileRepository extends JpaRepository<AudioFile, Long>{
	
	AudioFile findBySttResult(STTResult sttResult);

}
