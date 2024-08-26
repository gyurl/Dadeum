package com.hkit.stt.member;

import lombok.AllArgsConstructor;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;


@Getter
@Setter
public class MemberUsageDTO {

	private Long memberNum;
    private String id;
    private double internalUsage;
    private double externalUsage;

    public MemberUsageDTO(Long memberNum, String id, double internalUsage, double externalUsage) {
        this.memberNum = memberNum;
        this.id = id;
        this.internalUsage = internalUsage / 3600; // 초를 시간으로 변환
        this.externalUsage = externalUsage / 3600; // 초를 시간으로 변환
    }

    // Getters
    public String getFormattedInternalUsage() {
        return String.format("%.2f", internalUsage);
    }

    public String getFormattedExternalUsage() {
        return String.format("%.2f", externalUsage);
    }
}
