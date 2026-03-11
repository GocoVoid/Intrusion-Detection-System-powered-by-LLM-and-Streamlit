package com.utilityService.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;
import java.time.LocalDateTime;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class TransactionResponse {
    private LocalDateTime date;
    private String description;
    private String type; //	DR, CR
    private BigDecimal amount;
}
