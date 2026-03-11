package com.utilityService.dto;

import lombok.Data;
import java.time.LocalDate;

@Data
public class StatementRequest {
    private String accountNumber;
    
    private LocalDate fromDate;
    private LocalDate toDate;
}
