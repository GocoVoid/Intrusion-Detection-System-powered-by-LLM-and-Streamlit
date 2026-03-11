package com.utilityService.dto;

import lombok.Data;
import lombok.NoArgsConstructor;

import java.math.BigDecimal;

@Data
@NoArgsConstructor
public class FixedDepositRequest {
    private String fundingAccountNumber;
    private BigDecimal depositAmount;
    private String natureOfDeposit; //	MONTHLY, QUARTERLY, REINVESTMENT
    private int durationInMonths; 
    private BigDecimal interestRate;
}
