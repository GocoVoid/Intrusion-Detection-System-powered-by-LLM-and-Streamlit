package com.utilityService.service;

import com.utilityService.dto.FixedDepositRequest;
import com.utilityService.model.FixedDeposit;
import java.math.BigDecimal;
import java.time.LocalDate;
import java.util.List;

public interface FixedDepositService {

    FixedDeposit openFixedDeposit(FixedDepositRequest request) throws Exception;

    LocalDate calculateMaturityDate(LocalDate creationDate, int durationInMonths);
    
    List<FixedDeposit> getFixedDepositsByAccountNumber(String accountNumber) throws Exception;

    BigDecimal calculateEstimatedMaturityAmount(BigDecimal principal, BigDecimal interestRate, String nature, int durationInMonths);
}