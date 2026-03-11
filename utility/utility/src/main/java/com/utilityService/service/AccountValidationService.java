package com.utilityService.service;

import java.math.BigDecimal;

public interface AccountValidationService {

    
    boolean doesAccountExist(String accountNumber);

    boolean hasSufficientBalance(String accountNumber, BigDecimal amountRequested);

    BigDecimal getAvailableBalance(String accountNumber);

    //boolean verifyTransactionPassword(Long customerId, String rawPassword);
    
    Long getCustomerIdByAccountNumber(String accountNumber);
    
}
