package com.utilityService.service;

import com.utilityService.dto.TransactionResponse;
import java.time.LocalDate;
import java.util.List;

import javax.security.auth.login.AccountNotFoundException;

public interface AccountStatementService {

    List<TransactionResponse> getAccountStatement(String accountNumber, LocalDate fromDate, LocalDate toDate) throws AccountNotFoundException;

	List<TransactionResponse> getAccountStatementByUserId(Long userId);

	List<TransactionResponse> getAccountStatementByAccountNumber(String accountNumber);

}
