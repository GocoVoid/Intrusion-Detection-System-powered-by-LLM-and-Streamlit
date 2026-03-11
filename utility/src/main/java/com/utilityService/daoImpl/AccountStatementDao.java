package com.utilityService.daoImpl;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import com.utilityService.model.Transaction;

public interface AccountStatementDao {

	Optional<List<Transaction>> getAccountStatement(String accountNumber, LocalDateTime startDateTime,
			LocalDateTime endDateTime);

	Optional<List<Transaction>> getAccountStatementById(Long userId);

	Optional<List<Transaction>> getAccountStatementByAccountNumber(String accountNumber);

}