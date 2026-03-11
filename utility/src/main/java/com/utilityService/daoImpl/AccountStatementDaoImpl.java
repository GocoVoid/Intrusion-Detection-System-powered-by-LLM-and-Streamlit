package com.utilityService.daoImpl;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;

import org.springframework.stereotype.Service;

import com.utilityService.model.Transaction;
import com.utilityService.repo.TransactionRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AccountStatementDaoImpl implements AccountStatementDao {

	private final TransactionRepository transactionRepository;
	
	@Override
	public Optional<List<Transaction>> getAccountStatement(String accountNumber, LocalDateTime startDateTime, LocalDateTime endDateTime) {
		List<Transaction> transactions = transactionRepository.findByAccountNumberAndDateBetween(accountNumber, startDateTime, endDateTime);
		return Optional.of(transactions);
	}
	
	@Override
	public Optional<List<Transaction>> getAccountStatementById(Long userId) {
		List<Transaction> transactions = transactionRepository.findAllByUserId(userId);
		return Optional.of(transactions);
	}
	
	@Override
	public Optional<List<Transaction>> getAccountStatementByAccountNumber(String accountNumber) {
		List<Transaction> transactions = transactionRepository.findAllByAccountNumber(accountNumber);
		return Optional.of(transactions);
	}
	
}
