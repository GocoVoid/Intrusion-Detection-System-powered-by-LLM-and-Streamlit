package com.utilityService.daoImpl;

import java.util.Optional;

import org.springframework.stereotype.Service;

import com.utilityService.model.Transaction;
import com.utilityService.repo.TransactionRepository;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class TransactionDaoImpl implements TransactionDao {

	private final TransactionRepository transactionRepository;
	
	@Override
	public Optional<Transaction> saveTransaction(Transaction transaction) {
		Transaction savedTransaction = transactionRepository.save(transaction);
		return Optional.of(savedTransaction);
	}
	
}
