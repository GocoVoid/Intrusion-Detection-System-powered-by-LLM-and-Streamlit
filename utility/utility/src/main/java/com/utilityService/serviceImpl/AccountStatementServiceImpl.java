package com.utilityService.serviceImpl;

import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import javax.security.auth.login.AccountNotFoundException;

import org.springframework.stereotype.Service;

import com.utilityService.daoImpl.AccountStatementDao;
import com.utilityService.dto.TransactionResponse;
import com.utilityService.exception.InvalidDateRangeException;
import com.utilityService.exception.UnableToFetchTransactionsException;
import com.utilityService.model.Transaction;
import com.utilityService.service.AccountStatementService;
import com.utilityService.service.AccountValidationService;

import lombok.RequiredArgsConstructor;

@Service
@RequiredArgsConstructor
public class AccountStatementServiceImpl implements AccountStatementService {

	private final AccountStatementDao accountStatementDao;
	private final AccountValidationService accountValidationService;
	
	@Override
	public List<TransactionResponse> getAccountStatement(String accountNumber, LocalDate fromDate, LocalDate toDate) throws AccountNotFoundException {
		
		if (!accountValidationService.doesAccountExist(accountNumber)) {
            throw new AccountNotFoundException("Account Number " + accountNumber+" Not Found");
        }

        if (!fromDate.isBefore(toDate) || !fromDate.equals(toDate)) {
            throw new InvalidDateRangeException("Invalid date range provided.");
        }

        LocalDateTime startDateTime = fromDate.atStartOfDay();
        LocalDateTime endDateTime = toDate.atTime(LocalTime.MAX);

        Optional<List<Transaction>> transactions = accountStatementDao.getAccountStatement(accountNumber, startDateTime, endDateTime);

        if (transactions.isPresent()) {
	        return transactions.get().stream()
	                .map(this::mapToResponseDto)
	                .collect(Collectors.toList());
        } else {
        	throw new UnableToFetchTransactionsException("Unable to fetch transactions for A/c no. "+accountNumber);
        }
	}
	
	@Override
	public List<TransactionResponse> getAccountStatementByUserId(Long userId) {
		Optional<List<Transaction>> transactions = accountStatementDao.getAccountStatementById(userId);
		if (transactions.isPresent()) {
	        return transactions.get().stream()
	                .map(this::mapToResponseDto)
	                .collect(Collectors.toList());
        } else {
        	throw new UnableToFetchTransactionsException("Unable to fetch transactions");
        }
	}
	
	@Override
	public List<TransactionResponse> getAccountStatementByAccountNumber(String accountNumber) {
		Optional<List<Transaction>> transactions = accountStatementDao.getAccountStatementByAccountNumber(accountNumber);
		if (transactions.isPresent()) {
	        return transactions.get().stream()
	                .map(this::mapToResponseDto)
	                .collect(Collectors.toList());
        } else {
        	throw new UnableToFetchTransactionsException("Unable to fetch transactions for A/c no. "+accountNumber);
        }
	}

    private TransactionResponse mapToResponseDto(Transaction transaction) {
        TransactionResponse response = new TransactionResponse();
        response.setDate(transaction.getDate());
        response.setDescription(transaction.getDescription());
        response.setType(transaction.getType());
        response.setAmount(transaction.getTransactionAmount());
        return response;
    }
	
}
