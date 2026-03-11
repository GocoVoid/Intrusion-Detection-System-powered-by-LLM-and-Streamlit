package com.utilityService.controller;

import java.time.LocalDate;
import java.util.List;

import javax.security.auth.login.AccountNotFoundException;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.utilityService.dto.StatementRequest;
import com.utilityService.dto.TransactionResponse;
import com.utilityService.service.AccountStatementService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/utility/statement")
@RequiredArgsConstructor
public class AccountStatementController {

	private final AccountStatementService accountStatementService;
	
	@PostMapping("/getStatement")
	public ResponseEntity<List<TransactionResponse>> getAccountStatement(@RequestBody StatementRequest statementRequest) throws AccountNotFoundException {
		
		String accountNumber = statementRequest.getAccountNumber();
		LocalDate fromDate = statementRequest.getFromDate();
		LocalDate toDate = statementRequest.getToDate();
		
		List<TransactionResponse> accountStatement = accountStatementService.getAccountStatement(accountNumber,fromDate, toDate);
		return new ResponseEntity<List<TransactionResponse>>(accountStatement, HttpStatus.OK);
	}
	
	@GetMapping("/getStatement/user/{userId}")
	public ResponseEntity<List<TransactionResponse>> getAccountStatementByUserId(@PathVariable Long userId) {
		List<TransactionResponse> accountStatementByUserId = accountStatementService.getAccountStatementByUserId(userId);
		return new ResponseEntity<List<TransactionResponse>>(accountStatementByUserId, HttpStatus.OK);
	}
	
	@GetMapping("/getStatement/{accountNumber}")
	public ResponseEntity<List<TransactionResponse>> getAccountStatementByAccountNumber(@PathVariable String accountNumber) {
		List<TransactionResponse> accountStatementByUserId = accountStatementService.getAccountStatementByAccountNumber(accountNumber);
		return new ResponseEntity<List<TransactionResponse>>(accountStatementByUserId, HttpStatus.OK);
	}
	
}
