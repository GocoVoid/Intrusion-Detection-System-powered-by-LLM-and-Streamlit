package com.utilityService.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import com.utilityService.dto.FundTransferRequest;
import com.utilityService.service.FundTransferService;

import lombok.RequiredArgsConstructor;

@RestController
@RequestMapping("/api/utility/transfers")
@RequiredArgsConstructor
public class FundTransferController {
	
	private final FundTransferService fundTransferService;

	@PostMapping("/send")
	public ResponseEntity<String> transferFunds(@RequestBody FundTransferRequest fundTransferRequest) throws Exception {
		String message = fundTransferService.transferFunds(fundTransferRequest);
		return new ResponseEntity<String>(message, HttpStatus.ACCEPTED);
	}
	
}
