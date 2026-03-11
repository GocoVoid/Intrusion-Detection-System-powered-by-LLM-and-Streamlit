package com.utilityService.controller;

import com.utilityService.dto.FixedDepositRequest;
import com.utilityService.model.FixedDeposit;
import com.utilityService.service.FixedDepositService;
import lombok.RequiredArgsConstructor;

import java.util.List;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/utility/fixed-deposits")
@RequiredArgsConstructor
public class FixedDepositController {

    private final FixedDepositService fixedDepositService;

    @PostMapping("/create")
    public ResponseEntity<FixedDeposit> openFixedDeposit(@RequestBody FixedDepositRequest fixedDepositRequest) throws Exception {
        
        FixedDeposit newFixedDeposit = fixedDepositService.openFixedDeposit(fixedDepositRequest);
        return new ResponseEntity<FixedDeposit>(newFixedDeposit, HttpStatus.CREATED);
    }
    
    @GetMapping("/account/{accountNumber}")
    public ResponseEntity<List<FixedDeposit>> getFixedDepositsByAccount(@PathVariable String accountNumber) throws Exception {
        
        List<FixedDeposit> fixedDeposits = fixedDepositService.getFixedDepositsByAccountNumber(accountNumber);
        return new ResponseEntity<List<FixedDeposit>>(fixedDeposits, HttpStatus.OK);
    }

}
