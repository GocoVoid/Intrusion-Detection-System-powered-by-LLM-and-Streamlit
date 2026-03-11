package com.utilityService.service;

import com.utilityService.dto.FundTransferRequest;

public interface FundTransferService {

    String transferFunds(FundTransferRequest request) throws Exception;

    //boolean isBeneficiaryActiveAndValid(Long customerId, String beneficiaryAccountNo);
}
