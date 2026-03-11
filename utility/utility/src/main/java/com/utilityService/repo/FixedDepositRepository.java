package com.utilityService.repo;

import com.utilityService.model.FixedDeposit;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface FixedDepositRepository extends JpaRepository<FixedDeposit, Long> {
    
    List<FixedDeposit> findByFundingAccountNumber(String fundingAccountNumber);

	
}
