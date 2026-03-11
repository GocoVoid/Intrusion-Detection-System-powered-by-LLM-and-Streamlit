package com.utilityService.model;

import jakarta.persistence.*;
import lombok.Data;
import java.math.BigDecimal;

@Entity
@Table(name = "accounts")
@Data
public class Account {

    @Id
    private String accountNumber; 
    
    private String accountStatus;
    
    private String accountType; // SELF, BENEFICIARY

    @Column(nullable = false)
    private String branchName;

    @Column(nullable = false)
    private BigDecimal availableBalance;

    @Column(nullable = false)
    private Long userId;
    
}
