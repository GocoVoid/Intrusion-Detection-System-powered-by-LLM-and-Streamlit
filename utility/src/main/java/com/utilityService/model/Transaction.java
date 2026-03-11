package com.utilityService.model;

import jakarta.persistence.*;
import lombok.Data;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "transactions")
@Data
public class Transaction {

    @Id
    @GeneratedValue(strategy = GenerationType.AUTO)
    private Long sno;

    @Column(nullable = false)
    private LocalDateTime date;

    private String description;

    @Column(nullable = false)
    private String type; // DR, CR

    @Column(nullable = false)
    private BigDecimal transactionAmount;

    @Column(nullable = false)
    private String accountNumber;
    
    private Long userId;
    
}
