package com.finsecure.model;

import javax.persistence.*;

/**
 * Account entity — models a financial account.
 *
 * VULN: isAdmin field is included in mass assignment.
 * A POST to /api/accounts with {"isAdmin": true} will elevate privileges.
 * This is CWE-915 — Improperly Controlled Modification of Dynamically-Determined Object Attributes.
 */
@Entity
@Table(name = "accounts")
public class Account {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String accountNumber;
    private String ownerName;
    private String ownerEmail;
    private Double balance;

    // VULN: isAdmin is mass-assignable via JSON — no @JsonIgnore here
    // An attacker can POST {"username":"hack","isAdmin":true} to gain admin
    private Boolean isAdmin = false;

    // VULN: This field gets stored and later used in a raw SQL query (second-order SQLi)
    private String profileNote;

    // =========== Constructors ===========
    public Account() {}

    public Account(String accountNumber, String ownerName, String ownerEmail, Double balance) {
        this.accountNumber = accountNumber;
        this.ownerName = ownerName;
        this.ownerEmail = ownerEmail;
        this.balance = balance;
    }

    // =========== Getters & Setters ===========
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }

    public String getAccountNumber() { return accountNumber; }
    public void setAccountNumber(String accountNumber) { this.accountNumber = accountNumber; }

    public String getOwnerName() { return ownerName; }
    public void setOwnerName(String ownerName) { this.ownerName = ownerName; }

    public String getOwnerEmail() { return ownerEmail; }
    public void setOwnerEmail(String ownerEmail) { this.ownerEmail = ownerEmail; }

    public Double getBalance() { return balance; }
    public void setBalance(Double balance) { this.balance = balance; }

    public Boolean getIsAdmin() { return isAdmin; }
    public void setIsAdmin(Boolean isAdmin) { this.isAdmin = isAdmin; }

    public String getProfileNote() { return profileNote; }
    public void setProfileNote(String profileNote) { this.profileNote = profileNote; }
}
