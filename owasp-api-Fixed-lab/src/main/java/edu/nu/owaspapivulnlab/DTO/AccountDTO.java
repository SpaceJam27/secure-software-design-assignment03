package edu.nu.owaspapivulnlab.DTO;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class AccountDTO {
    private Long id;
    private String iban;
    private Double balance;
    // Do NOT include ownerUserId if you don't want to expose who owns the account directly,
    // although in an ownership-enforced API, this might be less critical.
    // For this task, we will exclude it to be safe.
}
