package org.mcs.finaljwtversion.token.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.Getter;
import lombok.NoArgsConstructor;

import java.util.Date;
import java.util.List;
import java.util.UUID;

@AllArgsConstructor
@NoArgsConstructor
@Data
public abstract class Token {

    private UUID id;

    private String subject;

    private List<String> authorities;

    private Date createdAt;

    private Date expiresAt;
}
