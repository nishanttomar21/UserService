// EnumType.ORDINAL is used to store the enum value as an integer in the database.
// EnumType.STRING is used to store the enum value as a string in the database.

package org.example.userservice.models;

import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.ManyToOne;
import lombok.Getter;
import lombok.Setter;

import java.util.Date;

@Getter
@Setter
@Entity
public class Session extends BaseModel {
    private String token;
    private Date expiringAt;

    @Enumerated(EnumType.ORDINAL)
    private SessionStatus status;

    @ManyToOne
    private User user;
}
