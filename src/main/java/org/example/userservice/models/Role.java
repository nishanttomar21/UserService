package org.example.userservice.models;

import jakarta.persistence.Entity;
import lombok.Getter;
import lombok.Setter;

@Getter
@Setter
@Entity
public class Role extends BaseModel {

    private String role; // ENUM not used here because if we want to add a new enum later, then we will have to manually update the ENUM and the database but with String you can do it on the fly/runtime
}
