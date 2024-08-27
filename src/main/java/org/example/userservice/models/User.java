// JsonIgnore - The @JsonIgnore annotation in Spring Boot, which comes from the Jackson library, is used to instruct Jackson to ignore certain fields during the serialization (converting Java objects to JSON) and deserialization (converting JSON to Java objects) processes. This means that when a Java object is serialized to JSON, the field annotated with @JsonIgnore will be omitted from the JSON output, and when deserializing JSON to a Java object, the field will not be populated even if it is present in the JSON input.
// Use Cases: @JsonIgnore is useful in scenarios where certain sensitive or irrelevant data should not be exposed or processed, such as passwords, internal IDs, or any fields that should remain hidden in API responses.
// Jackson - A popular Java library used in Spring Boot for converting Java objects to JSON (serialization) and JSON to Java objects (deserialization). It is the default JSON processor in Spring Boot, meaning that when your Spring Boot application deals with JSON data, Jackson is typically used under the hood.

package org.example.userservice.models;

import jakarta.persistence.Entity;
import jakarta.persistence.FetchType;
import jakarta.persistence.ManyToMany;
import lombok.Getter;
import lombok.Setter;

import java.util.HashSet;
import java.util.Set;

@Getter
@Setter
@Entity
public class User extends BaseModel {
    private String email;
    private String password;

    @ManyToMany(fetch = FetchType.EAGER)
    private Set<Role> roles = new HashSet<>();
}
