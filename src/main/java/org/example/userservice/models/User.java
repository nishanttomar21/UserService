// JsonIgnore - The @JsonIgnore annotation in Spring Boot, which comes from the Jackson library, is used to instruct Jackson to ignore certain fields during the serialization (converting Java objects to JSON) and deserialization (converting JSON to Java objects) processes. This means that when a Java object is serialized to JSON, the field annotated with @JsonIgnore will be omitted from the JSON output, and when deserializing JSON to a Java object, the field will not be populated even if it is present in the JSON input.
// Use Cases: @JsonIgnore is useful in scenarios where certain sensitive or irrelevant data should not be exposed or processed, such as passwords, internal IDs, or any fields that should remain hidden in API responses.
// Jackson - A popular Java library used in Spring Boot for converting Java objects to JSON (serialization) and JSON to Java objects (deserialization). It is the default JSON processor in Spring Boot, meaning that when your Spring Boot application deals with JSON data, Jackson is typically used under the hood.
// FetchType - (when will an attribute be fetched) It is used to specify the fetching strategy to retrieve the related entities. Used when you have a relation between two entities. There are two types of FetchType:
//      FetchType.LAZY - It fetches the related entities lazily, i.e., only when they are requested. When you try to get object of class, the value of that attribute will be fetched when accessed. It is the default fetch type for @OneToMany and @ManyToMany relationships. By default Collections(List, Set, Map) are lazy fetchType, collections leads to calling joins in SQL. It means that when you load an entity, the collection is not loaded. It is loaded only when you try to access it. Mostly for Collections you use LAZY and only use EAGER when the no. of items are less and those items are almost needed together along with the object of the parent class.
//      FetchType.EAGER - It fetches the related entities eagerly, i.e., at the time of fetching the parent entity. When you try to get object of class, the value of all the attributes will be fetched. It is the default fetch type for @OneToOne and @ManyToOne relationships.
//      FetchType.LAZY is more efficient than FetchType.EAGER as it loads the related entities only when they are needed. However, FetchType.LAZY can lead to LazyInitializationException if the related entities are accessed outside the transaction boundary.
//      FetchType.EAGER can lead to performance issues as it fetches all the related entities even if they are not needed. It is recommended to use FetchType.LAZY for @OneToMany and @ManyToMany relationships to avoid performance issues.
// FetchMode - (how will an attribute be fetched) It is used to specify the fetching mode to retrieve the related entities. Used when you have a relation between two entities. There are three types of FetchMode:
//      FetchMode.SELECT - It fetches the related entities using a separate SELECT query. It is the default fetch mode for @OneToMany and @ManyToMany relationships. It means that when you load an entity, the collection is not loaded. It is loaded only when you try to access it.
//      FetchMode.SUBSELECT - It fetches the related entities using a separate SELECT query with a subquery statement. It is used to fetch the related entities in a single query. It is more efficient than FetchMode.SELECT as it reduces the number of queries executed. It is recommended to use FetchMode.SUBSELECT for @OneToMany and @ManyToMany relationships to improve performance.
//      FetchMode.JOIN - It fetches the related entities using a JOIN query. It is the default fetch mode for @OneToOne and @ManyToOne relationships. It means that when you load an entity, the collection is loaded along with it. It is loaded even if you do not access it.
// FetchMode.SELECT is more efficient than FetchMode.JOIN as it loads the related entities using a separate SELECT query only when they are needed. However, FetchMode.SELECT can lead to N+1 query issues if the related entities are accessed in a loop. FetchMode.JOIN fetches all the related entities using a JOIN query even if they are not needed. It is recommended to use FetchMode.SELECT for @OneToMany and @ManyToMany relationships to avoid N+1 query issues.
// FetchType.LAZY and FetchMode.SELECT are used together to fetch the related entities lazily using a separate SELECT query only when they are needed. FetchType.EAGER and FetchMode.JOIN are used together to fetch the related entities eagerly using a JOIN query even if they are not needed.


package org.example.userservice.models;

import com.fasterxml.jackson.annotation.JsonIgnore;
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
    @JsonIgnore
    private Set<Role> roles = new HashSet<>();
}
