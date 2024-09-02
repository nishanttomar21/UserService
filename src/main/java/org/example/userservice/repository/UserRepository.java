// JpaRepository<Model, Primary key datatype> is an interface that extends the PagingAndSortingRepository<Model, Primary key datatype> which in turn extends the CrudRepository<Model, Primary key datatype>
// ORM (Object-Relational Mapping) is a programming technique that maps the object-oriented domain model (Java objects) to a relational database (Tables)
// Optional<Object> is a container object that may or may not contain a non-null value. If a value is present, isPresent() will return true and get() will return the value.
// 3 ways to Query the database:
//      1. JPA Query Methods - Define the method in the repository interface by appending the method name with the query keyword followed by the entity name. Example: findByName(String name) - This method will find the entity by its name.
//      2. @Query Annotation - Define the query using JPQL (Java Persistence Query Language) in the repository interface. Example: @Query("SELECT c FROM Category c WHERE c.name = :name") - This method will find the entity by its name. You are writing the query in object-oriented way using java objects.
//      3. Native Query - Define the query using native SQL in the repository interface. Example: @Query(value = "SELECT * FROM categories WHERE name = :name", nativeQuery = true) - This method will find the entity by its name. SQL query directly runs on the database.
// When your system/codebase start to become large/complex, then companies generally start to transition from ORM to directly writing Native queries. ORM is good for small projects because it is easy to use and understand. It is also good for rapid development. But for large projects, ORM can be slow and inefficient. Native queries are faster and more efficient for large projects.

package org.example.userservice.repository;

import org.example.userservice.models.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    @Override
    User save(User user);

    Optional<User> findByEmail(String email);
}
