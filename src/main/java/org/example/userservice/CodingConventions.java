/**

A. TODO [Coding convention in springboot for creating 2 classes createDto and getDto for each model  and later using in other classes]:

In a Spring Boot project, it's common to use Data Transfer Objects (DTOs) to transfer data between different layers of an application, such as the controller, service, and repository layers. DTOs are particularly useful for encapsulating the data that you want to expose or receive from an API while keeping your internal models safe from external exposure.

When creating CreateDto and GetDto classes for each model, it's essential to follow a consistent coding convention to maintain readability, clarity, and maintainability. Here’s a convention you can follow:

1. Naming Conventions
Model Class: Use PascalCase for model names. Example: User, Product.
DTO Classes:
CreateDto: Name it in the format <ModelName>CreateDto. Example: UserCreateDto, ProductCreateDto.
GetDto: Name it in the format <ModelName>GetDto. Example: UserGetDto, ProductGetDto.

2. Package Structure
Organize your DTOs under a dto package inside the model package or alongside your model classes.

Copy code
com.example.projectname.model
│
├── User.java
├── dto
│   ├── UserCreateDto.java
│   └── UserGetDto.java

3. Class Structure
CreateDto Class: Include only the fields that are required for creating a new instance of the model. This might exclude fields like id, createdAt, or any auto-generated fields.
GetDto Class: Include all fields that you want to expose in the response to the client. This might include additional fields like id, createdAt, or any derived fields.

public class UserCreateDto {
    @NotBlank(message = "Username is required") // Validation annotations can be added
    private String username;

    @NotBlank(message = "Email is required")
    private String email;
}

public class UserGetDto {
    private Long id;
    private String username;
    private String email;
    private String createdAt;
}

4. Mapping Between Model and DTOs
Use a mapping service or library like MapStruct, ModelMapper, or write custom methods to convert between the model and DTOs.
Create a static method in each DTO class to convert the model to the DTO and vice versa. This method should handle the conversion logic between the model and DTO fields.

public class UserMapper {

    public static User toEntity(UserCreateDto dto) {
        User user = new User();
        user.setUsername(dto.getUsername());
        user.setEmail(dto.getEmail());
        return user;
    }

    public static UserGetDto toDto(User user) {
        UserGetDto dto = new UserGetDto();
        dto.setId(user.getId());
        dto.setUsername(user.getUsername());
        dto.setEmail(user.getEmail());
        dto.setCreatedAt(user.getCreatedAt().toString());
        return dto;
    }
}

6. Controller Usage
In your controllers, you can use these DTOs to handle incoming requests and to send responses.

@RestController
@RequestMapping("/api/users")
public class UserController {

    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @PostMapping
    public ResponseEntity<UserGetDto> createUser(@RequestBody UserCreateDto userCreateDto) {
        UserGetDto createdUser = userService.createUser(userCreateDto);
        return ResponseEntity.ok(createdUser);
    }

    @GetMapping("/{id}")
    public ResponseEntity<UserGetDto> getUserById(@PathVariable Long id) {
        UserGetDto user = userService.getUserById(id);
        return ResponseEntity.ok(user);
    }
}

B. TODO [Why use ResponseEntity in response sent to client]:
The ResponseEntity class in Spring is a powerful way to represent the entire HTTP response, including the status code, headers, and body. It's often used in controllers to return responses from RESTful APIs. Using ResponseEntity in Spring Boot is optional but highly recommended, especially when you want to have fine-grained control over your HTTP responses

ResponseEntity is recommended when you need precise control over your HTTP responses.
It allows for setting status codes, headers, and different types of response bodies, which is useful in many scenarios, particularly in RESTful web services.
For simple use cases, where a method always returns 200 OK, you can skip ResponseEntity and let Spring handle the wrapping for you.

@GetMapping("/users")
public List<UserGetDto> getAllUsers() {
    return userService.getAllUsers(); // Implicitly wrapped in ResponseEntity.ok() (Spring will wrap it in a ResponseEntity automatically.)
}

C. TODO [Should we convert the dto data to model in controller layer or service layer]:

In a Spring Boot application, it's generally considered best practice to convert DTOs (Data Transfer Objects) to model entities in the service layer rather than in the controller layer. Here's why:

Separation of Concerns:
    Controller Layer: The controller is responsible for handling HTTP requests, interacting with the service layer, and returning appropriate HTTP responses. It should be focused on dealing with the web aspect of your application, such as request handling and response formatting.
    Service Layer: The service layer contains the business logic of your application. It's responsible for processing the data, which often involves converting DTOs to entities and vice versa. This keeps your business logic decoupled from the web layer, making the application easier to maintain and test.

Example Workflow:
    Controller Receives DTO: The controller receives a CreateDto from the client.
    Controller Passes DTO to Service: The controller passes this DTO to the service layer without converting it.
    Service Converts DTO to Model: The service converts the DTO to a model entity, processes it, and performs the necessary business logic.
    Service Returns Result: The service might return a GetDto or another DTO that the controller will use to construct the HTTP response.

*/