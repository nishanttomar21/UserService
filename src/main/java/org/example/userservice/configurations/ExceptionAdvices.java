// @ControllerAdvices - Allows you to define global exception handlers, model attributes, and data binding logic that apply to all or selected controllers in your application.
// DispatcherServlet <== ControllerAdvice(Additional Check/Manager) <== Controller
// By default, @ControllerAdvice applies to all controllers, but you can limit its scope by specifying the base packages, annotations, or controller classes it should apply to.
// @ExceptionHandler methods can be placed within a controller class for specific handling or in a @ControllerAdvice class for global handling.

package org.example.userservice.configurations;

import org.example.userservice.dtos.ErrorResponseDto;
import org.springframework.web.bind.annotation.ControllerAdvice;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestController;

@ControllerAdvice
@RestController   /** Use this annotation here otherwise you will get Error - "Whitelabel Error" in the browser when you hit a URL with method that is not defined in your server which throws an exception (This application has no explicit mapping for /error, so you are seeing this as a fallback) */
public class ExceptionAdvices {

    @ExceptionHandler(RuntimeException.class)
    public ErrorResponseDto handleRuntimeException(RuntimeException e) {    // This method is used to handle a specific exception
        ErrorResponseDto dto = new ErrorResponseDto();
        dto.setStatus("ERROR");
        dto.setMessage(e.getMessage());
        return dto;
    }

    @ExceptionHandler(Exception.class)  // This method is used to handle all the exceptions
    public String handleException() {   // // This method is used to handle all the exceptions
        return "something went wrong";
    }
}
