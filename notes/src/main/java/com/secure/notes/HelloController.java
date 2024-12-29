package com.secure.notes;


import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class HelloController {

    @GetMapping("/hello-vansh")
    public String hello()
    {
        return "HELLO";
    }

    @GetMapping("/hi-vansh")
    public String hi()
    {
        return "Hi";
    }

    @GetMapping("/contact")
    public String helloContact()
    {
        return "Contacting the Ritik";
    }
}
