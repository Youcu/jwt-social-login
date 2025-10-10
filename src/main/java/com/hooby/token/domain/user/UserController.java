package com.hooby.token.domain.user;

import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequiredArgsConstructor
@RequestMapping("/test")
public class UserController {

    @GetMapping
    public String test() {
        return "ShouldNotFilter 잘 동작하나?";
    }
}
