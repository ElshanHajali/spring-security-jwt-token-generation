package az.company.security.controller;

import az.company.security.service.TokenService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("v1/token")
@RequiredArgsConstructor
public class AuthController {
    private final TokenService tokenService;

    @PostMapping
    public ResponseEntity<String> generateToken(Authentication authentication) {
        return new ResponseEntity<>(
                tokenService.generateToken(authentication),
                HttpStatus.CREATED
        );
    }
}
