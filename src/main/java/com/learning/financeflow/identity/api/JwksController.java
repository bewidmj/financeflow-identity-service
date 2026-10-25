package com.learning.financeflow.identity.api;

import com.learning.financeflow.identity.security.JwtKeyProvider;
import java.util.List;
import java.util.Map;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class JwksController {

    private final JwtKeyProvider keys;

    public JwksController(JwtKeyProvider keys) {
        this.keys = keys;
    }

    @GetMapping("/.well-known/jwks.json")
    public Map<String, List<Map<String, String>>> jwks() {
        return Map.of("keys", keys.jwkSet());
    }
}
