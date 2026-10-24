package com.learning.financeflow.identity.security;
import io.jsonwebtoken.Claims;
import jakarta.servlet.*;
import jakarta.servlet.http.*;
import java.io.IOException;
import java.util.List;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
@Component
public class JwtAuthenticationFilter extends OncePerRequestFilter {
  private final JwtService jwtService;
  public JwtAuthenticationFilter(JwtService jwtService){this.jwtService=jwtService;}
  @Override protected void doFilterInternal(HttpServletRequest req,HttpServletResponse res,FilterChain chain) throws ServletException,IOException {
    String header=req.getHeader("Authorization");
    if(header!=null && header.startsWith("Bearer ")) {
      try {
        Claims claims=jwtService.parseAndValidate(header.substring(7));
        String role=claims.get("role",String.class);
        var auth=new UsernamePasswordAuthenticationToken(claims.getSubject(),null,List.of(new SimpleGrantedAuthority("ROLE_"+role)));
        SecurityContextHolder.getContext().setAuthentication(auth);
      } catch(RuntimeException ex) { SecurityContextHolder.clearContext(); }
    }
    chain.doFilter(req,res);
  }
}
