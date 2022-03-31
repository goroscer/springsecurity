package es.softtek.jwtDemo.security;

import es.softtek.jwtDemo.Service.PlatziUserDetailsService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.Security;

@Component
public class JwtFilterRequest extends OncePerRequestFilter {


    @Autowired
    private  JWTUtil jwtUtil;
    @Autowired
    private PlatziUserDetailsService platziUserDetailsService;



    @Override
    protected void doFilterInternal(HttpServletRequest httpServletRequest, HttpServletResponse httpServletResponse, FilterChain filterChain) throws ServletException, IOException {
        String authorizationHeader = httpServletRequest.getHeader("Authorization");


        if (authorizationHeader!=null && authorizationHeader.startsWith("Bearer")){

            String jwt= authorizationHeader.substring(7);
            String username= jwtUtil.extractUsername(jwt);
            if (username!=null && SecurityContextHolder.getContext().getAuthentication()==null){


                UserDetails userDetails= platziUserDetailsService.loadUserByUsername(username);

                if (jwtUtil.validateToken(jwt, userDetails)){



                    UsernamePasswordAuthenticationToken authenticationToken= new UsernamePasswordAuthenticationToken(userDetails,null,userDetails.getAuthorities());

                    authenticationToken.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpServletRequest));
                    SecurityContextHolder.getContext().setAuthentication(authenticationToken);


                }

            }



        }

        filterChain.doFilter(httpServletRequest,httpServletResponse);
    }
}
