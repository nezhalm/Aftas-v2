package com.example.reviewappv2.security.filters;

import com.example.reviewappv2.security.JwtService;
import com.example.reviewappv2.services.impl.CustomUserDetailsService;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.NonNull;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import java.io.IOException;

@Component
@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtService jwtService;
    private final CustomUserDetailsService customUserDetailsService;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain)
            throws ServletException, IOException {
        // Récupérer l'en-tête "Authorization" de la requête
        String header = request.getHeader("Authorization");
        final String token;
        final String userEmail;

        // Vérifier si l'en-tête est absent ou ne commence pas par "Bearer "
        if (header == null || !header.startsWith("Bearer ")) {
            // Si l'en-tête est absent ou ne correspond pas au format attendu, passer au filtre suivant
            filterChain.doFilter(request, response);
            return;
        }

        // Extraire le token JWT en enlevant le préfixe "Bearer "
        token = header.replace("Bearer ", "");

        // Configurer le service JWT avec le token extrait
        jwtService.setToken(token);

        // Extraire le nom d'utilisateur (userEmail) du token
        userEmail = jwtService.extractUsername(token);

        // Vérifier si l'authentification n'est pas déjà définie dans le contexte de sécurité de Spring
        if (userEmail != null && SecurityContextHolder.getContext().getAuthentication() == null) {
            // Charger les détails de l'utilisateur depuis la base de données (ou autre source) par le service UserDetails
            UserDetails userDetails = this.customUserDetailsService.loadUserByUsername(userEmail);

            // Valider le token par rapport aux détails de l'utilisateur
            if (jwtService.validateToken(token, userDetails)) {
                // Créer un objet d'authentification Spring Security
                UsernamePasswordAuthenticationToken authenticationToken = new UsernamePasswordAuthenticationToken(
                        userDetails, null, userDetails.getAuthorities()
                );

                // Définir les détails d'authentification supplémentaires basés sur la requête
                authenticationToken.setDetails(
                        new WebAuthenticationDetailsSource().buildDetails(request)
                );

                // Définir l'objet d'authentification dans le contexte de sécurité de Spring
                SecurityContextHolder.getContext().setAuthentication(authenticationToken);
            }
        }

        // Continuer avec le filtre suivant dans la chaîne de filtres
        filterChain.doFilter(request, response);
    }


}