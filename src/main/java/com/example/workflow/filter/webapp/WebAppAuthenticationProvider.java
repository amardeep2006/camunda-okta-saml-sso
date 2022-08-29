package com.example.workflow.filter.webapp;

import org.camunda.bpm.engine.ProcessEngine;
import org.camunda.bpm.engine.rest.security.auth.AuthenticationResult;
import org.camunda.bpm.engine.rest.security.auth.impl.ContainerBasedAuthenticationProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.http.HttpServletRequest;
import java.util.List;
import java.util.stream.Collectors;

public class WebAppAuthenticationProvider extends ContainerBasedAuthenticationProvider {

    private static final Logger LOG = LoggerFactory.getLogger(WebAppAuthenticationProvider.class);

    @Override
    public AuthenticationResult extractAuthenticatedUser(HttpServletRequest request, ProcessEngine engine) {

        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

        if (authentication == null) {
            return AuthenticationResult.unsuccessful();
        }

        String name = authentication.getName();
        LOG.info("extracted user: {}", name);
        LOG.info(String.valueOf(authentication));
        if (name == null || name.isEmpty()) {
            return AuthenticationResult.unsuccessful();
        }

        AuthenticationResult authenticationResult = new AuthenticationResult(name, true);
//       For extracting Groups from Auth info
        authenticationResult.setGroups(getUserGroups(authentication));

        return authenticationResult;
    }

    private List<String> getUserGroups(Authentication authentication) {

        List<String> groupIds;

        groupIds = authentication.getAuthorities().stream()
                .map(res -> res.getAuthority())
                .map(res -> res.substring(5)) // Strip "ROLE_"
                .collect(Collectors.toList());

        return groupIds;

    }

}
