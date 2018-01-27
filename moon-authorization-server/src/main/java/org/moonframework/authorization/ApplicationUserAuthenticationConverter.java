package org.moonframework.authorization;

import org.moonframework.authorization.domain.ApplicationUser;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.provider.token.DefaultUserAuthenticationConverter;

import java.util.LinkedHashMap;
import java.util.Map;

public class ApplicationUserAuthenticationConverter extends DefaultUserAuthenticationConverter {

    private static final String USER_ID = "user_id";
    private static final String EMAIL = "email";

    @Override
    public Map<String, ?> convertUserAuthentication(Authentication authentication) {
        Map<String, Object> response = new LinkedHashMap<>();
        convertUserAuthentication(authentication, response);
        // response.put(USERNAME, authentication.getName());

        if (authentication.getAuthorities() != null && !authentication.getAuthorities().isEmpty()) {
            response.put(AUTHORITIES, AuthorityUtils.authorityListToSet(authentication.getAuthorities()));
        }
        return response;
    }

    private void convertUserAuthentication(Authentication authentication, Map<String, Object> response) {
        Object principal = authentication.getPrincipal();
        if (principal instanceof ApplicationUser) {
            ApplicationUser user = (ApplicationUser) principal;
            Map<String, Object> map = new LinkedHashMap<>();
            map.put(USER_ID, user.getId());
            map.put(USERNAME, authentication.getName());
            map.put(EMAIL, user.getEmail());
            response.put(USER_ID, user.getId());
            response.put(USERNAME, map); // the key must use the USERNAME
        }
    }

}
