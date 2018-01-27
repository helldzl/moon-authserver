package org.moonframework.authorization;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.context.embedded.LocalServerPort;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.client.TestRestTemplate;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpMethod;
import org.springframework.http.RequestEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.net.URI;
import java.util.Map;

/**
 * <p>https://docs.spring.io/spring-boot/docs/1.5.9.RELEASE/reference/htmlsingle/#boot-features-testing-spring-boot-applications-working-with-random-ports</p>
 *
 * @author quzile
 * @version 1.0
 * @since 2018/1/27
 */
@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
public class OAuth2Tests {

    /**
     * Tests that use @SpringBootTest(webEnvironment=WebEnvironment.RANDOM_PORT) can also inject the actual port into a field using the @LocalServerPort annotation.
     */
    @LocalServerPort
    private int port;

    private TestRestTemplate template = new TestRestTemplate();

    private final String CLIENT_NAME = "music";
    private final String CLIENT_PASSWORD = "music";

    @SuppressWarnings("unchecked")
    @Test
    public void loginSucceeds() {
        System.out.println(String.format("PORT:%s", port));

        // REQUEST BODY
        MultiValueMap<String, String> request = new LinkedMultiValueMap<>();
        request.set("grant_type", "password");
        request.set("username", "reader1");
        request.set("password", "123");

        // POST
        URI uri = URI.create(String.format("http://localhost:%s/oauth/token", port));
        Map<String, Object> map = template
                .withBasicAuth(CLIENT_NAME, CLIENT_PASSWORD)
                .postForObject(uri, request, Map.class);
        System.out.println(map);

        // EXCHANGE
        RequestEntity<MultiValueMap<String, String>> requestEntity = new RequestEntity<>(request, null, HttpMethod.POST, uri);
        ResponseEntity<Map<String, Object>> response = template
                .withBasicAuth(CLIENT_NAME, CLIENT_PASSWORD)
                .exchange(requestEntity, new ParameterizedTypeReference<Map<String, Object>>() {
                });
        System.out.println(response);
    }

}
