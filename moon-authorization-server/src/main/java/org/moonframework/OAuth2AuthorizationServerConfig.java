package org.moonframework;

import org.moonframework.authorization.ApplicationUserAuthenticationConverter;
import org.moonframework.authorization.filter.TokenFilter;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Primary;
import org.springframework.core.io.ClassPathResource;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.client.JdbcClientDetailsService;
import org.springframework.security.oauth2.provider.token.DefaultAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.DefaultTokenServices;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;
import org.springframework.security.oauth2.provider.token.store.JwtTokenStore;
import org.springframework.security.oauth2.provider.token.store.KeyStoreKeyFactory;

import javax.sql.DataSource;

/**
 * <p>The @EnableAuthorizationServer annotation is used to configure the OAuth 2.0 Authorization Server mechanism, together with any @Beans that implement AuthorizationServerConfigurer (there is a handy adapter implementation with empty methods). The following features are delegated to separate configurers that are created by Spring and passed into the AuthorizationServerConfigurer:</p>
 * <p>To switch off the auto-configuration and configure the Authorization Server features yourself just add a @Bean of type AuthorizationServerConfigurer.</p>
 * <p><code>curl client:secret@localhost:8080/oauth/token -d grant_type=password -d username=user -d password=pwd</code></p>
 * <p>OAuth2 resources are protected by a filter chain with order security.oauth2.resource.filter-order and the default is after the filter protecting the actuator endpoints by default (so actuator endpoints will stay on HTTP Basic unless you change the order).</p>
 * <ol>
 * <li>{@link org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer} : a configurer that defines the client details service. Client details can be initialized, or you can just refer to an existing store.</li>
 * <li>{@link org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer} : defines the security constraints on the token endpoint.</li>
 * <li>{@link org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer} : defines the authorization and token endpoints and the token services.</li>
 * </ol>
 * <p>
 * <a href='https://projects.spring.io/spring-security-oauth/docs/oauth2.html'>oauth 2.0<a/>
 */
@Configuration
@EnableAuthorizationServer
public class OAuth2AuthorizationServerConfig extends AuthorizationServerConfigurerAdapter {

    private final AuthenticationManager authenticationManager;

    private final UserDetailsService userDetailsService;

    private final DataSource dataSource;

    @Autowired
    public OAuth2AuthorizationServerConfig(AuthenticationManager authenticationManager, UserDetailsService userDetailsService, @Qualifier("dataSource") DataSource dataSource) {
        this.authenticationManager = authenticationManager;
        this.userDetailsService = userDetailsService;
        this.dataSource = dataSource;
    }

    /**
     * <p>The public key (if available) is exposed by the Authorization Server on the /oauth/token_key endpoint, which is secure by default with access rule "denyAll()". You can open it up by injecting a standard SpEL expression into the AuthorizationServerSecurityConfigurer (e.g. "permitAll()" is probably adequate since it is a public key).</p>
     *
     * @param security security
     * @throws Exception Exception
     */
    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception {
        security
                .tokenKeyAccess("permitAll()")
                .checkTokenAccess("permitAll()")
                .addTokenEndpointAuthenticationFilter(new TokenFilter());
    }

    /**
     * <p>A configurer that defines the client details service. Client details can be initialized, or you can just refer to an existing store.</p>
     * <p>NOTE: the schema for the JDBC service is not packaged with the library (because there are too many variations you might like to use in practice), but there is an example you can start from in the test code in github.</p>
     *
     * @param clients clients
     * @throws Exception Exception
     */
    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception {
        clients

                //.withClientDetails(clientDetails());

                .inMemory()
                .withClient("music")
                .secret("music")
                .scopes("read", "write")
                .autoApprove(true)
                .authorities("ROLE_USER_1", "ROLE_ADMIN_1", "ROLE_TRUST_1")
                .accessTokenValiditySeconds(60)
                .refreshTokenValiditySeconds(7 * 24 * 3600)
                .authorizedGrantTypes("implicit", "refresh_token", "password", "authorization_code");
    }

    /**
     * <p>The grant types supported by the AuthorizationEndpoint can be configured via the AuthorizationServerEndpointsConfigurer. By default all grant types are supported except password (see below for details of how to switch it on). The following properties affect grant types:</p>
     * <ol>
     * <li>authenticationManager: password grants are switched on by injecting an AuthenticationManager.</li>
     * <li>userDetailsService: if you inject a UserDetailsService or if one is configured globally anyway (e.g. in a GlobalAuthenticationManagerConfigurer) then a refresh token grant will contain a check on the user details, to ensure that the account is still active</li>
     * <li>authorizationCodeServices: defines the authorization code services (instance of AuthorizationCodeServices) for the auth code grant.</li>
     * <li>implicitGrantService: manages state during the imlpicit grant.</li>
     * <li>tokenGranter: the TokenGranter (taking full control of the granting and ignoring the other properties above)</li>
     * </ol>
     * <p>
     * <p>Configuring the Endpoint URLs</p>
     * <ol>
     * <li>The URL paths provided by the framework are /oauth/authorize (the authorization endpoint)</li>
     * <li>/oauth/token (the token endpoint), /oauth/confirm_access (user posts approval for grants here)</li>
     * <li>/oauth/error (used to render errors in the authorization server), /oauth/check_token (used by Resource Servers to decode access tokens)</li>
     * <li>/oauth/token_key (exposes public key for token verification if using JWT tokens)</li>
     * </ol>
     *
     * @param endpoints endpoints
     * @throws Exception Exception
     */
    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception {
        endpoints
                .tokenServices(tokenServices())
        // .tokenStore(tokenStore())
        // .tokenEnhancer(jwtTokenEnhancer())
        ;

        // endpoints.addInterceptor();

        // authenticationManager: password grants are switched on by injecting an AuthenticationManager.
        endpoints.authenticationManager(authenticationManager);

        // refresh_token use user details service
        endpoints.userDetailsService(userDetailsService);
    }


    @Bean
    public ClientDetailsService clientDetails() {
        return new JdbcClientDetailsService(dataSource);
    }

    /**
     * <p>o use JWT tokens you need a JwtTokenStore in your Authorization Server. The Resource Server also needs to be able to decode the tokens so the JwtTokenStore has a dependency on a JwtAccessTokenConverter, and the same implementation is needed by both the Authorization Server and the Resource Server.</p>
     * <p>To use the JwtTokenStore you need "spring-security-jwt" on your classpath (you can find it in the same github repository as Spring OAuth but with a different release cycle).</p>
     *
     * @return TokenStore
     */
    @Bean
    public TokenStore tokenStore() {
        return new JwtTokenStore(jwtTokenEnhancer());
    }

    /**
     * <ol>
     * <li>keytool -genkeypair -alias jwt -keyalg RSA -keypass quzile1984 -keystore jwt.jks -storepass quzile1984</li>
     * <li>keytool -list -rfc --keystore jwt.jks | openssl x509 -inform pem -pubkey</li>
     * </ol>
     *
     * @return JwtAccessTokenConverter
     */
    @Bean
    protected JwtAccessTokenConverter jwtTokenEnhancer() {
        JwtAccessTokenConverter converter = new JwtAccessTokenConverter();

        // token converter
        DefaultAccessTokenConverter defaultAccessTokenConverter = new DefaultAccessTokenConverter();
        defaultAccessTokenConverter.setUserTokenConverter(new ApplicationUserAuthenticationConverter());
        converter.setAccessTokenConverter(defaultAccessTokenConverter);

        // key
        KeyStoreKeyFactory keyStoreKeyFactory = new KeyStoreKeyFactory(new ClassPathResource("jwt.jks"), "quzile1984".toCharArray());
        converter.setKeyPair(keyStoreKeyFactory.getKeyPair("jwt"));

        return converter;
    }

    /**
     * <p>The AuthorizationServerTokenServices interface defines the operations that are necessary to manage OAuth 2.0 tokens. Note the following:</p>
     * <ol>
     * <li>When an access token is created, the authentication must be stored so that resources accepting the access token can reference it later.</li>
     * <li>The access token is used to load the authentication that was used to authorize its creation.</li>
     * </ol>
     * <p>The default store is an in-memory implementation, but there are some other implementations available.</p>
     * <ol>
     * <li>The default InMemoryTokenStore is perfectly fine for a single server (i.e. low traffic and no hot swap to a backup server in the case of failure). Most projects can start here, and maybe operate this way in development mode, to make it easy to start a server with no dependencies.</li>
     * <li>The JdbcTokenStore is the JDBC version of the same thing, which stores token data in a relational database. Use the JDBC version if you can share a database between servers, either scaled up instances of the same server if there is only one, or the Authorization and Resources Servers if there are multiple components. To use the JdbcTokenStore you need "spring-jdbc" on the classpath.</li>
     * <li>The JSON Web Token (JWT) version of the store encodes all the data about the grant into the token itself (so no back end store at all which is a significant advantage). One disadvantage is that you can't easily revoke an access token, so they normally are granted with short expiry and the revocation is handled at the refresh token. Another disadvantage is that the tokens can get quite large if you are storing a lot of user credential information in them. The JwtTokenStore is not really a "store" in the sense that it doesn't persist any data, but it plays the same role of translating betweeen token values and authentication information in the DefaultTokenServices.</li>
     * </ol>
     *
     * @return DefaultTokenServices
     */
    @Bean
    @Primary
    public DefaultTokenServices tokenServices() {
        DefaultTokenServices defaultTokenServices = new DefaultTokenServices();
        defaultTokenServices.setTokenStore(tokenStore());
        defaultTokenServices.setTokenEnhancer(jwtTokenEnhancer());
        defaultTokenServices.setSupportRefreshToken(true);
        defaultTokenServices.setAccessTokenValiditySeconds(600);
        return defaultTokenServices;
    }

}
