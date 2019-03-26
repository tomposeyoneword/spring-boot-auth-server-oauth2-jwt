package com.payfone.oauth;

import java.util.Arrays;
import java.util.Map;

import org.apache.commons.lang3.StringUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.config.annotation.configurers.ClientDetailsServiceConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configuration.AuthorizationServerConfigurerAdapter;
import org.springframework.security.oauth2.config.annotation.web.configuration.EnableAuthorizationServer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerEndpointsConfigurer;
import org.springframework.security.oauth2.config.annotation.web.configurers.AuthorizationServerSecurityConfigurer;
import org.springframework.security.oauth2.provider.ClientDetails;
import org.springframework.security.oauth2.provider.ClientDetailsService;
import org.springframework.security.oauth2.provider.TokenRequest;
import org.springframework.security.oauth2.provider.request.DefaultOAuth2RequestFactory;
import org.springframework.security.oauth2.provider.token.TokenEnhancer;
import org.springframework.security.oauth2.provider.token.TokenEnhancerChain;
import org.springframework.security.oauth2.provider.token.TokenStore;
import org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter;

@Configuration
@EnableAuthorizationServer
public class AuthorizationServerConfiguration extends AuthorizationServerConfigurerAdapter
{
    @Autowired
    private AuthenticationManager authenticationManager;

    @Autowired
    private TokenEnhancer tokenEnhancer;

    @Autowired
    private TokenStore jwtTokenStore;

    @Autowired
    private JwtAccessTokenConverter jwtAccessTokenConverter;

    @Autowired
    private PasswordEncoder passwordEncoder;

    @Autowired
    private UserDetailsService userDetailsService;

    @Autowired
    private ClientDetailsService clientDetailsService;

    @Override
    public void configure(AuthorizationServerSecurityConfigurer security) throws Exception
    {
        //security.tokenKeyAccess("permitAll()").checkTokenAccess("isAuthenticated()");
        //security.tokenKeyAccess("hasAuthority('ROLE_TRUSTED_CLIENT')").checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
        //security.allowFormAuthenticationForClients() .tokenKeyAccess("hasAuthority('ROLE_TRUSTED_CLIENT')") .checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");
        //security.tokenKeyAccess("permitAll()").checkTokenAccess("hasAuthority('ROLE_TRUSTED_CLIENT')");

        security.tokenKeyAccess("permitAll()")
                .checkTokenAccess("isAuthenticated()")
                .allowFormAuthenticationForClients(); // Allows us to get client_id (and client_secret, if applicable) from the request body
    }

    @Override
    public void configure(ClientDetailsServiceConfigurer clients) throws Exception
    {
        // These can by dynamically loaded via a DB.  e.g. clients.jdbc(dataSource()).passwordEncoder(passwordEncoder);
        // See example: https://www.baeldung.com/spring-security-oauth-dynamic-client-registration

        String clientId = "early_warning";
        String clientSecret = "early_warning_client_secret..."; // This would get sent as Basic Auth credentials
        //String clientSecret = ""; // This technique does not require Client Basic Auth
        String grantTypePassword = "password";
        String authorizationCode = "authorization_code";
        String refreshToken = "refresh_token"; // This is how we get a refresh token returned
        String implicit = "implicit";
        String scopeRead = "read";
        String scopeWrite = "write";
        String trust = "trust";

        clients.inMemory()
                .withClient(clientId)
                .secret(passwordEncoder.encode(clientSecret))
                .scopes(scopeRead, scopeWrite, trust)
                .authorizedGrantTypes(grantTypePassword, refreshToken, authorizationCode, implicit)//, authorizationCode, implicit
                .authorities("ROLE_CLIENT", "ROLE_TRUSTED_CLIENT")
                .accessTokenValiditySeconds(120) //Access token is only valid for 2 minutes.
                .refreshTokenValiditySeconds(600); //Refresh token is only valid for 10 minutes.
    }

    @Override
    public void configure(AuthorizationServerEndpointsConfigurer endpoints) throws Exception
    {
        TokenEnhancerChain chain = new TokenEnhancerChain();
        chain.setTokenEnhancers(Arrays.asList(tokenEnhancer, jwtAccessTokenConverter));
        //endpoints.pathMapping("/oauth/token", "/oauth/jwt")
        endpoints.tokenStore(jwtTokenStore)
                .tokenEnhancer(chain)
                .authenticationManager(authenticationManager)
                .requestFactory(new PayfoneOAuth2RequestFactory(clientDetailsService));
        //.userDetailsService(userDetailsService);
    }

    private class PayfoneOAuth2RequestFactory extends DefaultOAuth2RequestFactory
    {
        // The ResourceOwnerPasswordTokenGranter specifically looks for "username" and "password".
        // I am allowing the use of "sub_client_id" and "sub_client_secret" in the web request
        // This OAuth2RequestFactory was the only place I found to swap out the variable names,
        // such that the ResourceOwnerPasswordTokenGranter can grab "username" and "password".

        private static final String USERNAME = "username";
        private static final String SUB_CLIENT_ID = "sub_client_id";

        private static final String PASSWORD = "password";
        private static final String SUB_CLIENT_SECRET = "sub_client_secret";

        public PayfoneOAuth2RequestFactory(ClientDetailsService clientDetailsService)
        {
            super(clientDetailsService);
        }

        @Override
        public TokenRequest createTokenRequest(Map<String, String> requestParameters, ClientDetails authenticatedClient)
        {
            // Hot swap the request parameter names and values with those expected by ResourceOwnerPasswordTokenGranter

            String subClientId = requestParameters.get(SUB_CLIENT_ID);
            if (StringUtils.isNotBlank(subClientId))
            {
                requestParameters.put(USERNAME, subClientId);
                requestParameters.remove(SUB_CLIENT_ID);
            }

            String subClientSecret = requestParameters.get(SUB_CLIENT_SECRET);
            if (StringUtils.isNotBlank(subClientSecret))
            {
                requestParameters.put(PASSWORD, subClientSecret);
                requestParameters.remove(SUB_CLIENT_SECRET);
            }
            return super.createTokenRequest(requestParameters, authenticatedClient);
        }
    }
}
