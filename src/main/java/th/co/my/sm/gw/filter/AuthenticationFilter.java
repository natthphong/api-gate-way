package th.co.my.sm.gw.filter;


import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

@Component
@Slf4j
public class AuthenticationFilter extends AbstractGatewayFilterFactory<AuthenticationFilter.Config> {

    @Autowired
    private RouteValidator validator;

    //    @Autowired
//    private RestTemplate template;
    @Autowired
    private JwtUtil jwtUtil;

    public AuthenticationFilter() {
        super(Config.class);
    }

    @Override
    public GatewayFilter apply(Config config) {

        return ((exchange, chain) -> {
            if (validator.isSecured.test(exchange.getRequest())) {
                log.info("HELLO {}" );
                //header contains token or not
                if (!exchange.getRequest().getHeaders().containsKey(HttpHeaders.AUTHORIZATION)) {
                    throw new RuntimeException("missing authorization header");
                }

                String authHeader = exchange.getRequest().getHeaders().get(HttpHeaders.AUTHORIZATION).get(0);
                if (authHeader != null && authHeader.startsWith("Bearer ")) {
                    authHeader = authHeader.substring(7);
                }
                try {
//                    //REST call to AUTH service
//                    template.getForObject("http://IDENTITY-SERVICE//validate?token" + authHeader, String.class);
                    jwtUtil.validateToken(authHeader);

                } catch (Exception e) {
                    System.out.println("invalid access...!");
                    throw new RuntimeException("un authorized access to application");
                }
            }
//            exchange.getRequest().getHeaders().set();

            log.info("chain {}" );
            return chain.filter(exchange).then(Mono.fromRunnable(()->{
                log.info("post getLogPrefix {}" , exchange.getLogPrefix());
                List<Map.Entry<String, Object>> list = exchange.getAttributes().entrySet().stream().toList();
                log.info("post getAttributes {}" , list.get(4).getValue());
                log.info("post getApplicationContext {}" , exchange.getApplicationContext());
                log.info("post getLocaleContext {}" , exchange.getLocaleContext());
                log.info("post getPrincipal {}" , exchange.getPrincipal());
                log.info("post filter status {} ",exchange.getResponse());
            }));
        });
    }

    public static class Config {

    }
}
