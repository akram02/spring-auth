package info.nitex.auth.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = "application", ignoreUnknownFields = false)
public class ApplicationProperties {
    private String baseUrl;
    private String fromMail;
    private String base64Secret;
    private Long tokenValidityInSeconds;
    private Long tokenValidityInSecondsForRememberMe;

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public String getFromMail() {
        return fromMail;
    }

    public void setFromMail(String fromMail) {
        this.fromMail = fromMail;
    }

    public String getBase64Secret() {
        return base64Secret;
    }

    public void setBase64Secret(String base64Secret) {
        this.base64Secret = base64Secret;
    }

    public Long getTokenValidityInSeconds() {
        return tokenValidityInSeconds;
    }

    public void setTokenValidityInSeconds(Long tokenValidityInSeconds) {
        this.tokenValidityInSeconds = tokenValidityInSeconds;
    }

    public Long getTokenValidityInSecondsForRememberMe() {
        return tokenValidityInSecondsForRememberMe;
    }

    public void setTokenValidityInSecondsForRememberMe(Long tokenValidityInSecondsForRememberMe) {
        this.tokenValidityInSecondsForRememberMe = tokenValidityInSecondsForRememberMe;
    }
}
