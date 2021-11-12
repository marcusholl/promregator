package org.cloudfoundry.promregator.config.validations;

import static org.apache.commons.lang3.StringUtils.isBlank;

import java.util.ArrayList;
import java.util.List;

import org.apache.commons.lang3.StringUtils;
import org.cloudfoundry.promregator.config.AuthenticatorConfiguration;
import org.cloudfoundry.promregator.config.BasicAuthenticationConfiguration;
import org.cloudfoundry.promregator.config.OAuth2XSUAABasicAuthenticationConfiguration;
import org.cloudfoundry.promregator.config.OAuth2XSUAACertificateAuthenticationConfiguration;
import org.cloudfoundry.promregator.config.PromregatorConfiguration;
import org.cloudfoundry.promregator.config.TargetAuthenticatorConfiguration;
import org.springframework.stereotype.Component;

@Component
public class AuthenticationConfigurationValidator implements ConfigurationValidation {

	@Override
	public String validate(PromregatorConfiguration promregatorConfiguration) {
		List<String> validationFailures = new ArrayList<>();
		validate(promregatorConfiguration.getAuthenticator(), validationFailures);
		for (TargetAuthenticatorConfiguration tac : promregatorConfiguration
				.getTargetAuthenticators()) {
			validate(tac, validationFailures);
		}
		return validationFailures.isEmpty() ? null : StringUtils.join(validationFailures, ", ");
	}

	private static void validate(AuthenticatorConfiguration authConfig, List<String> validationFailures) {
		boolean validConfigFound = false;
		if (authConfig.getBasic() != null && validateBasicAuthConfig(authConfig.getBasic(), validationFailures)) {
			validConfigFound = true;
		}
		if (authConfig.getOauth2xsuaa() != null && validateOauth2xsuaaBasic(authConfig.getOauth2xsuaa(), validationFailures)) {
			validConfigFound = true;
		}
		if (authConfig.getOauth2xsuaaBasic() != null && validateOauth2xsuaaBasic(authConfig.getOauth2xsuaaBasic(), validationFailures)) {
			validConfigFound = true;
		}
		if (authConfig.getOauth2xsuaaCertificate() != null && validateOauth2xsuaaCertificate(authConfig.getOauth2xsuaaCertificate(), validationFailures)) {
			validConfigFound = true;
		}
		if (validConfigFound) {
			validationFailures.clear();
		}
	}

	private static boolean validateBasicAuthConfig(BasicAuthenticationConfiguration config,
			List<String> validationFailures) {
		boolean isValid = true;
		if (isBlank(config.getUsername())) {
			isValid = false;
			validationFailures.add(String.format("%s without username found", config.getClass().getSimpleName()));
		}
		if (isBlank(config.getPassword())) {
			isValid = false;
			validationFailures.add(String.format("%s without password found", config.getClass().getSimpleName()));
		}
		return isValid;
	}

	private static boolean validateOauth2xsuaaBasic(OAuth2XSUAABasicAuthenticationConfiguration config,
			List<String> validationFailures) {
		boolean isValid = true;
		if (isBlank(config.getClient_id())) {
			isValid = false;
			validationFailures.add(String.format("%s without client id found", config.getClass().getSimpleName()));
		}
		if (isBlank(config.getClient_secret())) {
			isValid = false;
			validationFailures.add(String.format("%s without client secret found", config.getClass().getSimpleName()));
		}
		if (isBlank(config.getTokenServiceURL())) {
			isValid = false;
			validationFailures
					.add(String.format("%s without token service url found", config.getClass().getSimpleName()));
		}
		return isValid;
	}

	private static boolean validateOauth2xsuaaCertificate(OAuth2XSUAACertificateAuthenticationConfiguration config,
			List<String> validationFailures) {
		boolean isValid = true;
		if (isBlank(config.getClient_id())) {
			isValid = false;
			validationFailures
					.add(String.format("%s auth config without client id found", config.getClass().getSimpleName()));
		}
		if (isBlank(config.getClient_certificates())) {
			isValid = false;
			validationFailures
					.add(String.format("%s without client certificate found", config.getClass().getSimpleName()));
		}
		if (isBlank(config.getClient_key())) {
			validationFailures.add(String.format("%s without client key found", config.getClass().getSimpleName()));
		}
		if (isBlank(config.getTokenServiceCertURL())) {
			isValid = false;
			validationFailures.add(
					String.format("%s without token service certificate URL found", config.getClass().getSimpleName()));
		}
		return isValid;
	}
}
