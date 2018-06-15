package es.gob.clavefirma.client.jse;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

final class ClaveFirmaProviderMessages {

	private static final String BUNDLE_NAME = "clavefirmaprovidermessages"; //$NON-NLS-1$

	private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle(BUNDLE_NAME);

	private ClaveFirmaProviderMessages() {
		// No instanciable
	}

	static String getString(final String key) {
		try {
			return RESOURCE_BUNDLE.getString(key);
		}
		catch (final MissingResourceException e) {
			return '!' + key + '!';
		}
	}
}
