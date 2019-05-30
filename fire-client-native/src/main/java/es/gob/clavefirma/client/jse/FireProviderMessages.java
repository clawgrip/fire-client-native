package es.gob.clavefirma.client.jse;

import java.util.MissingResourceException;
import java.util.ResourceBundle;
import java.util.logging.Logger;

final class FireProviderMessages {

	private static final String BUNDLE_NAME = "fireprovidermessages"; //$NON-NLS-1$

	private static final ResourceBundle RESOURCE_BUNDLE = ResourceBundle.getBundle(BUNDLE_NAME);

	private FireProviderMessages() {
		// No instanciable
	}

	static String getString(final String key) {
		try {
			return RESOURCE_BUNDLE.getString(key);
		}
		catch (final MissingResourceException e) {
			Logger.getLogger(FireProviderMessages.class.getName()).severe(
				"Recurso textual no encontrado ('" + key + "'): " + e //$NON-NLS-1$ //$NON-NLS-2$
			);
			return '!' + key + '!';
		}
	}
}
