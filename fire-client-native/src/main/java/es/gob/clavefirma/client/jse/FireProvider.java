package es.gob.clavefirma.client.jse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Provider;
import java.util.Properties;

/** Proveedor JSE (<code>KeyStore</code> y <code>Signature</code>) para ClaveFirma.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class FireProvider extends Provider {

	private static final long serialVersionUID = -2291959557760084483L;

	private static final String INFO = "Proveedor para FIRe"; //$NON-NLS-1$
	private static final double VERSION = 0.1d;

    /** Nombre del proveedor. */
    public static final String NAME = "FireJCAProvider"; //$NON-NLS-1$

    private static final String FIRE_PRIVATE_KEY = "es.gob.clavefirma.client.jse.FirePrivateKey"; //$NON-NLS-1$

    private static final String SHA512WITH_RSA   = "SHA512withRSA"; //$NON-NLS-1$
    private static final String SHA384WITH_RSA   = "SHA384withRSA"; //$NON-NLS-1$
    private static final String SHA256WITH_RSA   = "SHA256withRSA"; //$NON-NLS-1$
    private static final String SHA1WITH_RSA     = "SHA1withRSA"; //$NON-NLS-1$
    private static final String SHA256WITH_ECDSA = "SHA256withECDSA"; //$NON-NLS-1$
    private static final String SHA384WITH_ECDSA = "SHA384withECDSA"; //$NON-NLS-1$
    private static final String SHA512WITH_ECDSA = "SHA512withECDSA"; //$NON-NLS-1$

    /** Nombre del almac&eacute;n de claves. */
    public static final String KEYSTORE_NAME = "FIRE"; //$NON-NLS-1$

	/** Construye el proveedor JSE (<code>KeyStore</code> y <code>Signature</code>) para ClaveFirma. */
	public FireProvider() {
		super(NAME, VERSION, INFO);

		// MessageDigest
		put("MessageDigest.NONE",       "es.gob.clavefirma.client.jse.NoneMessageDigestImpl"); //$NON-NLS-1$ //$NON-NLS-2$
		put("MessageDigest.MD5andSHA1", "es.gob.clavefirma.client.jse.MD5andSHA1MessageDigestImpl"); //$NON-NLS-1$ //$NON-NLS-2$

        // KeyStore
        put("KeyStore.FIRE", "es.gob.clavefirma.client.jse.FireKeyStoreImpl"); //$NON-NLS-1$ //$NON-NLS-2$

        // Motores de firma
        put("Signature.SHA1withRSA",       "es.gob.clavefirma.client.jse.FireSignatureImpl$Sha1"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA256withRSA",     "es.gob.clavefirma.client.jse.FireSignatureImpl$Sha256"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA384withRSA",     "es.gob.clavefirma.client.jse.FireSignatureImpl$Sha384"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA512withRSA",     "es.gob.clavefirma.client.jse.FireSignatureImpl$Sha512"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.MD5andSHA1withRSA", "es.gob.clavefirma.client.jse.FireSignatureImpl$MD5andSHA1"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA256withECDSA",   "es.gob.clavefirma.client.jse.FireSignatureImpl$Sha256Ecdsa"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA384withECDSA",   "es.gob.clavefirma.client.jse.FireSignatureImpl$Sha384Ecdsa"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.SHA512withECDSA",   "es.gob.clavefirma.client.jse.FireSignatureImpl$Sha512Ecdsa"); //$NON-NLS-1$ //$NON-NLS-2$
        put("Signature.NONEwithECDSA",     "es.gob.clavefirma.client.jse.FireSignatureImpl$NoneEcdsa"); //$NON-NLS-1$ //$NON-NLS-2$

        // Claves soportadas
        put("Signature.SHA1withRSA SupportedKeyClasses",       FIRE_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA256withRSA SupportedKeyClasses",     FIRE_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA384withRSA SupportedKeyClasses",     FIRE_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA512withRSA SupportedKeyClasses",     FIRE_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.MD5andSHA1withRSA SupportedKeyClasses", FIRE_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA256withECDSA SupportedKeyClasses",   FIRE_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA384withECDSA SupportedKeyClasses",   FIRE_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.SHA512withECDSA SupportedKeyClasses",   FIRE_PRIVATE_KEY); //$NON-NLS-1$
        put("Signature.NONEwithECDSA SupportedKeyClasses",     FIRE_PRIVATE_KEY); //$NON-NLS-1$

        // Alias de los nombres de algoritmos de firma
        put("Alg.Alias.Signature.1.2.840.113549.1.1.5",       SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.5",   SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.1.3.14.3.2.29",              SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHAwithRSA",                 SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-1withRSA",               SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA1withRSAEncryption",      SHA1WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-1withRSAEncryption",     SHA1WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.113549.1.1.11",      SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.11",  SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-256withRSA",             SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-256withRSAEncryption",   SHA256WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA256withRSAEncryption",    SHA256WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.113549.1.1.12",      SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.12",  SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-384withRSA",             SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-384withRSAEncryption",   SHA384WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA384withRSAEncryption",    SHA384WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.113549.1.1.13",      SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.113549.1.1.13",  SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-512withRSA",             SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-512withRSAEncryption",   SHA512WITH_RSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA512withRSAEncryption",    SHA512WITH_RSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.10045.4.3.2",        SHA256WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.2",    SHA256WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-256withECDSA",           SHA256WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-256withECDSAEncryption", SHA256WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA256withECDSAEncryption",  SHA256WITH_ECDSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.10045.4.3.3",        SHA384WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.3",    SHA384WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-384withECDSA",           SHA384WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-384withECDSAEncryption", SHA384WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA384withECDSAEncryption",  SHA384WITH_ECDSA); //$NON-NLS-1$

        put("Alg.Alias.Signature.1.2.840.10045.4.3.4",        SHA512WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.OID.1.2.840.10045.4.3.4",    SHA512WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-512withECDSA",           SHA512WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA-512withECDSAEncryption", SHA512WITH_ECDSA); //$NON-NLS-1$
        put("Alg.Alias.Signature.SHA512withECDSAEncryption",  SHA512WITH_ECDSA); //$NON-NLS-1$

	}

	private static String retrieveServerUrl = null;
	private static String storageServerUrl = null;
	private static String appId = null;
	private static String otpManagerClassName;

	//@Override
	/** Configura el proveedor (est&aacute;ndar en Java 9).
	 * @param config Configuraci&oacute;n del proveedor (en formato <code>Properties</code>).
	 * @return Proveedor configurado. */
	public Provider configure(final String config) {
		if (config == null) {
			throw new IllegalArgumentException(
				"La configuracion no puede ser nula" //$NON-NLS-1$
			);
		}
		final Properties cfg = new Properties();
		try {
			cfg.load(new ByteArrayInputStream(config.getBytes()));
		}
		catch (final IOException e) {
			throw new IllegalArgumentException(
				"La configuracion proporcionada no puede cargarse: " + e //$NON-NLS-1$
			);
		}

		retrieveServerUrl =  cfg.getProperty("retrieveServerUrl"); //$NON-NLS-1$
		storageServerUrl = cfg.getProperty("storageServerUrl"); //$NON-NLS-1$
		appId = cfg.getProperty("appId"); //$NON-NLS-1$
		otpManagerClassName = cfg.getProperty("otpManager"); //$NON-NLS-1$

		return this;
	}

	/** Obtiene nombre de clase del gestor de OTP.
	 * @return Nombre de clase del gestor de OTP. */
	public static String getOtpManagerClassName() {
		return otpManagerClassName;
	}

	/** Obtiene la URL de almac&ecute;n de datos del servidor intermedio.
	 * @return URL de almac&ecute;n de datos del servidor intermedio. */
	public static String getStorageServerUrl() {
		if (storageServerUrl == null) {
			throw new IllegalStateException(
				"El proveedor no esta configurado" //$NON-NLS-1$
			);
		}
		return storageServerUrl;
	}

	/** Obtiene la URL de recuperaci&oacute;n de datos del servidor intermedio.
	 * @return URL de recuperaci&oacute;n de datos del servidor intermedio. */
	public static String getRetrieveServerUrl() {
		if (retrieveServerUrl == null) {
			throw new IllegalStateException(
				"El proveedor no esta configurado" //$NON-NLS-1$
			);
		}
		return retrieveServerUrl;
	}

	/** Obtiene el identificador de aplicacion en ClaveFirma.
	 * @return Identificador de aplicacion en ClaveFirma. */
	public static String getAppId() {
		if (appId == null) {
			throw new IllegalStateException(
				"El proveedor no esta configurado" //$NON-NLS-1$
			);
		}
		return appId;
	}

}
