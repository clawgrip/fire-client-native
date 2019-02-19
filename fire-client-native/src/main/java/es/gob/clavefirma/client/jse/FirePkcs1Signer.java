package es.gob.clavefirma.client.jse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Locale;
import java.util.Properties;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.AOInvalidFormatException;
import es.gob.afirma.core.signers.AOSignInfo;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.clavefirma.client.ClientConfigFilesNotFoundException;
import es.gob.clavefirma.client.HttpOperationException;
import es.gob.clavefirma.client.signprocess.HttpLoadProcess;
import es.gob.clavefirma.client.signprocess.HttpSignProcess;
import es.gob.clavefirma.client.signprocess.HttpSignProcessConstants.SignatureOperation;
import es.gob.clavefirma.client.signprocess.LoadResult;
import es.gob.fire.client.Base64;

/** Firmador PKCS#1 que delega el proceso en ClaveFirma.
 * @author Raquel Cuevas
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class FirePkcs1Signer implements AOSigner {

	private static final String PKCS1_FILE_SUFFIX = ".p1"; //$NON-NLS-1$

	private static final String SIG_OP = "sign"; //$NON-NLS-1$

	static {
		if (Security.getProvider(FireProvider.NAME) != null) {
			Security.addProvider(new FireProvider());
		}
	}

	@Override
	public byte[] cosign(final byte[] data,
			             final byte[] sign,
			             final String algorithm,
			             final PrivateKey key,
			             final Certificate[] certChain,
			             final Properties extraParams) throws AOException, IOException {
		throw new UnsupportedOperationException("No se pueden hacer cofirmas en PKCS#1"); //$NON-NLS-1$
	}

	@Override
	public byte[] cosign(final byte[] sign,
			             final String algorithm,
			             final PrivateKey key,
			             final Certificate[] certChain,
			             final Properties extraParams) throws AOException, IOException {
		throw new UnsupportedOperationException("No se pueden hacer cofirmas en PKCS#1"); //$NON-NLS-1$
	}

	@Override
	public byte[] countersign(final byte[] sign,
			                  final String algorithm,
			                  final CounterSignTarget targetType,
			                  final Object[] targets,
			                  final PrivateKey key,
			                  final Certificate[] certChain,
			                  final Properties extraParams) throws AOException, IOException {
		throw new UnsupportedOperationException("No se pueden hacer contrafirmas en PKCS#1"); //$NON-NLS-1$
	}

	@Override
	public byte[] sign(final byte[] data,
			           final String signatureAlgo,
			           final PrivateKey privateKey,
			           final Certificate[] certChain,
			           final Properties extraParams) throws AOException, IOException {

		if (privateKey == null) {
			throw new IllegalArgumentException(
				"La clave privada no puede ser nula" //$NON-NLS-1$
			);
		}
		if (!(privateKey instanceof FirePrivateKey)) {
			throw new IllegalArgumentException(
				"Tipo de clave privada no soportado: " + privateKey.getClass().getName() //$NON-NLS-1$
			);
		}
		if (certChain == null || certChain.length < 1) {
			throw new IllegalArgumentException(
				"Debe indicarse al menos un certificado en la cadena de firma" //$NON-NLS-1$
			);
		}

		final String sessionId = UUID.randomUUID().toString();

		final String retrieveServer = FireProvider.getRetrieveServerUrl();
		final String storageServer = FireProvider.getStorageServerUrl();

		final StringBuilder config = new StringBuilder();
		config.append("redirectOkUrl=" + storageServer + "?op=put&v=PEDO&id=" + sessionId + "&dat=OK\r\n"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		config.append("redirectErrorUrl=" + storageServer + "?op=put&v=PEDO&id=" + sessionId + "&dat=KO\r\n"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		final LoadResult res;
		try {
			res = HttpLoadProcess.loadData(
				((FirePrivateKey)privateKey).getAppId(),
				((FirePrivateKey)privateKey).getSubjectId(),
				SignatureOperation.SIGN.toString(),
				"NONE", //$NON-NLS-1$
				signatureAlgo,
				null, // ExtraParams
				Base64.encode(certChain[0].getEncoded()),
				Base64.encode(data),
				Base64.encode(config.toString().getBytes(StandardCharsets.UTF_8)) // Configuracion del servicio servidor
			);
		}
		catch (
			final CertificateEncodingException | HttpOperationException | ClientConfigFilesNotFoundException e) {
			throw new AOException(
				"Error cargando los datos a firmar: " + e, e //$NON-NLS-1$
			);
		}

		final PasswordCallback pwc = new PasswordCallback(
			FireProviderMessages.getString("FireSignatureImpl.0"), //$NON-NLS-1$
			false
		);

		try {
			((FirePrivateKey)privateKey).getCallbackHandler().handle(new Callback[] { pwc });
		}
		catch (IOException | UnsupportedCallbackException e2) {
			throw new AOException(
				"No se ha proporcionado un manejador que soporte un PasswordCallback: " + e2, e2 //$NON-NLS-1$
			);
		}

		final OtpManager otpManager;
		try {
			otpManager = (OtpManager) Class.forName(
				FireProvider.getOtpManagerClassName()
			).getConstructor().newInstance();
		}
		catch (
			final InstantiationException |
			IllegalAccessException       |
			IllegalArgumentException     |
			InvocationTargetException    |
			NoSuchMethodException        |
			SecurityException            |
			ClassNotFoundException e
		) {
			throw new IllegalStateException(
				"El gestor de OTP configurado ('" + FireProvider.getOtpManagerClassName() + "' no puede cargarse: " + e //$NON-NLS-1$ //$NON-NLS-2$
			);
		}

		// Configuramos el gestor de OTP con el ID de sesion y las URL de redireccion (OK y KO)
		final Properties otpManagerConfig = new Properties();
		try {
			otpManagerConfig.load(new ByteArrayInputStream(config.toString().getBytes()));
		}
		catch (final IOException e2) {
			throw new AOException(
				"Error configurando el gestor de OTP: " + e2, e2 //$NON-NLS-1$
			);
		}
		otpManagerConfig.put("transactionId", res.getTransactionId()); //$NON-NLS-1$

		try {
			otpManager.manageOtp(
				new String(pwc.getPassword()),
				retrieveServer,
				sessionId,
				res.getRedirectUrl(),
				otpManagerConfig
			);
		}
		catch (final OtpManagerException e1) {
			throw new AOException(
				"El OTP de firma no es valido: " + e1, e1 //$NON-NLS-1$
			);
		}

		// El OTP ha validado y tenemos los datos cargados... Solo queda firmar
		try {
			return HttpSignProcess.sign(
				((FirePrivateKey)privateKey).getAppId(),
				res.getTransactionId(),
				SIG_OP,
				"NONE", //$NON-NLS-1$
				signatureAlgo,
				null,
				Base64.encode(((FirePrivateKey)privateKey).getCertificate().getEncoded(), true),
				Base64.encode(data, true),
				Base64.encode(res.getTriphaseData().toString().getBytes(), true), // Datos trifasicos en Base64,
				null // Upgrade
			);
		}
		catch (final CertificateEncodingException |
				     HttpOperationException       |
				     ClientConfigFilesNotFoundException e) {
			throw new AOException(e);
		}

	}

	@Override
	public AOTreeModel getSignersStructure(final byte[] sign,
			                               final boolean asSimpleSignInfo) throws AOInvalidFormatException, IOException {
		throw new UnsupportedOperationException("No se puede obtener la estructura de firmantes en PKCS#1"); //$NON-NLS-1$
	}

	@Override
	public boolean isSign(final byte[] is) throws IOException {
		throw new UnsupportedOperationException("No se pueden detectar firmas PKCS#1"); //$NON-NLS-1$
	}

	@Override
	public boolean isValidDataFile(final byte[] is) throws IOException {
		return true;
	}

	@Override
	public String getSignedName(final String originalName, final String inText) {
        final String inTextInt = inText != null ? inText : ""; //$NON-NLS-1$
        if (originalName == null) {
            return "signature" + PKCS1_FILE_SUFFIX; //$NON-NLS-1$
        }
        if (originalName.toLowerCase(Locale.US).endsWith(PKCS1_FILE_SUFFIX)) {
            return originalName.substring(0, originalName.length() - PKCS1_FILE_SUFFIX.length()) + inTextInt + PKCS1_FILE_SUFFIX;
        }
        return originalName + inTextInt + PKCS1_FILE_SUFFIX;
	}

	@Override
	public byte[] getData(final byte[] signData) throws AOException, IOException {
		throw new UnsupportedOperationException("No se pueden obtener los datos firmados en PKCS#1"); //$NON-NLS-1$
	}

	@Override
	public AOSignInfo getSignInfo(final byte[] signData) throws AOException, IOException {
		throw new UnsupportedOperationException("No se puede obtener informacion de las firmas PKCS#1"); //$NON-NLS-1$
	}

}
