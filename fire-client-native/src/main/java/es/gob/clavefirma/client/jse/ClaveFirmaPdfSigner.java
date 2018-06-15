package es.gob.clavefirma.client.jse;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.security.Security;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.util.Properties;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.afirma.core.AOException;
import es.gob.afirma.core.AOInvalidFormatException;
import es.gob.afirma.core.misc.AOUtil;
import es.gob.afirma.core.signers.AOSignInfo;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.signers.CounterSignTarget;
import es.gob.afirma.core.util.tree.AOTreeModel;
import es.gob.afirma.signers.pades.AOPDFSigner;
import es.gob.clavefirma.client.ClientConfigFilesNotFoundException;
import es.gob.clavefirma.client.HttpOperationException;
import es.gob.clavefirma.client.signprocess.HttpLoadProcess;
import es.gob.clavefirma.client.signprocess.HttpSignProcess;
import es.gob.clavefirma.client.signprocess.HttpSignProcessConstants.SignatureOperation;
import es.gob.clavefirma.client.signprocess.LoadResult;
import es.gob.fire.client.Base64;

/** Firmador PDF que delega el proceso en ClaveFirma.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class ClaveFirmaPdfSigner implements AOSigner {

	private static final AOSigner pdfSigner = new AOPDFSigner();

	private static final String SIG_OP = "sign"; //$NON-NLS-1$

	static {
		if (Security.getProvider(ClaveFirmaProvider.NAME) != null) {
			Security.addProvider(new ClaveFirmaProvider());
		}
	}

	@Override
	public byte[] sign(final byte[] data,
			           final String signatureAlgo,
			           final PrivateKey privateKey,
			           final Certificate[] certChain,
			           final Properties extraParams) throws AOException,
	                                                        IOException {
		if (privateKey == null) {
			throw new IllegalArgumentException(
				"La clave privada no puede ser nula" //$NON-NLS-1$
			);
		}
		if (!(privateKey instanceof ClaveFirmaPrivateKey)) {
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

		final String retrieveServer = ClaveFirmaProvider.getRetrieveServerUrl();
		final String storageServer = ClaveFirmaProvider.getStorageServerUrl();

		final StringBuilder config = new StringBuilder();
		config.append("redirectOkUrl=" + storageServer + "?op=put&v=PEDO&id=" + sessionId + "&dat=OK\r\n"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		config.append("redirectErrorUrl=" + storageServer + "?op=put&v=PEDO&id=" + sessionId + "&dat=KO\r\n"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$

		final LoadResult res;
		try {
			res = HttpLoadProcess.loadData(
				((ClaveFirmaPrivateKey)privateKey).getAppId(),
				((ClaveFirmaPrivateKey)privateKey).getSubjectId(),
				SignatureOperation.SIGN.toString(),
				"PAdES", //$NON-NLS-1$
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
			ClaveFirmaProviderMessages.getString("ClaveFirmaPdfSigner.0"), //$NON-NLS-1$
			false
		);

		try {
			((ClaveFirmaPrivateKey)privateKey).getCallbackHandler().handle(new Callback[] { pwc });
		}
		catch (IOException | UnsupportedCallbackException e2) {
			throw new AOException(
				"No se ha proporcionado un manejador que soporte un PasswordCallback: " + e2, e2 //$NON-NLS-1$
			);
		}

		final OtpManager otpManager;
		try {
			otpManager = (OtpManager) Class.forName(
				ClaveFirmaProvider.getOtpManagerClassName()
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
				"El gestor de OTP configurado ('" + ClaveFirmaProvider.getOtpManagerClassName() + "' no puede cargarse: " + e //$NON-NLS-1$ //$NON-NLS-2$
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
				((ClaveFirmaPrivateKey)privateKey).getAppId(),
				res.getTransactionId(),
				SIG_OP,
				"PAdES", //$NON-NLS-1$
				signatureAlgo,
				AOUtil.properties2Base64(extraParams),
				Base64.encode(((ClaveFirmaPrivateKey)privateKey).getCertificate().getEncoded(), true),
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
	public byte[] cosign(final byte[] data,
			             final byte[] sign,
			             final String algorithm,
			             final PrivateKey key,
			             final Certificate[] certChain,
			             final Properties extraParams) throws AOException,
	                                                          IOException {
		return sign(
			data != null ? data : sign,
			algorithm,
			key,
			certChain,
			extraParams
		);
	}

	@Override
	public byte[] cosign(final byte[] sign,
			             final String algorithm,
			             final PrivateKey key,
			             final Certificate[] certChain,
			             final Properties extraParams) throws AOException,
	                                                          IOException {
		return sign(sign, algorithm, key, certChain, extraParams);
	}

	@Override
	public byte[] countersign(final byte[] sign,
			                  final String algorithm,
			                  final CounterSignTarget targetType,
			                  final Object[] targets,
			                  final PrivateKey key,
			                  final Certificate[] certChain,
			                  final Properties extraParams) throws AOException, IOException {
		throw new UnsupportedOperationException("Los PDF no admiten contrafirmas"); //$NON-NLS-1$
	}

	@Override
	public AOTreeModel getSignersStructure(final byte[] sign,
			                               final boolean asSimpleSignInfo) throws AOInvalidFormatException,
	                                                                              IOException {
		return pdfSigner.getSignersStructure(sign, asSimpleSignInfo);
	}

	@Override
	public boolean isSign(final byte[] is) throws IOException {
		return pdfSigner.isSign(is);
	}

	@Override
	public boolean isValidDataFile(final byte[] is) throws IOException {
		return pdfSigner.isValidDataFile(is);
	}

	@Override
	public String getSignedName(final String originalName, final String inText) {
		return pdfSigner.getSignedName(originalName, inText);
	}

	@Override
	public byte[] getData(final byte[] signData) throws AOException, IOException {
		return pdfSigner.getData(signData);
	}

	@Override
	public AOSignInfo getSignInfo(final byte[] signData) throws AOException, IOException {
		return getSignInfo(signData);
	}

}
