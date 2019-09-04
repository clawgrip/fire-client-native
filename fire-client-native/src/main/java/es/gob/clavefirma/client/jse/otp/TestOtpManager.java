package es.gob.clavefirma.client.jse.otp;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLEncoder;
import java.security.GeneralSecurityException;
import java.util.Properties;
import java.util.logging.Logger;

import es.gob.clavefirma.client.jse.OtpManager;
import es.gob.clavefirma.client.jse.OtpManagerException;
import es.gob.fire.client.HttpsConnection;
import es.gob.fire.client.HttpsConnection.Method;
import es.gob.fire.client.NetConnection;

/** <code>Callback</code> de pruebas para gesti&oacute;n del OTP.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestOtpManager implements OtpManager {

	private static final String PARAM_REDIR_OK = "redirectok"; //$NON-NLS-1$
	private static final String PARAM_REDIR_KO = "redirectko"; //$NON-NLS-1$
	private static final String PARAM_TRANS_ID = "transactionid"; //$NON-NLS-1$
	private static final String PARAM_PASSWORD = "password"; //$NON-NLS-1$

	private static final String PARAM_JOIN = "&"; //$NON-NLS-1$
	private static final String PARAM_EQUALS = "="; //$NON-NLS-1$

	private static final String OK = "OK"; //$NON-NLS-1$
	private static final String KO = "KO"; //$NON-NLS-1$

	private static final String POST_URL;
	static {
		final Properties p = new Properties();
		try {
			p.load(TestOtpManager.class.getResourceAsStream("/testotpmanager.properties")); //$NON-NLS-1$
		}
		catch (final IOException e) {
			throw new RuntimeException(
				"No se ha podido cargar la configuracion: " + e, e //$NON-NLS-1$
			);
		}
		POST_URL = p.getProperty("postUrl"); //$NON-NLS-1$
		if (POST_URL == null) {
			throw new RuntimeException(
				"La URL de configuracion del servicio es nula" //$NON-NLS-1$
			);
		}
		try {
			final URL url = new URL(POST_URL);
			Logger.getLogger(TestOtpManager.class.getName()).info(
				"URL de configuracion del servicio OTP de pruebas: " + url //$NON-NLS-1$
			);
		}
		catch (final MalformedURLException e) {
			throw new RuntimeException(
				"La URL de configuracion del servicio es invalida: " + e, e //$NON-NLS-1$
			);
		}
		Logger.getLogger(TestOtpManager.class.getName()).info(
			"Se usará el siguiente servicio OTP de pruebas: " + POST_URL //$NON-NLS-1$
		);
	}

	private static final String DEFAULT_ENCODING = "UTF-8"; //$NON-NLS-1$

	/** Construye una <code>Callback</code> de pruebas para gesti&oacute;n del OTP. */
	public TestOtpManager() {
		super();
	}

	@Override
	public void manageOtp(final String otpValue,
			              final String retrieveServerUrl,
			              final String retrieveServerSession,
			              final String redirectUrl,
			              final Properties cfg) throws OtpManagerException {

		final byte[] redirResponse;
		final NetConnection conn;
		try {
			conn = HttpsConnection.getConnection(new Properties(), null);
			redirResponse = conn.readUrl(redirectUrl, null, HttpsConnection.Method.GET);
		}
		catch (final IllegalArgumentException |
				     GeneralSecurityException |
				     IOException e) {
			throw new OtpManagerException(
				"No se ha podido acceder a la URL de redireccion: " + e, e //$NON-NLS-1$
			);
		}
		if (redirResponse == null) {
			throw new OtpManagerException(
				"No se ha podido leer la URL de redireccion" //$NON-NLS-1$
			);
		}

		final String transactionId;
		final String redirOk;
		final String redirKo;
		try {
			transactionId = URLEncoder.encode(cfg.getProperty("transactionId"), DEFAULT_ENCODING); //$NON-NLS-1$
			redirOk = URLEncoder.encode(cfg.getProperty("redirectOkUrl"),DEFAULT_ENCODING); //$NON-NLS-1$
			redirKo = URLEncoder.encode(cfg.getProperty("redirectErrorUrl"), DEFAULT_ENCODING); //$NON-NLS-1$
		}
		catch (final UnsupportedEncodingException e1) {
			throw new OtpManagerException(
				"No se han podido codificar los parametros del envio del OTP: " + e1, //$NON-NLS-1$
				e1
			);
		}
		catch(final NullPointerException e) {
			throw new OtpManagerException(
				"No se han proporcionado los datos necesarios en la configuracion: " + e, //$NON-NLS-1$
				e
			);
		}

		final byte[] otpRes;
		try {
			otpRes = conn.readUrl(
				POST_URL,
				PARAM_TRANS_ID + PARAM_EQUALS + transactionId + PARAM_JOIN +
					PARAM_REDIR_KO + PARAM_EQUALS + redirKo + PARAM_JOIN +
					PARAM_REDIR_OK + PARAM_EQUALS + redirOk + PARAM_JOIN +
					PARAM_PASSWORD + PARAM_EQUALS + otpValue,
				HttpsConnection.Method.GET
			);
		}
		catch (final IOException e) {
			throw new OtpManagerException(
				"El envio del OTP ha resultado en error: " + e, //$NON-NLS-1$
				e
			);
		}

		final String res = new String(otpRes).trim();

		if (!OK.equals(res)) {
			throw new OtpManagerException(
				"La operacion de guardado del resultado de validacion del OTP ha fallado: " + res //$NON-NLS-1$
			);
		}

		final byte[] finalRes;
		try {
			finalRes= conn.readUrl(
				retrieveServerUrl,
				"op=get&v=PEDO&id=" + retrieveServerSession, //$NON-NLS-1$
				Method.GET
			);
		}
		catch (final IOException e) {
			throw new OtpManagerException(
				"Error obteniendo el resultado de validacion del OTP: " + e, e //$NON-NLS-1$
			);
		}

		final String finalResult = new String(finalRes).trim();
		if (KO.equals(finalResult)) {
			throw new OtpManagerException(
				"El OTP es invalido" //$NON-NLS-1$
			);
		}
		else if (OK.equals(finalResult)) {
			return;
		}
		throw new OtpManagerException(
			"Respuesta incoherente tras el envio del OTP: " + finalResult //$NON-NLS-1$
		);
	}

}
