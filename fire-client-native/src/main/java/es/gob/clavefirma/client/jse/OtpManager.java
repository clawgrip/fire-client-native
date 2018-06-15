package es.gob.clavefirma.client.jse;

import java.util.Properties;

import javax.security.auth.callback.Callback;

/** Gestor del OTP.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public interface OtpManager extends Callback {

	/** Gestiona el OTP de autorizaci&oacute;n de firma.
	 * @param otpValue Valor del OTP.
	 * @param subjectId Identificador del firmante.
	 * @param retrieveServerUrl URL de recuperaci&oacute;n de datos del servidor intermedio.
	 * @param retrieveServerSession ID de sesi&oacute;n de recuperaci&oacute;n de datos del
	 *                              servidor intermedio.
	 * @param redirectUrl URL de redirecci&oacute;n donde introducir el OTP.
	 * @param cfg Configuraci&oacute;n del gestor.
	 * @throws OtpManagerException En cualquier error durante la gesti&oacute;n del OTP. */
	void manageOtp(final String otpValue,
                   final String retrieveServerUrl,
                   final String retrieveServerSession,
                   final String redirectUrl,
                   final Properties cfg) throws OtpManagerException;
}
