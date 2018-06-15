package es.gob.clavefirma.client.jse;

/** Error durante la gesti&oacute;n de un OTP.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class OtpManagerException extends Exception {

	private static final long serialVersionUID = 5300807179772249242L;

	/** Crea una excepci&oacute;n de error durante la gesti&oacute;n de un OTP.
	 * @param desc Descripci&oacute;n de la excepci&oacute;n.
	 * @param e Excepci&oacute;n de origen. */
	public OtpManagerException(final String desc, final Exception e) {
		super(desc, e);
	}

	/** Crea una excepci&oacute;n de error durante la gesti&oacute;n de un OTP.
	 * @param desc Descripci&oacute;n de la excepci&oacute;n. */
	public OtpManagerException(final String desc) {
		super(desc);
	}

}
