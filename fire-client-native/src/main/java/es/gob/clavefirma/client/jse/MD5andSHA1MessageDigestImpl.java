package es.gob.clavefirma.client.jse;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigest;
import java.security.MessageDigestSpi;
import java.security.NoSuchAlgorithmException;

/** Implementaci&oacute;n de la huella digital "MD5andSHA1" tal y como la necesita TLS
 * (una concatenaci&oacute;n de huellas en estos dos formatos).
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class MD5andSHA1MessageDigestImpl extends MessageDigestSpi {

	private static final ByteArrayOutputStream BUFFER = new ByteArrayOutputStream();
	private static final MessageDigest MD_MD5;
	private static final MessageDigest MD_SHA1;
	static {
		try {
			MD_MD5 = MessageDigest.getInstance("MD5"); //$NON-NLS-1$
		}
		catch (final NoSuchAlgorithmException e) {
			throw new IllegalStateException("El sistema no soporta MD5: " + e, e); //$NON-NLS-1$
		}
		try {
			MD_SHA1 = MessageDigest.getInstance("SHA-1"); //$NON-NLS-1$
		}
		catch (final NoSuchAlgorithmException e) {
			throw new IllegalStateException("El sistema no soporta SHA-1: " + e, e); //$NON-NLS-1$
		}
	}

	@Override
	protected byte[] engineDigest() {
		final byte[] data = BUFFER.toByteArray();
		final byte[] a = MD_MD5.digest(data);
		final byte[] b = MD_SHA1.digest(data);
		final byte[] c = new byte[a.length + b.length];
		System.arraycopy(a, 0, c, 0, a.length);
		System.arraycopy(b, 0, c, a.length, b.length);
		return c;
	}

	@Override
	protected void engineReset() {
		BUFFER.reset();
	}

	@Override
	protected void engineUpdate(final byte b) {
		BUFFER.write(b);

	}

	@Override
	protected void engineUpdate(final byte[] b, final int off, final int len) {
		BUFFER.write(b, off, len);
	}

}
