package es.gob.clavefirma.client.jse;

import java.io.ByteArrayOutputStream;
import java.security.MessageDigestSpi;

/** Implementaci&oacute;n de la huella digital "NONE".
 * Realmente no hace nada, devuelve los mismos datos que le llegan.
 * @author Raquel Cuevas
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class NoneMessageDigestImpl extends MessageDigestSpi {

	final ByteArrayOutputStream baos = new ByteArrayOutputStream();

	@Override
	protected byte[] engineDigest() {
		return this.baos.toByteArray();
	}

	@Override
	protected void engineReset() {
		this.baos.reset();
	}

	@Override
	protected void engineUpdate(final byte b) {
		this.baos.write(b);
	}

	@Override
	protected void engineUpdate(final byte[] input, final int offset, final int len) {
		this.baos.write(input, offset, len);
	}

}
