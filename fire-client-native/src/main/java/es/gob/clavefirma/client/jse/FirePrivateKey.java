package es.gob.clavefirma.client.jse;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPrivateKey;

import javax.security.auth.callback.CallbackHandler;

/** Clave privada de una entrada en ClaveFirma.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class FirePrivateKey implements RSAPrivateKey {

	private static final long serialVersionUID = 8103818384360324450L;

	private final String appId;
	private final String subjectId;
	private final X509Certificate cert;
	private final CallbackHandler ch;

	FirePrivateKey(final String app,
			             final String subject,
			             final X509Certificate c,
			             final CallbackHandler handler) {
		if (handler == null) {
			throw new IllegalArgumentException(
				"El CallbackHandler no puede ser nulo" //$NON-NLS-1$
			);
		}
		this.appId = app;
		this.subjectId = subject;
		this.cert = c;
		this.ch = handler;
	}

	CallbackHandler getCallbackHandler() {
		return this.ch;
	}

	String getAppId() {
		return this.appId;
	}

	String getSubjectId() {
		return this.subjectId;
	}

	X509Certificate getCertificate() {
		return this.cert;
	}

	@Override
	public String getAlgorithm() {
		return this.cert.getPublicKey().getAlgorithm();
	}

	@Override
	public byte[] getEncoded() {
		return null;
	}

	@Override
	public String getFormat() {
		return null;
	}

	@Override
	public BigInteger getModulus() {
		throw new UnsupportedOperationException();
	}

	@Override
	public BigInteger getPrivateExponent() {
		throw new UnsupportedOperationException();
	}

}
