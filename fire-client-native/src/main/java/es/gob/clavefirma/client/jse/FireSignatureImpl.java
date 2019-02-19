package es.gob.clavefirma.client.jse;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.lang.reflect.InvocationTargetException;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.SignatureSpi;
import java.security.cert.CertificateEncodingException;
import java.util.Properties;
import java.util.UUID;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.clavefirma.client.ClientConfigFilesNotFoundException;
import es.gob.clavefirma.client.HttpOperationException;
import es.gob.clavefirma.client.signprocess.HttpLoadProcess;
import es.gob.clavefirma.client.signprocess.HttpSignProcess;
import es.gob.clavefirma.client.signprocess.HttpSignProcessConstants.SignatureOperation;
import es.gob.clavefirma.client.signprocess.LoadResult;
import es.gob.fire.client.Base64;

/** Implementaci&oacute;n de firma basado en ClaveFirma.
 * Realiza firmas RSA con relleno PKCS#1 v1.5. Se soportan los siguientes algoritmos de firma:
 * <ul>
 *  <li>SHA1withRSA</li>
 *  <li>SHA256withRSA</li>
 *  <li>SHA384withRSA</li>
 *  <li>SHA512withRSA</li>
 * </ul>
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s */
public class FireSignatureImpl extends SignatureSpi {

	private static final String SIG_FORMAT_PKCS1 = "NONE"; //$NON-NLS-1$

	private static final String SIG_OP = "sign"; //$NON-NLS-1$

	private final ByteArrayOutputStream data = new ByteArrayOutputStream();

	private FirePrivateKey privateKey = null;

    private final String signatureAlgo;
    private final String signatureFormat;

    FireSignatureImpl(final String signatureAlgorithm) {
        super();
        this.signatureAlgo = signatureAlgorithm;
        this.signatureFormat = SIG_FORMAT_PKCS1;
    }

	@Override
	protected byte[] engineSign() throws SignatureException {

		if (this.privateKey == null) {
			throw new SignatureException(
				"No se ha inicializado la clave privada de firma" //$NON-NLS-1$
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
				this.privateKey.getAppId(),
				this.privateKey.getSubjectId(),
				SignatureOperation.SIGN.toString(),
				this.signatureFormat,
				this.signatureAlgo,
				null, // ExtraParams
				Base64.encode(this.privateKey.getCertificate().getEncoded()),
				Base64.encode(this.data.toByteArray()),
				Base64.encode(config.toString().getBytes(StandardCharsets.UTF_8)) // Configuracion del servicio servidor
			);
		}
		catch (final CertificateEncodingException | HttpOperationException | ClientConfigFilesNotFoundException e) {
			throw new SignatureException(
				"Error cargando los datos a firmar: " + e, e //$NON-NLS-1$
			);
		}

		final PasswordCallback pwc = new PasswordCallback(
			FireProviderMessages.getString("FireSignatureImpl.0"), //$NON-NLS-1$
			false
		);

		try {
			this.privateKey.getCallbackHandler().handle(new Callback[] { pwc });
		}
		catch (IOException | UnsupportedCallbackException e2) {
			throw new SignatureException(
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
			throw new SignatureException(
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
			throw new SignatureException(
				"El OTP de firma no es valido: " + e1, e1 //$NON-NLS-1$
			);
		}

		// El OTP ha validado y tenemos los datos cargados... Solo queda firmar
		try {
			return HttpSignProcess.sign(
				this.privateKey.getAppId(),
				res.getTransactionId(),
				SIG_OP,
				SIG_FORMAT_PKCS1,
				this.signatureAlgo,
				null,
				Base64.encode(this.privateKey.getCertificate().getEncoded(), true),
				Base64.encode(this.data.toByteArray(), true),
				Base64.encode(res.getTriphaseData().toString().getBytes(), true), // Datos trifasicos en Base64,
				null // Upgrade
			);
		}
		catch (final CertificateEncodingException |
				     HttpOperationException       |
				     ClientConfigFilesNotFoundException e) {
			throw new SignatureException(e);
		}
	}

	@Override
	protected void engineInitSign(final PrivateKey prKey) throws InvalidKeyException {
        if (prKey == null) {
            throw new InvalidKeyException("La clave proporcionada es nula"); //$NON-NLS-1$
        }
        if (!(prKey instanceof FirePrivateKey)) {
            throw new InvalidKeyException("La clave proporcionada no es de una tarjeta CERES: " + prKey.getClass().getName()); //$NON-NLS-1$
        }
        this.privateKey = (FirePrivateKey) prKey;
        this.data.reset();
	}

	@Override
	protected void engineUpdate(final byte b) throws SignatureException {
		this.data.write(b);
	}

	@Override
	protected void engineUpdate(final byte[] b, final int off, final int len) {
        this.data.write(b, off, len);
	}

    /** Firma SHA1withRSA. */
    public static final class Sha1 extends FireSignatureImpl {
        /** Constructor */
        public Sha1() {
            super("SHA1withRSA"); //$NON-NLS-1$
        }
    }

    /** Firma SHA256withRSA. */
    public static final class Sha256 extends FireSignatureImpl {
        /** Constructor */
        public Sha256() {
            super("SHA256withRSA"); //$NON-NLS-1$
        }
    }

    /** Firma SHA384withRSA. */
    public static final class Sha384 extends FireSignatureImpl {
        /** Constructor. */
        public Sha384() {
            super("SHA384withRSA"); //$NON-NLS-1$
        }
    }

    /** Firma SHA512withRSA. */
    public static final class Sha512 extends FireSignatureImpl {
        /** Constructor. */
        public Sha512() {
            super("SHA512withRSA"); //$NON-NLS-1$
        }
    }

    /** Firma MD5andSHA1withRSA. */
    public static final class MD5andSHA1 extends FireSignatureImpl {
    	/** Constructor. */
        public MD5andSHA1() {
            super("MD5andSHA1withRSA"); //$NON-NLS-1$
        }
    }

    /** Firma SHA256withECDSA. */
    public static final class Sha256Ecdsa extends FireSignatureImpl {
    	/** Constructor. */
        public Sha256Ecdsa() {
            super("SHA256withECDSA"); //$NON-NLS-1$
        }
    }

    /** Firma SHA384withECDSA. */
    public static final class Sha384Ecdsa extends FireSignatureImpl {
    	/** Constructor. */
        public Sha384Ecdsa() {
            super("SHA384withECDSA"); //$NON-NLS-1$
        }
    }

    /** Firma SHA512withECDSA. */
    public static final class Sha512Ecdsa extends FireSignatureImpl {
    	/** Constructor. */
        public Sha512Ecdsa() {
            super("SHA512withECDSA"); //$NON-NLS-1$
        }
    }

    /** Firma NONEwithECDSA. */
    public static final class NoneEcdsa extends FireSignatureImpl {
    	/** Constructor. */
        public NoneEcdsa() {
            super("NONEwithECDSA"); //$NON-NLS-1$
        }
    }

	//***********************************************************************
	// OPERACIONES NO SOPORTADAS

	@Override
	protected boolean engineVerify(final byte[] arg0) throws SignatureException {
		throw new UnsupportedOperationException();
	}

	@Override
	protected void engineInitVerify(final PublicKey arg0) throws InvalidKeyException {
		throw new UnsupportedOperationException();
	}

	@Override
	protected void engineSetParameter(final String arg0, final Object arg1) throws InvalidParameterException {
		throw new InvalidParameterException("Parametro no soportado"); //$NON-NLS-1$
	}

	@Override
	protected Object engineGetParameter(final String arg0) throws InvalidParameterException {
		throw new InvalidParameterException("Parametro no soportado"); //$NON-NLS-1$
	}

}
