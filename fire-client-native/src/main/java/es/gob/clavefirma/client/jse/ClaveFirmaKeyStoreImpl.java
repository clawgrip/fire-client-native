package es.gob.clavefirma.client.jse;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.KeyStore.ProtectionParameter;
import java.security.KeyStoreException;
import java.security.KeyStoreSpi;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.UnrecoverableEntryException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.Hashtable;
import java.util.List;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.UnsupportedCallbackException;

import es.gob.clavefirma.client.ClientConfigFilesNotFoundException;
import es.gob.clavefirma.client.HttpOperationException;
import es.gob.clavefirma.client.certificatelist.HttpCertificateList;

/** Implementaci&oacute;n de almac&eacute;n de claves basado en ClaveFirma.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class ClaveFirmaKeyStoreImpl extends KeyStoreSpi {

	private Dictionary<String, X509Certificate> certsByAlias = null;

	private CallbackHandler callbackHandler = null;

	private String subjectId = null;

	@Override
	public Key engineGetKey(final String alias,
			                final char[] password) throws NoSuchAlgorithmException,
	                                                      UnrecoverableKeyException {
		if (!engineContainsAlias(alias)) {
			return null;
		}
		return new ClaveFirmaPrivateKey(
			ClaveFirmaProvider.getAppId(),
			this.subjectId,
			(X509Certificate) engineGetCertificate(alias),
			this.callbackHandler
		);
	}

	@Override
	public Enumeration<String> engineAliases() {
		return this.certsByAlias.keys();
	}

	@Override
	public boolean engineContainsAlias(final String alias) {
		return this.certsByAlias.get(alias) != null;
	}

	@Override
	public void engineDeleteEntry(final String arg0) throws KeyStoreException {
		throw new UnsupportedOperationException();
	}

	@Override
	public Certificate engineGetCertificate(final String alias) {
		return this.certsByAlias.get(alias);
	}

	@Override
	public String engineGetCertificateAlias(final Certificate cert) {
		if (cert == null) {
			return null;
		}
		final Enumeration<String> aliases = this.certsByAlias.keys();
		while(aliases.hasMoreElements()) {
			final String alias = aliases.nextElement();
			final X509Certificate c = this.certsByAlias.get(alias);
			if (
				((X509Certificate)cert).getSerialNumber().equals(c.getSerialNumber()) &&
				((X509Certificate)cert).getIssuerX500Principal().equals(c.getIssuerX500Principal())
			) {
				return alias;
			}
		}
		return null;
	}

	@Override
	public Certificate[] engineGetCertificateChain(final String alias) {
		return new X509Certificate[] { (X509Certificate) engineGetCertificate(alias) };
	}

	@Override
	public Date engineGetCreationDate(final String alias) {
		final X509Certificate cert = this.certsByAlias.get(alias);
		if (cert == null) {
			return null;
		}
		return cert.getNotBefore();
	}

	@Override
	public boolean engineIsCertificateEntry(final String arg0) {
		return false;
	}

	@Override
	public boolean engineIsKeyEntry(final String alias) {
		return this.certsByAlias.get(alias) != null;
	}

	@Override
	public void engineLoad(final InputStream stream, final char[] password) throws IOException,
	                                                                               NoSuchAlgorithmException,
	                                                                               CertificateException {
		throw new UnsupportedOperationException(
			"Debe usarse 'engineLoad(KeyStore.LoadStoreParameter param)'" //$NON-NLS-1$
		);
	}

    /** {@inheritDoc} */
    @Override
    public void engineLoad(final KeyStore.LoadStoreParameter param) throws IOException {
    	if (param != null) {
    		final ProtectionParameter pp = param.getProtectionParameter();
    		if (pp instanceof KeyStore.CallbackHandlerProtection) {
    			if (((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler() == null) {
    				throw new IllegalArgumentException("El CallbackHandler no puede ser nulo"); //$NON-NLS-1$
    			}
    			this.callbackHandler = ((KeyStore.CallbackHandlerProtection) pp).getCallbackHandler();
    		}
    		else {
	       		throw new IllegalArgumentException(
	   				"Se ha proporcionado un LoadStoreParameter de tipo no soportado: " + (pp != null ? pp.getClass().getName() : "NULO") //$NON-NLS-1$ //$NON-NLS-2$
				);
    		}
    	}
    	else {
    		throw new IllegalArgumentException(
   				"Debe proporcionarse un LoadStoreParameter de tipo KeyStore.CallbackHandlerProtection" //$NON-NLS-1$
			);
    	}
    	try {
			loadCertsByAlias();
		}
    	catch (
			final CertificateException               |
			      HttpOperationException             |
			      ClientConfigFilesNotFoundException |
			      UnsupportedCallbackException e
		) {
			throw new IOException(e);
		}
    }

	@Override
	public int engineSize() {
		return this.certsByAlias.size();
	}

	private void loadCertsByAlias() throws CertificateException,
	                                       HttpOperationException,
	                                       ClientConfigFilesNotFoundException,
	                                       IOException,
	                                       UnsupportedCallbackException {
		if (this.certsByAlias != null) {
			return;
		}

		final NameCallback nameCallback = new NameCallback(ClaveFirmaProviderMessages.getString("ClaveFirmaKeyStoreImpl.0")); //$NON-NLS-1$
		this.callbackHandler.handle(new Callback[] { nameCallback });

		this.subjectId = nameCallback.getName();

		final List<X509Certificate> list = HttpCertificateList.getList(
			ClaveFirmaProvider.getAppId(),
			this.subjectId
		);
		this.certsByAlias = new Hashtable<>(list.size());
		for (final X509Certificate cert : list) {
			this.certsByAlias.put(
				cert.getSerialNumber().toString(),
				cert
			);
		}
	}

	@Override
	public KeyStore.Entry engineGetEntry(final String alias,
                                         final KeyStore.ProtectionParameter protParam) throws KeyStoreException,
                                                                                              NoSuchAlgorithmException,
                                                                                              UnrecoverableEntryException {
    	final PrivateKey key = (PrivateKey) engineGetKey(
			alias,
			null
		);
    	return new PrivateKeyEntry(key, engineGetCertificateChain(alias));
	}

	//***********************************************************************
	// OPERACIONES NO SOPORTADAS

	@Override
	public void engineStore(final OutputStream arg0, final char[] arg1) throws IOException, NoSuchAlgorithmException, CertificateException {
		throw new UnsupportedOperationException(
			"El proveedor no soporta 'engineStore()'" //$NON-NLS-1$
		);
	}

	@Override
	public void engineSetCertificateEntry(final String arg0, final Certificate arg1) throws KeyStoreException {
		throw new UnsupportedOperationException(
			"El proveedor no soporta 'engineSetCertificateEntry()'" //$NON-NLS-1$
		);
	}

	@Override
	public void engineSetKeyEntry(final String arg0, final byte[] arg1, final Certificate[] arg2) throws KeyStoreException {
		throw new UnsupportedOperationException(
			"El proveedor no soporta 'engineSetKeyEntry'" //$NON-NLS-1$
		);
	}

	@Override
	public void engineSetKeyEntry(final String arg0, final Key arg1, final char[] arg2, final Certificate[] arg3) throws KeyStoreException {
		throw new UnsupportedOperationException(
			"El proveedor no soporta 'engineSetKeyEntry'" //$NON-NLS-1$
		);
	}

}
