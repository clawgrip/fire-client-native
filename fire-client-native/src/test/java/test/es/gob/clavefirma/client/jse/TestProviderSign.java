package test.es.gob.clavefirma.client.jse;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.security.KeyStore;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.Security;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.LanguageCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JOptionPane;

import es.gob.afirma.core.signers.AOPkcs1Signer;
import es.gob.afirma.core.signers.AOSigner;
import es.gob.afirma.core.ui.AOUIFactory;
import es.gob.clavefirma.client.jse.FireProvider;

/** Pruebas del proveedor.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestProviderSign {

	private static final KeyStore.CallbackHandlerProtection CHP = new KeyStore.CallbackHandlerProtection(
		callbacks -> {
		   for (final Callback callback : callbacks) {
		      if (callback instanceof TextOutputCallback) {
		          final TextOutputCallback toc = (TextOutputCallback)callback;
		          switch (((TextOutputCallback)callback).getMessageType()) {
			          case TextOutputCallback.INFORMATION:
			              //
			              break;
			          case TextOutputCallback.ERROR:
			              //
			              break;
			          case TextOutputCallback.WARNING:
			              //
			              break;
			          default:
			              throw new IOException("Tipo de mensaje no soportado: " + toc.getMessageType()); //$NON-NLS-1$
		          }
		      }
		      else if (callback instanceof NameCallback) {
		    	  // Le pedimos al usuario el nombre de usuario
		    	  ((NameCallback)callback).setName(
	    			  (String) AOUIFactory.showInputDialog(
		    			  null,
		    			  ((NameCallback)callback).getPrompt(),
		    			  "Nombre de usuario", //$NON-NLS-1$
		    			  JOptionPane.QUESTION_MESSAGE,
		    			  null,
		    			  null,
		    			  null
	    			  )
    			  );
		      }
		      else if (callback instanceof PasswordCallback) {
		    	  // Le pedimos al usuario la contrasena
		    	  ((PasswordCallback)callback).setPassword(
	    			  AOUIFactory.getPassword(((PasswordCallback)callback).getPrompt(), null)
    			  );
		      }
		      else if (callback instanceof TextInputCallback) {
		    	  // Le pedimos al usuario el OTP
		      }
		      else if (callback instanceof LanguageCallback) {
		    	  // Obtenemos el Locale para los mensajes
		      }
		      else if (callback instanceof ConfirmationCallback) {
		    	  final ConfirmationCallback toc = (ConfirmationCallback)callback;
		          switch (((ConfirmationCallback)callback).getMessageType()) {
			          case ConfirmationCallback.YES_NO_OPTION:
			              //
			              break;
			          default:
			              throw new IOException("Tipo de confirmacion no soportada: " + toc.getMessageType()); //$NON-NLS-1$
		          }
		      }
		      else {
		          throw new UnsupportedCallbackException(callback, "Callback no soportada: " + callback.getClass().getName()); //$NON-NLS-1$
		      }
		   }
		}
	);

	/** Prueba de <code>KeyStore</code>.
	 * @param p Proveedor de ClaveFirma.
	 * @return <code>KeyStore</code> cargado.
	 * @throws Exception En cualquier error. */
	public static KeyStore testKeyStore(final FireProvider p) throws Exception {

		final KeyStore.Builder builder = KeyStore.Builder.newInstance(
			FireProvider.KEYSTORE_NAME,
			p,
			CHP
		);
		return builder.getKeyStore();
	}

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {

		final FireProvider p = new FireProvider();

		final String retrieveServer = "http://demo.tgm/afirma-signature-retriever/RetrieveService"; //$NON-NLS-1$
		final String storageServer = "http://demo.tgm/afirma-signature-storage/StorageService"; //$NON-NLS-1$
		final String config =
			"retrieveServerUrl=" + retrieveServer + "\r\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"storageServerUrl=" + storageServer + "\r\n" +  //$NON-NLS-1$ //$NON-NLS-2$
			"appId=spt\r\n" + //$NON-NLS-1$
			"otpManager=es.gob.clavefirma.client.jse.otp.TestOtpManager"; //$NON-NLS-1$

		Security.addProvider(p.configure(config));

		final KeyStore ks = testKeyStore(p);

		final AOSigner p1Signer = new AOPkcs1Signer();
		final String alias = ks.aliases().nextElement();
		final PrivateKeyEntry pke = (PrivateKeyEntry) ks.getEntry(alias, null);

		final byte[] data = "1234567812345678123456781234567812345678123456781234567812345678".getBytes(); //$NON-NLS-1$

//		final byte[] data = Utils.getDataFromInputStream(
//			TestProviderSign.class.getResourceAsStream("/TEST_PDF.pdf") //$NON-NLS-1$
//		);

		final byte[] pdf = p1Signer.sign(
			data,
			"NONEwithRSA", //$NON-NLS-1$
			pke.getPrivateKey(),
			pke.getCertificateChain(),
			null // ExtraParams
		);

		try (
			final OutputStream fos = new FileOutputStream(File.createTempFile("CLAVE_", ".pdf")); //$NON-NLS-1$ //$NON-NLS-2$
		) {
			fos.write(pdf);
			fos.close();
		}

		System.out.println("Datos firmados correctamente"); //$NON-NLS-1$

	}

}
