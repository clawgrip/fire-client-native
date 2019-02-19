package test.es.gob.clavefirma.client.jse;

import java.io.IOException;
import java.security.KeyStore;
import java.security.Security;
import java.util.Locale;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.ConfirmationCallback;
import javax.security.auth.callback.LanguageCallback;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.TextInputCallback;
import javax.security.auth.callback.TextOutputCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.swing.JOptionPane;

import es.gob.afirma.core.misc.http.UrlHttpManager;
import es.gob.afirma.core.misc.http.UrlHttpManagerFactory;
import es.gob.afirma.core.misc.http.UrlHttpManagerImpl;
import es.gob.afirma.core.misc.http.UrlHttpMethod;
import es.gob.afirma.core.ui.AOUIFactory;
import es.gob.clavefirma.client.jse.FireProvider;

/** Pruebas del proveedor.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestProviderAuth {

	private static final KeyStore.CallbackHandlerProtection CHP = new KeyStore.CallbackHandlerProtection(
		callbacks -> {
		   for (final Callback callback : callbacks) {
		      if (callback instanceof TextOutputCallback) {
		          final TextOutputCallback toc = (TextOutputCallback)callback;
		          switch (((TextOutputCallback)callback).getMessageType()) {
			          case TextOutputCallback.INFORMATION:
			        	  AOUIFactory.showMessageDialog(
		        			  null,  // Padre
		        			  ((TextOutputCallback)callback).getMessage(), // Mensaje
		        			  "Informacion", //$NON-NLS-1$
		        			  JOptionPane.INFORMATION_MESSAGE
	        			  );
			              break;
			          case TextOutputCallback.ERROR:
			        	  AOUIFactory.showMessageDialog(
		        			  null,  // Padre
		        			  ((TextOutputCallback)callback).getMessage(), // Mensaje
		        			  "Error", //$NON-NLS-1$
		        			  JOptionPane.ERROR_MESSAGE
	        			  );
			              break;
			          case TextOutputCallback.WARNING:
			        	  AOUIFactory.showMessageDialog(
		        			  null,  // Padre
		        			  ((TextOutputCallback)callback).getMessage(), // Mensaje
		        			  "Advertencia", //$NON-NLS-1$
		        			  JOptionPane.WARNING_MESSAGE
	        			  );
			              break;
			          default:
			              throw new IOException("Tipo de mensaje no soportado: " + toc.getMessageType()); //$NON-NLS-1$
		          }
		      }
		      else if (callback instanceof NameCallback) {
		    	  // Le pedimos al usuario el nombre de usuario
		    	  // Por ahora, siempre es el usuario 00001
		    	  ((NameCallback)callback).setName("00001"); //$NON-NLS-1$
		      }
		      else if (callback instanceof PasswordCallback) {
		    	  // Le pedimos al usuario la contrasena
		    	  ((PasswordCallback)callback).setPassword("1111".toCharArray()); //$NON-NLS-1$
		      }
		      else if (callback instanceof TextInputCallback) {
		    	  // Le pedimos al usuario el OTP
		    	  final Object o = AOUIFactory.showInputDialog(
	    			  null, // Padre
	    			  "Por favor introduzca el codigo de un solo uso", //$NON-NLS-1$
	    			  "Codigo de un solo uso", //$NON-NLS-1$
	    			  JOptionPane.INFORMATION_MESSAGE,
	    			  null, // Icono
	    			  null, // Valores permitidos
	    			  null  // Valor por defecto
    			  );
		    	  ((TextInputCallback)callback).setText(
	    			  o != null ? o.toString() : "" //$NON-NLS-1$
    			  );
		      }
		      else if (callback instanceof LanguageCallback) {
		    	  // Obtenemos el Locale para los mensajes
		    	  ((LanguageCallback)callback).setLocale(Locale.getDefault());
		      }
		      else if (callback instanceof ConfirmationCallback) {
		    	  final ConfirmationCallback toc = (ConfirmationCallback)callback;
		          switch (((ConfirmationCallback)callback).getMessageType()) {
			          case ConfirmationCallback.YES_NO_OPTION:
			              // Pedimos confirmacion
			        	  ((ConfirmationCallback)callback).setSelectedIndex(ConfirmationCallback.OK);
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

		final String retrieveServer = "http://raq.uel:8080/afirma-signature-retriever/RetrieveService"; //$NON-NLS-1$
		final String storageServer = "http://raq.uel:8080/afirma-signature-storage/StorageService"; //$NON-NLS-1$
		final String config =
			"retrieveServerUrl=" + retrieveServer + "\r\n" + //$NON-NLS-1$ //$NON-NLS-2$
			"storageServerUrl=" + storageServer + "\r\n" +  //$NON-NLS-1$ //$NON-NLS-2$
			"appId=spt\r\n" + //$NON-NLS-1$
			"otpManager=es.gob.clavefirma.client.jse.otp.TestOtpManager"; //$NON-NLS-1$
		Security.insertProviderAt(p.configure(config), 1);

		final KeyStore ks = testKeyStore(p);

//		final MessageDigest md = MessageDigest.getInstance("MD5andSHA1"); //$NON-NLS-1$
//		System.out.println(md);

		Security.removeProvider("SunJSSE"); //$NON-NLS-1$
		final UrlHttpManager uhm = UrlHttpManagerFactory.getInstalledManager();
		UrlHttpManagerImpl.setSslKeyStore(ks);
		UrlHttpManagerImpl.setSslKeyStorePasswordCallback(null);
		final byte[] res = uhm.readUrl(
			"https://w2.seg-social.es/ProsaInternet/OnlineAccess?ARQ.SPM.ACTION=LOGIN&ARQ.SPM.APPTYPE=SERVICE&ARQ.IDAPP=INAF0004&INFORME=INAF0002", //$NON-NLS-1$
			UrlHttpMethod.GET
		);

		System.out.println(new String(res));

	}

}
