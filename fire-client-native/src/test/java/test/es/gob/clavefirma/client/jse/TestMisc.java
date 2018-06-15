package test.es.gob.clavefirma.client.jse;

import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.SignatureException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.List;

import org.junit.Test;

import es.gob.afirma.core.misc.AOUtil;
import es.gob.clavefirma.client.ClientConfigFilesNotFoundException;
import es.gob.clavefirma.client.HttpOperationException;
import es.gob.clavefirma.client.certificatelist.HttpCertificateList;
import es.gob.clavefirma.client.signprocess.HttpLoadProcess;
import es.gob.clavefirma.client.signprocess.HttpSignProcess;
import es.gob.clavefirma.client.signprocess.LoadResult;
import es.gob.fire.client.Base64;

/** Prueba simple de las operaciones de ClaveFirma.
 * @author Tom&aacute;s Garc&iacute;a-Mer&aacute;s. */
public final class TestMisc {

	/** Escribe un P12 en Base64 en consola.
	 * @throws Exception En cualquier error. */
	@SuppressWarnings("static-method")
	@Test
	public void testReadP12() throws Exception {
		final String path = "C:/Java/tomcat/conf/ANCERTCCP_FIRMA.p12"; //$NON-NLS-1$
		final byte[] p12;
		try (
			final InputStream fis = new FileInputStream(path);
		) {
			p12 = AOUtil.getDataFromInputStream(fis);
		}
		System.out.println(Base64.encode(p12));
	}

	/** Main para pruebas.
	 * @param args No se usa.
	 * @throws Exception En cualquier error. */
	public static void main(final String[] args) throws Exception {

		final List<X509Certificate> certs = HttpCertificateList.getList(
			"spt", //$NON-NLS-1$
			"00001" //$NON-NLS-1$
		);

		System.out.println("Hemos encontrado " + (certs != null ? Integer.valueOf(certs.size()) : "0") + " certificados");   //$NON-NLS-1$//$NON-NLS-2$//$NON-NLS-3$

		if (certs == null || certs.size() < 1) {
			return; // En este caso usariamos AutoFirma
		}

		System.out.println("El certificado encontrado esta a nombre de " + AOUtil.getCN(certs.get(0))); //$NON-NLS-1$

		final StringBuilder config = new StringBuilder();
		config.append("redirectOkUrl=" + "https://www.ibm.com" + "\r\n"); //$NON-NLS-1$ //$NON-NLS-2$ //$NON-NLS-3$
		config.append("redirectErrorUrl=" + "https://www.google.com"); //$NON-NLS-1$ //$NON-NLS-2$
		final LoadResult res;
		try {
			res = HttpLoadProcess.loadData(
				"spt", //$NON-NLS-1$
				"00001", //$NON-NLS-1$
				"SIGN", //$NON-NLS-1$
				"CAdES", //$NON-NLS-1$
				"SHA512withRSA", //$NON-NLS-1$
				null, // ExtraParams
				Base64.encode(certs.get(0).getEncoded()),
				Base64.encode("DATOS A FIRMAR".getBytes()), //$NON-NLS-1$
				Base64.encode(config.toString().getBytes(StandardCharsets.UTF_8)) // Configuracion del servicio servidor
			);
		}
		catch (final CertificateEncodingException | HttpOperationException | ClientConfigFilesNotFoundException e) {
			throw new SignatureException(
				"Error cargando los datos a firmar: " + e, e //$NON-NLS-1$
			);
		}

		System.out.println();
		System.out.println(res);

		// AQui para la ejecucion hasta que el usuario autoriza con el PIN que le llega por SMS en la URL de la Seguridad Social

		// El OTP ha validado y tenemos los datos cargados... Solo queda firmar
		final byte[] sign;
		try {
			sign = HttpSignProcess.sign(
				"spt", //$NON-NLS-1$
				res.getTransactionId(),
				"SIGN", //$NON-NLS-1$
				"CAdES", //$NON-NLS-1$
				"SHA512withRSA", //$NON-NLS-1$
				null,
				Base64.encode(certs.get(0).getEncoded(), true),
				Base64.encode("DATOS A FIRMAR".getBytes(), true), //$NON-NLS-1$
				Base64.encode(res.getTriphaseData().toString().getBytes(), true), // Datos trifasicos en Base64,
				null // Upgrade
			);
		}
		catch (final CertificateEncodingException |
				     HttpOperationException       |
				     ClientConfigFilesNotFoundException e) {
			throw new SignatureException(e);
		}

		System.out.println("FIRMA:"); //$NON-NLS-1$
		System.out.println(Base64.encode(sign));
	}

}
