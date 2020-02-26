import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.net.Socket;
import java.security.AlgorithmParameterGenerator;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Protocol2Client
{
	static int			portNo	= 11338;
	// Values of p & g for Diffie-Hellman found using generateDHprams()
	static BigInteger	g		= new BigInteger(
			"129115595377796797872260754286990587373919932143310995152019820961988539107450691898237693336192317366206087177510922095217647062219921553183876476232430921888985287191036474977937325461650715797148343570627272553218190796724095304058885497484176448065844273193302032730583977829212948191249234100369155852168");
	static BigInteger	p		= new BigInteger(
			"165599299559711461271372014575825561168377583182463070194199862059444967049140626852928438236366187571526887969259319366449971919367665844413099962594758448603310339244779450534926105586093307455534702963575018551055314397497631095446414992955062052587163874172731570053362641344616087601787442281135614434639");

	public static void main(String[] args)
	{
		try
		{
			InetAddress ipAddress = InetAddress.getLocalHost();
			Socket socket = new Socket(ipAddress, portNo);
			DataOutputStream outStream;
			DataInputStream inStream;
			outStream = new DataOutputStream(socket.getOutputStream());
			inStream = new DataInputStream(socket.getInputStream());

			// Use crypto API to calculate x & g^x
			DHParameterSpec dhSpec = new DHParameterSpec(p, g);
			KeyPairGenerator diffieHellmanGen = null;
			
			diffieHellmanGen = KeyPairGenerator.getInstance("DiffieHellman");
		
			diffieHellmanGen.initialize(dhSpec);
			
			KeyPair serverPair = diffieHellmanGen.generateKeyPair();
			PrivateKey x = serverPair.getPrivate();
			PublicKey gToTheX = serverPair.getPublic();

			//Protocol message 1
			outStream.writeInt(gToTheX.getEncoded().length);
			outStream.write(gToTheX.getEncoded());
			System.out.println("g^x len :" + gToTheX.getEncoded().length);
			System.out.println("g^x cert:" + byteArrayToHexString(gToTheX.getEncoded()));

			//Protocol message 2
			int publicKenLen = inStream.readInt();
			byte[] message2 = new byte[publicKenLen];
			inStream.read(message2);
			KeyFactory keyfactoryDH = null;
			
			keyfactoryDH = KeyFactory.getInstance("DH");
			
			X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(message2);
			
			PublicKey gToTheY = keyfactoryDH.generatePublic(x509Spec);
   		    System.out.println("g^y len: "+gToTheY.getEncoded().length);
			System.out.println("g^y cert: "+byteArrayToHexString(gToTheY.getEncoded()));
		
			//Protocol Step 3
		    byte [] keyByte={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
			SecretKeySpec secretkeySpec = new SecretKeySpec(keyByte,
					"AES");
			Cipher encAESsessionCipher;
			encAESsessionCipher = Cipher.getInstance("AES");
			byte[] clientNonce = new byte[16];
			
		    System.out.print("clientNonce:"+clientNonce);
		    
		    //Protocol Step 4
		    Cipher decAEScipher = null;
		    byte[] serverNonce = new byte[20];
		    inStream.read(serverNonce);
		    System.out.print("serverNonce:"+clientNonce);
		    
		    //Protocol5
		    byte[] message5 = new byte[32];
		    outStream.write(message5);
		    Cipher encAEScipher=null;
		    byte[] nonceReplyBytes = encAEScipher.doFinal(encAESsessionCipher.doFinal(message5));
		    int serverNonceReply = new BigInteger(nonceReplyBytes).intValue();
		    System.out.println("Server Nonce Reply:"+serverNonceReply);
		}catch (IOException e)
		{
			e.printStackTrace();
		}
		catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		}
		catch (BadPaddingException e) {
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
		catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		catch (NoSuchPaddingException e) {
		
			e.printStackTrace();
		}
		catch (InvalidAlgorithmParameterException e) {
			e.printStackTrace();
		}
	
	}	

	@SuppressWarnings("unused")
	public static void generateDHprams() throws NoSuchAlgorithmException, InvalidParameterSpecException
	{
		AlgorithmParameterGenerator paramGen = AlgorithmParameterGenerator.getInstance("DH");
		paramGen.init(1024);
		//Generate the parameters   
		AlgorithmParameters params = paramGen.generateParameters();
		DHParameterSpec dhSpec = (DHParameterSpec) params.getParameterSpec(DHParameterSpec.class);
		System.out.println("These are some good values to use for p & g with Diffie Hellman");
		System.out.println("p: " + dhSpec.getP());
		System.out.println("g: " + dhSpec.getG());

	}

	private static String byteArrayToHexString(byte[] data)
	{
		StringBuffer buf = new StringBuffer();
		for (int i = 0; i < data.length; i++)
		{
			int halfbyte = (data[i] >>> 4) & 0x0F;
			int two_halfs = 0;
			do
			{
				if ((0 <= halfbyte) && (halfbyte <= 9))
					buf.append((char) ('0' + halfbyte));
				else
					buf.append((char) ('a' + (halfbyte - 10)));
				halfbyte = data[i] & 0x0F;
			} while (two_halfs++ < 1);
		}
		return buf.toString();
	}

	private static byte[] hexStringToByteArray(String s)
	{
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2)
		{
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4) + Character.digit(s.charAt(i + 1), 16));
		}
		return data;
	}

}
