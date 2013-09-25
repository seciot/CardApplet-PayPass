/**
 * 
 */
package com.st;

import java.io.IOException;
import java.io.Serializable;
import java.util.Calendar;

import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;
import javacard.framework.APDU;
import javacard.framework.JCSystem;
import javacard.framework.Util;
import javacard.security.DESKey;
import javacard.security.KeyBuilder;
import javacardx.crypto.Cipher;

/**
 * @author DYeager
 *
 */
public class PayPass extends Applet {
	
	/**
	 * 
	 */
	private static final long serialVersionUID = 1L;
	//these variables define the state of the profile
	//the pre_perso state cannot be an ACTIVE profile
	//the perso state means the card is in personalization mode
	//the alive state means the card is personalized 
	public final byte PRE_PERSO = (byte)0x00;
	public final byte PERSO = (byte)0x01;
	public final byte ALIVE = (byte)0x02;
	
	//this class is the main storage class for card profile storage
	public class Profile implements Serializable {
		/**
		 * 
		 */
		private static final long serialVersionUID = 1L;

		//upon successfule pre-personalization,
		//the profile can be considered valid.
		//until that data is filled in, the profile
		//cannot be used and should be considered invalid
		public byte STATE = PRE_PERSO;
		
		/*******************************************************
		***************Pre-Personalization Data*****************
		********************************************************/
		//ATC - Application Transaction Counter -
		public byte[] ATC = {	(byte)0x00,(byte)0x00						};

		//CSN - Chip Serial Number -
		public byte[] CSN = {	(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00	};
		
		//NEED ISSUER TO SUPPLY THESE VALUES FOR 
		//   VER_KMC
		//   KMC_ID
		//   KD_PERSO
		//
		//VER_KMC - DES Master Key Version -
		public byte VER_KMC;   //populated during install of applet
		//KMC_ID - DES Master Key ID -
		public byte[] KMC_ID = new byte[6];  //populated during install of applet
		//KD_PERSO - **DERIVED FROM DES MASTER KEY (KMC)**
		public byte[] KD_PERSO = new byte[16];  //populated during install of applet

		/*******************************************************
		*****************Personalization Data*******************
		********************************************************/
		/////////////////
		//DGI 0101 DATA//
		/////////////////
		public byte[] DGI0101 = new byte[176];
		public byte DGI0101_LEN = (byte)0x00;
		
		/////////////////
		//DGI A001 DATA//
		/////////////////
		//AC - Application Control
		public byte[] AC = new byte[3];
		//CVC3_T1 - Static CVC3 Track 1 -
		public byte[] CVC3_T1 = new byte[2];
		//CVC3_T2 - Static CVC3 Track 2 -
		public byte[] CVC3_T2 = new byte[2];
		//IVCVC3_T1 - CVC3 Track 1 -
		public byte[] IVCVC3_T1 = new byte[2];
		//IVCVC3_T2 - CVC3 Track 2 -
		public byte[] IVCVC3_T2 = new byte[2];
		
		/////////////////
		//DGI A002 DATA//
		/////////////////
		//KD_CVC3 - 3DES Key For CVC3 Generation -
		public byte[] KD_CVC3 = new byte[16];

		//private encryption key objects used
		public DESKey DESKEY_KD_CVC3_L_EN = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES,false);
		public DESKey DESKEY_KD_CVC3_R_DE = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES,false);

		//private cipher objects used
		public Cipher CIPHER_KD_CVC3_L_EN = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD,false);
		public Cipher CIPHER_KD_CVC3_R_DE = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD,false);
	}
	
	public Profile PROFILE;
	
	/*******************************************************
	***************MasterCard Specific Data*****************
	********************************************************/
	//AID - Application Identifier -
	public final byte[] AID = {(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,  //MasterCard
								(byte)0x04,(byte)0x10,(byte)0x10			};
//	public static byte[] AID = {(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,  //Maestro
//								(byte)0x04,(byte)0x30,(byte)0x60			};
	//AL - Application Label - 'MasterCard' or 'Maestro'
	public final byte[] AL = {	(byte)0x4D,(byte)0x61,(byte)0x73,(byte)0x74,  //MasterCard
								(byte)0x65,(byte)0x72,(byte)0x43,(byte)0x61,
								(byte)0x72,(byte)0x64						};
//	public static byte[] AL = {	(byte)0x4D,(byte)0x61,(byte)0x65,(byte)0x73,  //Maestro
//								(byte)0x74,(byte)0x72,(byte)0x6F			};
	//DF - Dedicated File (AID) -
	public final byte[] DF = {	(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,  //MasterCard
								(byte)0x04,(byte)0x10,(byte)0x10			};
//	public static byte[] DF = {(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,  //Maestro
//								(byte)0x04,(byte)0x30,(byte)0x60			};
	//AFL - Application File Locator -
	public final byte[] AFL = {	(byte)0x08,(byte)0x01,(byte)0x01,(byte)0x00	};
	//AIP - Application Interchange Profile -
	public final byte[] AIP = {	(byte)0x00,(byte)0x00						};
	
	/*******************************************************
	**************Pre-Defined Global Variables**************
	********************************************************/
	//private encryption key objects used
	private DESKey DESKEY_KD_PERSO_L_EN;
	private DESKey DESKEY_KD_PERSO_R_DE;
	private DESKey DESKEY_KD_PERSO_L_DE;
	private DESKey DESKEY_KD_PERSO_R_EN;
	
	//private cipher objects used
	private Cipher CIPHER_KD_PERSO_L_EN;
	private Cipher CIPHER_KD_PERSO_R_DE;
	private Cipher CIPHER_KD_PERSO_L_DE;
	private Cipher CIPHER_KD_PERSO_R_EN;

	//create buffer to put data to encrypt
	private byte[] CVC3_DATA;

	//create buffer to put long command strings in
	private byte[] CMD_BUF;
	
	//create buffer to put a calculated MAC in
	private byte[] MAC;

	//state variables
	private byte state;
	private final byte not_alive = (byte)0x00;
	private final byte selected = (byte)0x01;
	private final byte initiated = (byte)0x02;

	public PayPass(byte[] bArray, short bOffset, byte bLength)
	{
		if(bLength!=27)
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		//transaction starts
		JCSystem.beginTransaction();
		
		//set up and initialize all the DES encryption/descrytion ciphers used in the app
		DESKEY_KD_PERSO_L_EN = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES,false);
		DESKEY_KD_PERSO_R_DE = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES,false);
		DESKEY_KD_PERSO_L_DE = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES,false);
		DESKEY_KD_PERSO_R_EN = (DESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_DES,KeyBuilder.LENGTH_DES,false);
		CIPHER_KD_PERSO_L_EN = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD,false);
		CIPHER_KD_PERSO_R_DE = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD,false);
		CIPHER_KD_PERSO_L_DE = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD,false);
		CIPHER_KD_PERSO_R_EN = Cipher.getInstance(Cipher.ALG_DES_ECB_NOPAD,false);

		//transaction ends
		JCSystem.commitTransaction();
		
		//define RAM buffers for faster operation
		CVC3_DATA = JCSystem.makeTransientByteArray((short) 16, JCSystem.CLEAR_ON_DESELECT);
		CMD_BUF = JCSystem.makeTransientByteArray((short) 261, JCSystem.CLEAR_ON_DESELECT);
		MAC = JCSystem.makeTransientByteArray((short) 8, JCSystem.CLEAR_ON_DESELECT);
		
		//on initialize the current state is not_alive
		state = not_alive;
		
		PROFILE = new Profile();
		
		//testing area
		//pre-personalization data
		//issuer supply
		PROFILE.VER_KMC = (byte)0x01;  //MC version
		PROFILE.VER_KMC = bArray[bOffset];  //MC version
		PROFILE.KMC_ID[0] = (byte)0x54;  //key id
		PROFILE.KMC_ID[1] = (byte)0x13;
		PROFILE.KMC_ID[2] = (byte)0x12;
		PROFILE.KMC_ID[3] = (byte)0xFF;
		PROFILE.KMC_ID[4] = (byte)0xFF;
		PROFILE.KMC_ID[5] = (byte)0xFF;
		Util.arrayCopyNonAtomic(bArray, (short)(bOffset+1), PROFILE.KMC_ID, (short)0, (short)6);
		PROFILE.KD_PERSO[0] = (byte)0xA8;  //personalization key
		PROFILE.KD_PERSO[1] = (byte)0x6A;
		PROFILE.KD_PERSO[2] = (byte)0x3D;
		PROFILE.KD_PERSO[3] = (byte)0x06;
		PROFILE.KD_PERSO[4] = (byte)0xCA;
		PROFILE.KD_PERSO[5] = (byte)0xE7;
		PROFILE.KD_PERSO[6] = (byte)0x04;
		PROFILE.KD_PERSO[7] = (byte)0x6A;
		PROFILE.KD_PERSO[8] = (byte)0x10;
		PROFILE.KD_PERSO[9] = (byte)0x63;
		PROFILE.KD_PERSO[10] = (byte)0x58;
		PROFILE.KD_PERSO[11] = (byte)0xD5;
		PROFILE.KD_PERSO[12] = (byte)0xB8;
		PROFILE.KD_PERSO[13] = (byte)0x23;
		PROFILE.KD_PERSO[14] = (byte)0x9C;
		PROFILE.KD_PERSO[15] = (byte)0xBE;
		Util.arrayCopyNonAtomic(bArray, (short)(bOffset+7), PROFILE.KD_PERSO, (short)0, (short)16);
		PROFILE.CSN[0] = (byte)0x89;
		PROFILE.CSN[1] = (byte)0xAA;
		PROFILE.CSN[2] = (byte)0x7F;
		PROFILE.CSN[3] = (byte)0x00;
		Util.arrayCopyNonAtomic(bArray, (short)(bOffset+23), PROFILE.CSN, (short)0, (short)4);
		//end issuer supply

		//profile can now be considered in personalization state
		PROFILE.STATE = PERSO;
	}
	
	public static void install(byte[] bArray, short bOffset, byte bLength) {
		// GP-compliant JavaCard applet registration
		new PayPass(bArray,bOffset,bLength).register(bArray, (short) (bOffset + 1),
				bArray[bOffset]);
	}

	public void get_data(APDU apdu, byte[] buf)
	{
		//verify that the class for this instruction is correct
		if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x80)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//check state - this command only works in the PERSO state
		if(PROFILE.STATE != PERSO)
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		//check that P1 & P2 are correct
		if(buf[ISO7816.OFFSET_P1] != (byte) 0x00 || (byte)buf[ISO7816.OFFSET_P2] != (byte) 0xCF)
			ISOException.throwIt((short)0x6A88); //referenced data not found
		//build response message
		apdu.setOutgoing();
		apdu.setOutgoingLength((short)13);
	
		buf[0]=(byte)0xCF; //Key Data Tag
		buf[1]=(byte)11;   //length
			buf[2]=PROFILE.VER_KMC;
			Util.arrayCopyNonAtomic(PROFILE.KMC_ID,(short)0,buf,(short)3,(short)6);
			Util.arrayCopyNonAtomic(PROFILE.CSN,(short)0,buf,(short)9,(short)4);
			
		apdu.sendBytes((short)0,(short)13);		
	}
	
	public void store_data(APDU apdu, byte[] buf)
	{
		//verify that the class for this instruction is correct
		if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x84)
			ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
		//check state - this command only works in the PERSO state
		if(PROFILE.STATE != PERSO)
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		//check that P1 & P2 are correct
		if(buf[ISO7816.OFFSET_P1] != (byte) 0xA0 || (byte)buf[ISO7816.OFFSET_P2] != (byte) 0x00)
			ISOException.throwIt((short)ISO7816.SW_INCORRECT_P1P2); //referenced data not found
		
		//this is a big amount of data to read in
		//we must cache it into a temperary buffer for processing
		//we must also count the number of bytes we bring in
		short BYTES=5;
		short MORE_BYTES;
		//copy the first 5 header bytes to the temp buffer
		Util.arrayCopyNonAtomic(buf,(short)0,CMD_BUF,(short)0,(short)5);
		//get one set of bytes in from the APDU buffer
		if((MORE_BYTES=apdu.setIncomingAndReceive())==0)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		//copy the bytes from the buf to the temp buffer
		Util.arrayCopyNonAtomic(buf,BYTES,CMD_BUF,ISO7816.OFFSET_CDATA,MORE_BYTES);
		//increase my total byte count
		BYTES=(short)(BYTES+MORE_BYTES);
		//continue reading in bytes and increasing the total byte count
		//until there are no more left
		while((MORE_BYTES = apdu.receiveBytes((short)0))!=0)
		{
			Util.arrayCopyNonAtomic(buf,(short)0,CMD_BUF,BYTES,MORE_BYTES);
			BYTES=(short)(BYTES+MORE_BYTES);
		}
		//check total length against the said LC value
		if((short)((short)(CMD_BUF[ISO7816.OFFSET_LC] & 0xFF)+5) != BYTES)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		
		//check the length of the data to make sure it corresponds
		if((short)((short)(buf[ISO7816.OFFSET_CDATA+2] & 0xFF)+44) != (short)(buf[ISO7816.OFFSET_LC] & 0xFF))
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if((short)(buf[(short)( ISO7816.OFFSET_CDATA + 2 + 1 + (short)(buf[ISO7816.OFFSET_CDATA+2] & 0xFF) + 2 )] & 0xFF) != (short)0x0B)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
		if((short)(buf[(short)( ISO7816.OFFSET_CDATA + 2 + 1 + (short)(buf[ISO7816.OFFSET_CDATA+2] & 0xFF) + 2 + 1 + 0x0B + 2)] & 0xFF) != (short)0x10)
			ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

		//verify the MAC
		//initial vector of all zeros
		Util.arrayFillNonAtomic(MAC,(short)0,(short)8,(byte)0x00);
		
		//this is how many full 8 byte words exist in the command string without the MAC
		byte WORDS =  (byte)((5 + (short)(CMD_BUF[ISO7816.OFFSET_LC] & 0xFF) - 8)/8); 
		
		//calculate the MAC of the data based on MC PayPass spec in ANNEX B
		//set the DES key to be the left and right halves of KD_PERSO and initialize
		DESKEY_KD_PERSO_L_EN.setKey(PROFILE.KD_PERSO,(short)0);  //left half of key
		CIPHER_KD_PERSO_L_EN.init(DESKEY_KD_PERSO_L_EN, Cipher.MODE_ENCRYPT);
		DESKEY_KD_PERSO_R_DE.setKey(PROFILE.KD_PERSO,(short)8);  //right half of key
		CIPHER_KD_PERSO_R_DE.init(DESKEY_KD_PERSO_R_DE, Cipher.MODE_DECRYPT);

		byte i;
		//cycle through all the full words of the string and MAC them
		for(i=0;i<WORDS;i++)
		{
			for(byte j=0;j<8;j++) 
				MAC[j]=(byte)((short)(MAC[j] & 0xFF) ^ (short)(CMD_BUF[i*8+j] & 0xFF));
			//encrypt MAC operation
			CIPHER_KD_PERSO_L_EN.update(MAC,(short)0,(short)8,MAC,(short)0);				
		}
		
		//MAC the remaining length of command buffer
		for(i=0;i<(byte)(5 + (short)(CMD_BUF[ISO7816.OFFSET_LC] & 0xFF) - 8 - (WORDS*8));i++)
			//MACing remaining length of command buffer
			MAC[i]=(byte)((short)(MAC[i] & 0xFF) ^ (short)(CMD_BUF[WORDS*8 + i] & 0xFF));
		//begin MACing padding segment
		MAC[i]=(byte)((short)(MAC[i] & 0xFF) ^ (short)0x80);
		//encrypt MAC operation
		CIPHER_KD_PERSO_L_EN.update(MAC,(short)0,(short)8,MAC,(short)0);

		//decrypt MAC operation
		CIPHER_KD_PERSO_R_DE.doFinal(MAC,(short)0,(short)8,MAC,(short)0);
		
		//encrypt MAC operation
		CIPHER_KD_PERSO_L_EN.doFinal(MAC,(short)0,(short)8,MAC,(short)0);
		
		//compare the MAC that was passed in with the calculated MAC above

		
//!!!!!!!!!!!!!!!!!!!!!!!!don't check the MAC!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!		
		if(Util.arrayCompare(MAC,(short)0,CMD_BUF,(short)(5 + (short)(CMD_BUF[ISO7816.OFFSET_LC] & 0xFF) - 8),(short)8)!=0) 
			ISOException.throwIt(ISO7816.SW_SECURITY_STATUS_NOT_SATISFIED);

		//compare the DGI tags with the ones that were passed
		if(CMD_BUF[ISO7816.OFFSET_CDATA] != (byte)0x01 || CMD_BUF[ISO7816.OFFSET_CDATA+1] != (byte)0x01)	
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		if(CMD_BUF[ISO7816.OFFSET_CDATA+3+(short)(CMD_BUF[ISO7816.OFFSET_CDATA + 2] & 0xFF)] != (byte)0xA0 || 
		   CMD_BUF[ISO7816.OFFSET_CDATA+3+(short)(CMD_BUF[ISO7816.OFFSET_CDATA + 2] & 0xFF)+1] != (byte)0x01)	
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);
		if(CMD_BUF[ISO7816.OFFSET_CDATA+3+(short)(CMD_BUF[ISO7816.OFFSET_CDATA + 2] & 0xFF)+14] != (byte)0xA0 || 
		   CMD_BUF[ISO7816.OFFSET_CDATA+3+(short)(CMD_BUF[ISO7816.OFFSET_CDATA + 2] & 0xFF)+14+1] != (byte)0x02)	
			ISOException.throwIt(ISO7816.SW_WRONG_DATA);

		//we passed all of these tests, now take action on the card
		//transaction starts
		JCSystem.beginTransaction();

		//copy the record data into DGI1010
		PROFILE.DGI0101_LEN = (byte)(CMD_BUF[ISO7816.OFFSET_CDATA + 2] & 0xFF);
		Util.arrayCopyNonAtomic(	CMD_BUF,
									(short)(ISO7816.OFFSET_CDATA + 3),
									PROFILE.DGI0101,
									(short)0,
									(short)(PROFILE.DGI0101_LEN & 0xFF));
		
		//copy Application Control bytes
		Util.arrayCopyNonAtomic(	CMD_BUF,
									(short)(ISO7816.OFFSET_CDATA + 3 + (short)(PROFILE.DGI0101_LEN & 0xFF) + 3),
									PROFILE.AC,
									(short)0,
									(short)3);
		//copy Static CVC3 Track 1 bytes
		Util.arrayCopyNonAtomic(	CMD_BUF,
									(short)(ISO7816.OFFSET_CDATA + 3 + (short)(PROFILE.DGI0101_LEN & 0xFF) + 6),
									PROFILE.CVC3_T1,
									(short)0,
									(short)2);
		//copy Static CVC3 Track 2 bytes
		Util.arrayCopyNonAtomic(	CMD_BUF,
									(short)(ISO7816.OFFSET_CDATA + 3 + (short)(PROFILE.DGI0101_LEN & 0xFF) + 8),
									PROFILE.CVC3_T2,
									(short)0,
									(short)2);
		//copy IVCVC3 Track 1 bytes
		Util.arrayCopyNonAtomic(	CMD_BUF,
									(short)(ISO7816.OFFSET_CDATA + 3 + (short)(PROFILE.DGI0101_LEN & 0xFF) + 10),
									PROFILE.IVCVC3_T1,
									(short)0,
									(short)2);
		//copy IVCVC3 Track 2 bytes
		Util.arrayCopyNonAtomic(	CMD_BUF,
									(short)(ISO7816.OFFSET_CDATA + 3 + (short)(PROFILE.DGI0101_LEN & 0xFF) + 12),
									PROFILE.IVCVC3_T2,
									(short)0,
									(short)2);
		//copy encrypted value of KD_CVC3
		byte [] ENC_KD_CVC3 = new byte[16];
		Util.arrayCopyNonAtomic(	CMD_BUF,
									(short)(ISO7816.OFFSET_CDATA + 3 + (short)(PROFILE.DGI0101_LEN & 0xFF) + 17),
									ENC_KD_CVC3,
									(short)0,
									(short)16);
		//set and initialize the KD_PERSO key used for decryption
		DESKEY_KD_PERSO_L_DE.setKey(PROFILE.KD_PERSO,(short)0);  //left half of key
		CIPHER_KD_PERSO_L_DE.init(DESKEY_KD_PERSO_L_DE, Cipher.MODE_DECRYPT);
		DESKEY_KD_PERSO_R_EN.setKey(PROFILE.KD_PERSO,(short)8);  //right half of key
		CIPHER_KD_PERSO_R_EN.init(DESKEY_KD_PERSO_R_EN, Cipher.MODE_ENCRYPT);
		//decrypt KD_CVC3 (3DES)
		CIPHER_KD_PERSO_L_DE.update(ENC_KD_CVC3,(short)0,(short)16,ENC_KD_CVC3,(short)0);
		CIPHER_KD_PERSO_R_EN.doFinal(ENC_KD_CVC3,(short)0,(short)16,ENC_KD_CVC3,(short)0);
		CIPHER_KD_PERSO_L_DE.doFinal(ENC_KD_CVC3,(short)0,(short)16,ENC_KD_CVC3,(short)0);
		//copy the decrypted value of KD_CVC3 to KD_CVC3
		Util.arrayCopyNonAtomic(	ENC_KD_CVC3,
									(short)0,
									PROFILE.KD_CVC3,
									(short)0,
									(short)16);
		
		//set and initiate keys for encryption during compute cryptographic checksum
		PROFILE.DESKEY_KD_CVC3_L_EN.setKey(PROFILE.KD_CVC3,(short)0);  //left half of key
		PROFILE.CIPHER_KD_CVC3_L_EN.init(PROFILE.DESKEY_KD_CVC3_L_EN, Cipher.MODE_ENCRYPT);
		PROFILE.DESKEY_KD_CVC3_R_DE.setKey(PROFILE.KD_CVC3,(short)8);  //right half of key
		PROFILE.CIPHER_KD_CVC3_R_DE.init(PROFILE.DESKEY_KD_CVC3_R_DE, Cipher.MODE_DECRYPT);
		
		//set Personalization Flag to personalized
		PROFILE.STATE = ALIVE;
		Calendar exp = Calendar.getInstance();
		exp.set(Calendar.YEAR, 2009);
		exp.set(Calendar.MONTH, 5);
		try {
			setStatePersonalized("5413123456784800", exp, "", "");
		} catch (IOException e) {
		}
		//transaction ends
		JCSystem.commitTransaction();
	}
	
	public void process(APDU apdu) {
		
		byte[] buf = apdu.getBuffer();

		if (selectingApplet()) {
			//verify that the class for this instruction is correct
			if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x00)
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			//if the active profile state has not been pre-personalized
			//this application cannot be used
			if(PROFILE.STATE == PRE_PERSO)
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			//check that LC is the length of AID
//			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != (short)AID.length)
//				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

			//return FCI upon successful select
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)(15+AL.length));

			//send Mastercard or Maestro FCI
			buf[0]=(byte)0x6F; //FCI Template
			buf[1]=(byte)(13 + AL.length);   //length
				buf[2]=(byte)0x84; //DF
				buf[3]=(byte)7;    //length
					Util.arrayCopyNonAtomic(DF,(short)0,buf,(short)4,(short)7);
				buf[11]=(byte)0xA5; //FCI Proprietary Template
				buf[12]=(byte)(2+AL.length);    //length
					buf[13]=(byte)0x50; //AL
					buf[14]=(byte)AL.length;   //length
						Util.arrayCopyNonAtomic(AL,(short)0,buf,(short)15,(short)AL.length);

			apdu.sendBytes((short)0,(short)(15+AL.length));
			
			//set state to selected state if the card is alive
			if(PROFILE.STATE == ALIVE) state = selected;
			else state=not_alive;
			return;
		}

		switch (buf[ISO7816.OFFSET_INS]) {
		
		case (byte) 0xA4: //select AID
			//verify that the class for this instruction is correct
			if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x00)
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			//check that P1 & P2 are correct
			if(buf[ISO7816.OFFSET_P1] != (byte) 0x04 || buf[ISO7816.OFFSET_P2] != (byte) 0x00)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			//check that LC is the length of AID
//			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != (short)AID.length)
//				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//otherwise, the file name was wrong for this select
			else ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
		
		case (byte) 0xA8: //get processing options
			//verify that the class for this instruction is correct
			if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x80)
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			//check state - this command only works in selected state
			if(state != selected)
				ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
			//check that P1 & P2 are correct
			if(buf[ISO7816.OFFSET_P1] != (byte) 0x00 || buf[ISO7816.OFFSET_P2] != (byte) 0x00)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			//check that LC is 0x02
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != (short) 0x02)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//check PDOL data that it is '8300'
			if(buf[ISO7816.OFFSET_CDATA] != (byte) 0x83 || buf[ISO7816.OFFSET_CDATA+1] != (byte) 0x00)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			//check to see if ATC has reached its limit
			if(PROFILE.ATC[1]==(byte)0xFF && PROFILE.ATC[0]==(byte)0xFF)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			
			//transaction starts
			JCSystem.beginTransaction();
			
			//increment ATC
			if(PROFILE.ATC[1]==(byte)0xFF) PROFILE.ATC[0] = (byte)((short)(PROFILE.ATC[0] & 0xFF)+1);
			PROFILE.ATC[1] = (byte)((short)(PROFILE.ATC[1] & 0xFF)+1);
			
			//transaction ends
			JCSystem.commitTransaction();
			
			//build response message
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)12);
			
			buf[0]=(byte)0x77; //Response Message Template
			buf[1]=(byte)10;   //length
				buf[2]=(byte)0x82; //Application Interchange Profile
				buf[3]=(byte)2;    //length
					Util.arrayCopyNonAtomic(AIP,(short)0,buf,(short)4,(short)2);
				buf[6]=(byte)0x94; //Application File Locator
				buf[7]=(byte)4;    //length
					Util.arrayCopyNonAtomic(AFL,(short)0,buf,(short)8,(short)4);
			
			apdu.sendBytes((short)0,(short)12);
			state = initiated;
			break;
		
		case (byte) 0xB2: //read record
			//verify that the class for this instruction is correct
			if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x00)
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			//check state - this command does not work in the selected_not_personalized state
			if(state != selected && state !=initiated)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			state = selected;
			//check that P1 & P2 are correct
			if(buf[ISO7816.OFFSET_P1] == (byte) 0x00 || (byte)(buf[ISO7816.OFFSET_P2]&(byte)0x07) != (byte) 0x04)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			//check that SFI is in the range of 1 to 10
			if((byte)(buf[ISO7816.OFFSET_P2]>>3)!=(byte)1 || buf[ISO7816.OFFSET_P1]!=(byte)1)
				ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			//build response message
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)((short)(PROFILE.DGI0101_LEN & 0xFF)+3));
			
			buf[0]=(byte)0x70; //Response Message Template
			buf[1]=(byte)0x81; //??
			buf[2]=PROFILE.DGI0101_LEN;   //length
			apdu.sendBytes((short)0,(short)3);	
				apdu.sendBytesLong(PROFILE.DGI0101,(short)0,(short)(PROFILE.DGI0101_LEN & 0xFF));

			state = initiated;
			break;
		
		case (byte) 0x2A: //compute cryptographic checksum
			//verify that the class for this instruction is correct
			if((short)(buf[ISO7816.OFFSET_CLA] & 0xFF) != 0x80)
				ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
			//check state - this command does not work in the selected_not_personalized state
			if(state != initiated)
				ISOException.throwIt(ISO7816.SW_CONDITIONS_NOT_SATISFIED);
			state = selected;
			//check that P1 & P2 are correct
			if(buf[ISO7816.OFFSET_P1] != (byte) 0x8E || buf[ISO7816.OFFSET_P2] != (byte) 0x80)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			//check that the length of LC is 4
			if(buf[ISO7816.OFFSET_LC] != (byte) 0x04)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			
			//build response message
			apdu.setOutgoing();
			apdu.setOutgoingLength((short)17);

			//check to see if static CVC3 is used and populate accordingly
			if((byte)(PROFILE.AC[2]&(byte)0x80)==(byte)0x80)  //static is used
			{
					//populate CVC3_T2 with static CVC3
					Util.arrayCopyNonAtomic(PROFILE.CVC3_T2,(short)0,buf,(short)5,(short)2);

					//populate CVC3_T1 with static CVC3
					Util.arrayCopyNonAtomic(PROFILE.CVC3_T1,(short)0,buf,(short)10,(short)2);
			}
			else   //dynamic CVC3 is used
			{
				
				//populate left half of CVC3_DATA
				//copy dynamic CVC3_T2 number into array
				Util.arrayCopyNonAtomic(PROFILE.IVCVC3_T2,(short)0,CVC3_DATA,(short)0,(short)2);
				//copy unpredictable number UN into array
				Util.arrayCopyNonAtomic(buf,(short)ISO7816.OFFSET_CDATA,CVC3_DATA,(short)2,(short)4);
				//copy ATC into array if needed
				if((byte)(PROFILE.AC[2]&(byte)0x40)==(byte)0x40)  //ATC is included
					Util.arrayCopyNonAtomic(PROFILE.ATC,(short)0,CVC3_DATA,(short)6,(short)2);
				else
					CVC3_DATA[6]=CVC3_DATA[7]=(byte)0x00;
				
				//populate right half of CVC3_DATA
				//copy dynamic CVC3_T2 number into array
				Util.arrayCopyNonAtomic(PROFILE.IVCVC3_T1,(short)0,CVC3_DATA,(short)8,(short)2);
				//copy unpredictable number UN into array
				Util.arrayCopyNonAtomic(buf,(short)ISO7816.OFFSET_CDATA,CVC3_DATA,(short)10,(short)4);
				//copy ATC into array if needed
				if((byte)(PROFILE.AC[2]&(byte)0x40)==(byte)0x40)  //ATC is included
					Util.arrayCopyNonAtomic(PROFILE.ATC,(short)0,CVC3_DATA,(short)14,(short)2);
				else
					CVC3_DATA[14]=CVC3_DATA[15]=(byte)0x00;
				
				//encrypt CVC3_DATA
				PROFILE.CIPHER_KD_CVC3_L_EN.update(CVC3_DATA,(short)0,(short)16,CVC3_DATA,(short)0);
				PROFILE.CIPHER_KD_CVC3_R_DE.doFinal(CVC3_DATA,(short)0,(short)16,CVC3_DATA,(short)0);
				PROFILE.CIPHER_KD_CVC3_L_EN.doFinal(CVC3_DATA,(short)0,(short)16,CVC3_DATA,(short)0);

					//populate CVC3_T2 with the last two bytes of encrypted key
					Util.arrayCopyNonAtomic(CVC3_DATA,(short)6,buf,(short)5,(short)2);

					//populate CVC3_T1 with the last two bytes of encrypted key
					Util.arrayCopyNonAtomic(CVC3_DATA,(short)14,buf,(short)10,(short)2);	
			}
			
			//building output buffer
			buf[0]=(byte)0x77; //Response Message Template
			buf[1]=(byte)15;   //length
				buf[2]=(byte)0x9F; //CVC3 Track2
				buf[3]=(byte)0x61; //CVC3 Track2
				buf[4]=(byte)2;    //length
				//CVC3_T2 was copied in here
				buf[7]=(byte)0x9F; //CVC3 Track1
				buf[8]=(byte)0x60; //CVC3 Track1
				buf[9]=(byte)2;    //length
				//CVC3_T1 was copied in here
				buf[12]=(byte)0x9F; //ATC Tag
				buf[13]=(byte)0x36; //ATC Tag
				buf[14]=(byte)2; //length
					buf[15]=(byte)0x00;
					buf[16]=(byte)0x00;
//!!!!!!!!!!!!!!!!!!!!set ATC value to 00 00!!!!!!!!!!!!!!!!!!!!!!!!				
					Util.arrayCopyNonAtomic(PROFILE.ATC,(short)0,buf,(short)15,(short)2);
			
			apdu.sendBytes((short)0,(short)17);
			
			//transaction starts
			JCSystem.beginTransaction();
			
			//transaction ends
			JCSystem.commitTransaction();

			break;

			
		//the cases below are only for the "selected not personalized" state
		//once the card is personalized, there is no need for these
		case (byte) 0xCA: //get data
			get_data(apdu,buf);
			break;

		case (byte) 0xE2: //store data
			store_data(apdu,buf);
			break;

		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}
	}
}
