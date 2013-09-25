package com.st;
import javacard.framework.APDU;
import javacard.framework.Applet;
import javacard.framework.ISO7816;
import javacard.framework.ISOException;


public class Ppse2Pay extends Applet {

	private static final long serialVersionUID = 1L;

	//FCI_TEMPLATE - DEFAULT
	private final byte[] ADF = {(byte)0xA0,(byte)0x00,(byte)0x00,(byte)0x00,  //Visa
											(byte)0x04,(byte)0x10,(byte)0x10			};
	
	//DF - Dedicated File (AID) - '2PAY.SYS.DDF01'
	public final byte[] DF = {(byte)0x32,(byte)0x50,(byte)0x41,(byte)0x59,
								(byte)0x2E,(byte)0x53,(byte)0x59,(byte)0x53,
								(byte)0x2E,(byte)0x44,(byte)0x44,(byte)0x46,
								(byte)0x30,(byte)0x31						};
	
	public byte[] FCI_TEMPLATE = null;
	
	public static void install(byte[] bArray, short bOffset, byte bLength){
		new Ppse2Pay().register();
	}

	@Override
	public void process(APDU apdu) throws ISOException {
		byte[] buf = apdu.getBuffer();

		if (selectingApplet()) {
			//check that LC is 0x0E
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != 0x0E)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			
			if(FCI_TEMPLATE==null)
			{
				FCI_TEMPLATE = new byte[12 + ADF.length];
				FCI_TEMPLATE[0]=(byte)0xA5; //FCI Proprietary Template
				FCI_TEMPLATE[1]=(byte)(10 + ADF.length);   //length
					FCI_TEMPLATE[2]=(byte)0xBF; //FCI Issuer Discretionary Data
					FCI_TEMPLATE[3]=(byte)0x0C;
					FCI_TEMPLATE[4]=(byte)(7 + ADF.length);   //length

					FCI_TEMPLATE[5]=(byte)0x61; //Directory Entry
					FCI_TEMPLATE[6]=(byte)(ADF.length + 5);   //length
						FCI_TEMPLATE[7]=(byte)0x4F; //ADF Name
						FCI_TEMPLATE[8]=(byte)(ADF.length);    //length
						for(short i=0;i<ADF.length;i++)
							FCI_TEMPLATE[9+i] = ADF[i];
						FCI_TEMPLATE[9 + ADF.length]=(byte)0x87; //Application Priority Indicator
						FCI_TEMPLATE[10 + ADF.length]=(byte)1;    //length
						FCI_TEMPLATE[11 + ADF.length]=(byte)0x01;
			}
			
			//return FCI upon successful select
			apdu.setOutgoing();

			buf[0]=(byte)0x6F; //FCI Template
			buf[1]=(byte)(2 + DF.length + FCI_TEMPLATE.length);   //length
				buf[2]=(byte)0x84; //DF Name
				buf[3]=(byte)DF.length;   //length
				for(short i=0;i<DF.length;i++)
					buf[4+i] = DF[i];
				for(short i=0;i<FCI_TEMPLATE.length;i++)
					buf[4 + DF.length + i] = FCI_TEMPLATE[i];
			apdu.setOutgoingLength((short)(4 + DF.length + FCI_TEMPLATE.length));
			apdu.sendBytes((short)0,(short)(4 + DF.length + FCI_TEMPLATE.length));
			return;
		}
		
		switch (buf[ISO7816.OFFSET_INS]) {

		case (byte) 0xA4: //select PPSE
			//check that P1 & P2 are correct
			if(buf[ISO7816.OFFSET_P1] != (byte) 0x04 || buf[ISO7816.OFFSET_P2] != (byte) 0x00)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			//check that LC is 0x0E
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != 0x0E)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//otherwise, the file name was wrong for this select
			else ISOException.throwIt(ISO7816.SW_FILE_NOT_FOUND);
			
		case (byte) 0xEE: //loopback
			//check that P1 & P2 are correct
			if(buf[ISO7816.OFFSET_P1] != (byte) 0x00 || buf[ISO7816.OFFSET_P2] != (byte) 0x00)
				ISOException.throwIt(ISO7816.SW_INCORRECT_P1P2);
			//check that the length byte is within the spec (1-250)
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) < 1 || (short)(buf[ISO7816.OFFSET_LC] & 0xFF) > 250)
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);
			//get the rest of the apdu and check length
			if((short)(buf[ISO7816.OFFSET_LC] & 0xFF) != apdu.setIncomingAndReceive())
				ISOException.throwIt(ISO7816.SW_WRONG_LENGTH);

			short len = buf[ISO7816.OFFSET_LC];
			for(short i=0;i<len;i++)
				buf[i] = buf[i+5];
			apdu.setOutgoingLength(len);
			apdu.sendBytes((short)0,len);
			break;
		
		default:
			// good practice: If you don't know the INStruction, say so:
			ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
		}


	}


}
