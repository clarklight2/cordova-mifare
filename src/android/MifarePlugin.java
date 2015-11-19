
package se.frostyelk.cordova.mifare;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import com.nxp.nfclib.classic.IMFClassic;
import com.nxp.nfclib.exceptions.PlusException;
import com.nxp.nfclib.exceptions.ReaderException;
import com.nxp.nfclib.exceptions.SAMException;
import com.nxp.nfclib.exceptions.SmartCardException;
import com.nxp.nfclib.icode.ICodeSLI;
import com.nxp.nfclib.icode.IICodeSLI;
import com.nxp.nfclib.icode.IICodeSLIL;
import com.nxp.nfclib.icode.IICodeSLIS;
import com.nxp.nfclib.icode.IICodeSLIX;
import com.nxp.nfclib.icode.IICodeSLIX2;
import com.nxp.nfclib.icode.IICodeSLIXL;
import com.nxp.nfclib.icode.IICodeSLIXS;
import com.nxp.nfclib.ndef.FormatException;
import com.nxp.nfclib.ndef.NdefMessage;
import com.nxp.nfclib.ndef.NdefRecord;
import com.nxp.nfclib.ntag.INTag;
import com.nxp.nfclib.ntag.INTag203x;
import com.nxp.nfclib.ntag.INTag210;
import com.nxp.nfclib.ntag.INTag213215216;
import com.nxp.nfclib.ntag.INTag213F216F;
import com.nxp.nfclib.ntag.INTagI2C;
import com.nxp.nfclib.plus.IPlusSL1;
import com.nxp.nfclib.ultralight.IUltralight;
import com.nxp.nfclib.ultralight.IUltralightC;
import com.nxp.nfclib.ultralight.IUltralightEV1;
import com.nxp.nfclib.utils.NxpLogUtils;
import com.nxp.nfclib.utils.Utilities;
import com.nxp.nfcliblite.Interface.NxpNfcLibLite;
import com.nxp.nfcliblite.Interface.Nxpnfcliblitecallback;
import com.nxp.nfcliblite.cards.IDESFireEV1;
import com.nxp.nfcliblite.cards.IPlus;

import com.nxp.nfcliblite.cards.Plus;
import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.apache.cordova.PluginResult.Status;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

/**
 * This class represents the native implementation for the MIFARE Cordova plugin.
 */
public class MifarePlugin extends CordovaPlugin {

    private static final String LOGTAG = "MifarePlugin";
    private static final String ACTION_INIT = "init";
    private static final String ACTION_WRITE_TAG_DATA = "writeTag";
    private static final String TAG_EVENT_DETECTED = "onTagDetected";
    private static final String TAG_EVENT_ERROR = "onTagError";
    private static final String TAG_EVENT_ERROR_TYPE_SECURITY = "Security";
    private static final String TAG_EVENT_ERROR_TYPE_IOREAD = "IORead";
    private static final String TAG_EVENT_ERROR_TYPE_CARD = "Card";
    private static final String TAG_EVENT_ERROR_TYPE_UNSUPPORTED = "Unsupported";
    private static final int UNIVERSAL_NUMBER = 42;
    private static final int MAX_FAST_READ_PAGES = 50;
    private static String TAG = "MifarePLugin";

    private String password;
    private byte[] payload;
 
    private Tag tagInfo;
    private Intent initializeIntent;
    
 
	/** Create lib lite instance. */
	private NxpNfcLibLite libInstance = null;
	/** Mifare DESFire instance initiated. */
	private IDESFireEV1 mDESFire;

	/** Mifare MFClassic instance initiated. */
	private IMFClassic classic;
	/** Mifare Ultralight instance initiated. */
	private IUltralight mifareUL;
	/** Mifare Ultralight instance initiated. */
	private IUltralightC objUlCardC;
	/** Mifare Ultralight EV1 instance initiated. */
	private IUltralightEV1 objUlCardEV1;
	/** Mifare Plus instance initiated. */
	private IPlus plus;

	/** Mifare Plus SL1 instance initiated. */
	private IPlusSL1 plusSL1;

	/** ICode SLI instance initiated. */
	private IICodeSLI iCodeSli;
	/** ICode SLI-L instance initiated. */
	private IICodeSLIL iCodeSliL;
	/** ICode SLI-S instance initiated. */
	private IICodeSLIS iCodeSliS;
	/** ICode SLI-X instance initiated. */
	private IICodeSLIX iCodeSliX;
	/** ICode SLI-XL instance initiated. */
	private IICodeSLIXL iCodeSliXL;
	/** ICode SLI-XS instance initiated. */
	private IICodeSLIXS iCodeSliXS;
	/** ICode SLIX2 instance initiated. */
	private IICodeSLIX2 iCodeSliX2;

	/** Create imageView instance. */

	// private static Handler mHandler;
	/** Create Textview instance initiated. */
	private TextView tv = null;
	/**
	 * Ultralight First User Memory Page Number.
	 */
	private static final int DEFAULT_PAGENO_ULTRALIGHT = 4;
	/**
	 * Variable DATA Contain a String.
	 */
	private static final String DATA = "This is the data";

	/**
	 * KEY_APP_MASTER key used for encrypt data.
	 */
	private static final String KEY_APP_MASTER = "This is my key  ";
	/** */
	private byte[] bytesKey = null;
	/** */
	private Cipher cipher = null;
	/** */
	private IvParameterSpec iv = null;

    // It seems that password errors returns as IOException instead of SmartCardException?!
    private boolean checkForPasswordSentAtIOError = false;

       public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
            
            
  	showMessage("Card Detected : " + mDESFire.getCardDetails().cardName,
				'n');
        
            
            
            
              if (ACTION_INIT.equals(action)) {
            result = init(args.getJSONObject(0), callbackContext);
        } else if (ACTION_WRITE_TAG_DATA.equals(action)) {
            result = writeTag(args.getJSONObject(0), callbackContext);
        } else if (ACTION_AUTHENTICATE.equals(action)) {

     result = authenticate(args.getJSONObject(0), callbackContext);
            
 }else if (ACTION_ENCRYPT.equals(action)) {

     result = encrypt(args.getJSONObject(0), callbackContext);
            
              
              }
          return true;
            
    }


private void initializeCipherinitVector() {

		/* Initialize the Cipher */
		try {
			cipher = Cipher.getInstance("AES/CBC/NoPadding");
		} catch (NoSuchAlgorithmException e) {

			e.printStackTrace();
		} catch (NoSuchPaddingException e) {

			e.printStackTrace();
		}

		/* set Application Master Key */
		bytesKey = KEY_APP_MASTER.getBytes();

		/* Initialize init vector of 16 bytes with 0xCD. It could be anything */
		byte[] ivSpec = new byte[16];
		Arrays.fill(ivSpec, (byte) 0xCD);
		iv = new IvParameterSpec(ivSpec);

	}

	/**
	 * Disclaimer Section contain Details About product.
	 */


	/**
	 * Read Me section contain Help and About product.
	 */

	/**
	 * Initializing the UI thread.
	 */

	private void showCardDetails(Object cardDetailsObj) {/*
														 * // showMessage(dump(
														 * cardDetailsObj) ,
														 * 'd'); StringBuilder
														 * strBuilder = new
														 * StringBuilder();
														 * strBuilder
														 * .append("Card Details"
														 * );
														 * strBuilder.append("\n"
														 * ); Field[] flds =
														 * cardDetailsObj
														 * .getClass
														 * ().getDeclaredFields
														 * (); for (Field fd :
														 * flds) { try {
														 * fd.setAccessible
														 * (true); Object value
														 * =
														 * fd.get(cardDetailsObj
														 * ); if (value != null)
														 * { if
														 * (value.getClass()
														 * .isPrimitive() ||
														 * value.getClass() ==
														 * java.lang.Long.class
														 * || value.getClass()
														 * ==
														 * java.lang.String.class
														 * || value.getClass()
														 * ==
														 * java.lang.Integer.class
														 * || value.getClass()
														 * ==
														 * java.lang.Boolean.class
														 * || value.getClass()
														 * ==
														 * java.lang.Double.class
														 * || value.getClass()
														 * ==
														 * java.lang.Short.class
														 * || value.getClass()
														 * ==
														 * java.lang.Byte.class)
														 * {
														 * strBuilder.append(fd
														 * .getName() + "-->" +
														 * value); } else { if
														 * (fd
														 * .getName().toString
														 * ().equals("this$0"))
														 * { continue; }
														 * strBuilder
														 * .append(fd.getName()
														 * + "-->");
														 * strBuilder.append
														 * ("["); for (int i =
														 * 0; i <
														 * Array.getLength
														 * (value); i++) {
														 * Object value2 =
														 * Array.get(value, i);
														 * if
														 * (value2.getClass().
														 * isPrimitive() ||
														 * value2.getClass() ==
														 * java.lang.Long.class
														 * || value2.getClass()
														 * ==
														 * java.lang.Integer.class
														 * || value2.getClass()
														 * ==
														 * java.lang.Boolean.class
														 * || value2.getClass()
														 * ==
														 * java.lang.String.class
														 * || value2.getClass()
														 * ==
														 * java.lang.Double.class
														 * || value2.getClass()
														 * ==
														 * java.lang.Short.class
														 * || value2.getClass()
														 * ==
														 * java.lang.Byte.class)
														 * {
														 * 
														 * 
														 * if(value2.toString().
														 * length() == 1) {
														 * strBuilder
														 * .append("0x0" +
														 * Integer
														 * .toHexString(Integer
														 * .parseInt
														 * (value2.toString
														 * ()))); } else {
														 * strBuilder
														 * .append("0x" +
														 * Integer
														 * .toHexString(Integer
														 * .parseInt
														 * (value2.toString
														 * ()))); } if (i !=
														 * (Array
														 * .getLength(value) -
														 * 1))
														 * strBuilder.append(
														 * ","); } }
														 * strBuilder.append
														 * ("]"); } } } catch
														 * (IllegalAccessException
														 * e) {
														 * strBuilder.append
														 * (e.getMessage()); }
														 * strBuilder
														 * .append("\n"); }
														 * 
														 * showMessage(strBuilder
														 * .toString(), 'd');
														 */
	}

	@Override
	protected void onNewIntent(final Intent intent) {
 
	

		// MifareUltralight.get(tag)
		libInstance.filterIntent(intent, new Nxpnfcliblitecallback() {

			@Override
			public void onUltraLightCardDetected(final IUltralight objUlCard) {
				mifareUL = objUlCard;
				/* Insert your logic here by commenting the function call below. */
				try {
					mifareUL.getReader().connect();
					ultralightCardLogic();
				} catch (Throwable t) {
					t.printStackTrace();
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onUltraLightCCardDetected(final IUltralightC ulC) {
				objUlCardC = ulC;
				/*
				 * Insert your logic here by commenting the function call below
				 */
				try {
					objUlCardC.getReader().connect();
					ultralightcCardLogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}

			}

			@Override
			public void onUltraLightEV1CardDetected(final IUltralightEV1 ulEV1) {
				objUlCardEV1 = ulEV1;
				/*
				 * Insert your logic here by commenting the function call below
				 */
				try {
					objUlCardEV1.getReader().connect();
					ultralightEV1CardLogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onClassicCardDetected(final IMFClassic objMFCCard) {
				classic = objMFCCard;
				/* Insert your logic here by commenting the function call below. */
				try {
					classic.getReader().connect();
					classicCardLogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onDESFireCardDetected(final IDESFireEV1 objDESFire) {
				mDESFire = objDESFire;
				/* Insert your logic here by commenting the function call below. */
				try {
					mDESFire.getReader().close();
					mDESFire.getReader().connect();
					desfireCardLogic();
				} catch (Throwable t) {
					t.printStackTrace();
					showMessage("Unknown Error Tap Again!", 't');
				}

			}

			@Override
			public void onPlusCardDetected(final IPlus objMFPlus) {
				plus = objMFPlus;
				try {
					plus.getReader().connect();
					plusCardLogic();
				} catch (Throwable t) {
					t.printStackTrace();
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onPlusSL1CardDetected(IPlusSL1 objPlusSL1) {
				plusSL1 = objPlusSL1;
				classic = objPlusSL1; // Plus SL1 is completely compatible with
										// Classic!!
				try {
					plusSL1.getReader().connect();
					PlusSL1CardLogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onICodeSLIDetected(final IICodeSLI objiCodesli) {
				iCodeSli = objiCodesli;

				try {
					iCodeSli.getReader().connect();
					iCodeSLILogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onICodeSLILDetected(final IICodeSLIL objiCodeslil) {
				iCodeSliL = objiCodeslil;

				try {
					iCodeSliL.getReader().connect();
					iCodeSLIlLogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onICodeSLISDetected(final IICodeSLIS objiCodeslis) {
				iCodeSliS = objiCodeslis;

				try {
					iCodeSliS.getReader().connect();
					iCodeSLIsLogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onICodeSLIXDetected(final IICodeSLIX objiCodeslix) {
				iCodeSliX = objiCodeslix;

				try {
					iCodeSliX.getReader().connect();
					iCodeSLIxLogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onICodeSLIXLDetected(final IICodeSLIXL objiCodeslixl) {
				iCodeSliXL = objiCodeslixl;

				try {
					iCodeSliXL.getReader().connect();
					iCodeSLIxlLogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onICodeSLIXSDetected(final IICodeSLIXS objiCodeslixs) {
				iCodeSliXS = objiCodeslixs;

				try {
					iCodeSliXS.getReader().connect();
					iCodeSLIxsLogic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}
			}

			@Override
			public void onICodeSLIX2Detected(final IICodeSLIX2 objiCodeslix2) {
				iCodeSliX2 = objiCodeslix2;

				try {
					iCodeSliX2.getReader().connect();
					iCodeSLIx2Logic();
				} catch (Throwable t) {
					showMessage("Unknown Error Tap Again!", 't');
				}

			}

			@Override
			public void onNTag203xCardDetected(final INTag203x objnTag203x) {
				try {
					objnTag203x.getReader().connect();
					ntagCardLogic(objnTag203x);
				} catch (ReaderException e) {
					 
					e.printStackTrace();
				}
			}

			@Override
			public void onNTag210CardDetected(final INTag210 objnTag210) {
				try {
					objnTag210.getReader().connect();
					ntagCardLogic(objnTag210);
				} catch (ReaderException e) {
					 
					e.printStackTrace();
				}
			}

			@Override
			public void onNTag213215216CardDetected(
					final INTag213215216 objnTag213215216) {
				try {
					objnTag213215216.getReader().connect();
					ntagCardLogic(objnTag213215216);
				} catch (ReaderException e) {
					 
					e.printStackTrace();
				}

			}

			@Override
			public void onNTag213F216FCardDetected(
					final INTag213F216F objnTag213216f) {
				try {
					objnTag213216f.getReader().connect();
					ntagCardLogic(objnTag213216f);
				} catch (ReaderException e) {
					 
					e.printStackTrace();
				}

			}

			@Override
			public void onNTagI2CCardDetected(final INTagI2C objnTagI2c) {
				try {
					objnTagI2c.getReader().connect();
					ntagCardLogic(objnTagI2c);
				} catch (Exception e) {
					 
					e.printStackTrace();
				}
			}
		});
	}

	/**
	 * iCode SLIXS Card Logic.
	 */
	protected void iCodeSLIxsLogic() {
 

		showImageSnap(R.drawable.icode_p);
		tv.setText(" ");
		/* Get the Icode label name. */
		showMessage("Card Detected : " + iCodeSliXS.getTagName(), 'n');

		try {
			/* Get the UID */
			byte[] uid = iCodeSliXS.getUID();
			/* Display message in text view */
			showMessage("uid: " + Utilities.dumpBytes(uid), 'd');
			/* It should contain four bytes of data to be write. */
			byte[] writeData = { (byte) 0x01, (byte) 0x02, (byte) 0x03,
					(byte) 0x04 };
			/* Display message in text view */
			showMessage("Write: " + Utilities.dumpBytes(writeData), 'd');
			/* Write the data in specified block. */
			iCodeSliXS.writeSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5,
					writeData);
			/* Read the data in specified block. */
			byte[] read = iCodeSliXS.readSingleBlock(
					ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5);
			/* Display message in text view. */
			showMessage("Read: " + Utilities.dumpBytes(read), 'd');
			showCardDetails(iCodeSliXS.getCardDetails());
			/* Close the connection. */
			iCodeSliXS.getReader().close();

		} catch (IOException e) {
			showMessage("IO Exception -  Check logcat!", 't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			showMessage("SmartCard Exception - Check logcat!", 't');
			e.printStackTrace();
		} catch (Throwable t) {
			showMessage("Exception - Check logcat!", 't');
			t.printStackTrace();
		}

	}

	protected void iCodeSLIxlLogic() {
 

		showImageSnap(R.drawable.icode_p);
		tv.setText(" ");
		/* Get the Icode label name. */
		showMessage("Card Detected : " + iCodeSliXL.getTagName(), 'n');

		try {
			/* Get the UID */
			byte[] uid = iCodeSliXL.getUID();
			/* Display message in text view */
			showMessage("uid: " + Utilities.dumpBytes(uid), 'd');
			/* It should contain four bytes of data to be write. */
			byte[] writeData = { (byte) 0x01, (byte) 0x02, (byte) 0x03,
					(byte) 0x04 };
			/* Display message in text view */
			showMessage("Write: " + Utilities.dumpBytes(writeData), 'd');
			/* Write the data in specified block. */
			iCodeSliXL.writeSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5,
					writeData);
			/* Read the data in specified block. */
			byte[] read = iCodeSliXL.readSingleBlock(
					ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5);
			/* Display message in text view. */
			showMessage("Read: " + Utilities.dumpBytes(read), 'd');
			showCardDetails(iCodeSliXL.getCardDetails());
			/* Close the connection. */
			iCodeSliXL.getReader().close();

		} catch (IOException e) {
			showMessage("IO Exception -  Check logcat!", 't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			showMessage("SmartCard Exception - Check logcat!", 't');
			e.printStackTrace();
		} catch (Throwable t) {
			showMessage("Exception - Check logcat!", 't');
			t.printStackTrace();
		}

	}

	/**
	 * iCode SLIX Card Logic.
	 */
	protected void iCodeSLIxLogic() {
 

		showImageSnap(R.drawable.icode_p);
		tv.setText(" ");
		/* Get the Icode label name. */
		showMessage("Card Detected : " + iCodeSliX.getTagName(), 'n');

		try {
			/* Get the UID */
			byte[] uid = iCodeSliX.getUID();
			/* Display message in text view */
			showMessage("uid: " + Utilities.dumpBytes(uid), 'd');
			/* It should contain four bytes of data to be write. */
			byte[] writeData = { (byte) 0x01, (byte) 0x02, (byte) 0x03,
					(byte) 0x04 };
			/* Display message in text view */
			showMessage("Write: " + Utilities.dumpBytes(writeData), 'd');
			/* Write the data in specified block. */
			iCodeSliX.writeSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5,
					writeData);
			/* Read the data in specified block. */
			byte[] read = iCodeSliX.readSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS,
					(byte) 5);
			/* Display message in text view. */
			showMessage("Read: " + Utilities.dumpBytes(read), 'd');
			showCardDetails(iCodeSliX.getCardDetails());
			/* Close the connection. */
			iCodeSliX.getReader().close();

		} catch (IOException e) {
			showMessage("IO Exception -  Check logcat!", 't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			showMessage("SmartCard Exception - Check logcat!", 't');
			e.printStackTrace();
		} catch (Throwable t) {
			showMessage("Exception - Check logcat!", 't');
			t.printStackTrace();
		}
	}

	/**
	 * iCode slis Card Logic.
	 */
	protected void iCodeSLIsLogic() {
 

		showImageSnap(R.drawable.icode_p);
		tv.setText(" ");
		/* Get the Icode label name. */
		showMessage("Card Detected : " + iCodeSliS.getTagName(), 'n');

		try {
			/* Get the UID */
			byte[] uid = iCodeSliS.getUID();
			/* Display message in text view */
			showMessage("uid: " + Utilities.dumpBytes(uid), 'd');
			/* It should contain four bytes of data to be write. */
			byte[] writeData = { (byte) 0x01, (byte) 0x02, (byte) 0x03,
					(byte) 0x04 };
			/* Display message in text view */
			showMessage("Write: " + Utilities.dumpBytes(writeData), 'd');
			/* Write the data in specified block. */
			iCodeSliS.writeSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5,
					writeData);
			/* Read the data in specified block. */
			byte[] read = iCodeSliS.readSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS,
					(byte) 5);
			/* Display message in text view. */
			showMessage("Read: " + Utilities.dumpBytes(read), 'd');
			showCardDetails(iCodeSliS.getCardDetails());
			/* Close the connection. */
			iCodeSliS.getReader().close();

		} catch (TagLostException e) {
			showMessage("TagLost Exception - Tap Again!", 't');
			e.printStackTrace();
		} catch (IOException e) {
			showMessage("IO Exception -  Check logcat!", 't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			showMessage("SmartCard Exception - Check logcat!", 't');
			e.printStackTrace();
		} catch (Throwable t) {
			showMessage("Exception - Check logcat!", 't');
			t.printStackTrace();
		}

	}

	/**
	 * icode sli card logic.
	 */
	protected void iCodeSLILogic() {

		showImageSnap(R.drawable.icode_p);
		tv.setText(" ");
		/* Get the Icode label name. */
		showMessage("Card Detected : " + iCodeSli.getTagName(), 'n');

		try {
			/* Get the UID */
			byte[] uid = iCodeSli.getUID();
			/* Display message in text view */
			showMessage("uid: " + Utilities.dumpBytes(uid), 'd');
			/* It should contain four bytes of data to be write. */
			byte[] writeData = { (byte) 0x01, (byte) 0x02, (byte) 0x03,
					(byte) 0x04 };
			/* Display message in text view */
			showMessage("Write: " + Utilities.dumpBytes(writeData), 'd');
			/* Write the data in specified block. */
			iCodeSli.writeSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5,
					writeData);
			/* Read the data in specified block. */
			byte[] read = iCodeSli.readSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS,
					(byte) 5);
			/* Display message in text view. */
			showMessage("Read: " + Utilities.dumpBytes(read), 'd');
			showCardDetails(iCodeSli.getCardDetails());
			/* Close the connection. */
			iCodeSli.getReader().close();

		} catch (TagLostException e) {
			showMessage("TagLost Exception - Tap Again!", 't');
			e.printStackTrace();
		} catch (IOException e) {
			showMessage("IO Exception -  Check logcat!", 't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			showMessage("SmartCard Exception - Check logcat!", 't');
			e.printStackTrace();
		} catch (Throwable t) {
			showMessage("Exception - Check logcat!", 't');
			t.printStackTrace();
		}
	}

	/**
	 * icode sli card logic.
	 */
	protected void iCodeSLIlLogic() {

		showImageSnap(R.drawable.icode_p);
		tv.setText(" ");
		/* Get the Icode label name. */
		showMessage("Card Detected : " + iCodeSliL.getTagName(), 'n');

		try {
			/* Get the UID */
			byte[] uid = iCodeSliL.getUID();
			/* Display message in text view */
			showMessage("uid: " + Utilities.dumpBytes(uid), 'd');
			/* It should contain four bytes of data to be write. */
			byte[] writeData = { (byte) 0x01, (byte) 0x02, (byte) 0x03,
					(byte) 0x04 };
			/* Display message in text view */
			showMessage("Write: " + Utilities.dumpBytes(writeData), 'd');
			/* Write the data in specified block. */
			iCodeSliL.writeSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5,
					writeData);
			/* Read the data in specified block. */
			byte[] read = iCodeSliL.readSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS,
					(byte) 5);
			/* Display message in text view. */
			showMessage("Read: " + Utilities.dumpBytes(read), 'd');
			showCardDetails(iCodeSliL.getCardDetails());
			/* Close the connection. */
			iCodeSliL.getReader().close();

		} catch (TagLostException e) {
			showMessage("TagLost Exception - Tap Again!", 't');
			e.printStackTrace();
		} catch (IOException e) {
			showMessage("IO Exception -  Check logcat!", 't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			showMessage("SmartCard Exception - Check logcat!", 't');
			e.printStackTrace();
		} catch (Throwable t) {
			showMessage("Exception - Check logcat!", 't');
			t.printStackTrace();
		}

	}

	/**
	 * icode slix2 card logic.
	 */
	protected void iCodeSLIx2Logic() {

		showImageSnap(R.drawable.icode_p);
		tv.setText(" ");
		/* Get the Icode label name. */
		showMessage("Card Detected : " + iCodeSliX2.getTagName(), 'n');

		try {
			/* Get the UID */
			byte[] uid = iCodeSliX2.getUID();
			/* Display message in text view */
			showMessage("uid: " + Utilities.dumpBytes(uid), 'd');
			/* It should contain four bytes of data to be write. */
			byte[] writeData = { (byte) 0x01, (byte) 0x02, (byte) 0x03,
					(byte) 0x04 };
			/* Display message in text view */
			showMessage("Write: " + Utilities.dumpBytes(writeData), 'd');
			/* Write the data in specified block. */
			iCodeSliX2.writeSingleBlock(ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5,
					writeData);
			/* Read the data in specified block. */
			byte[] read = iCodeSliX2.readSingleBlock(
					ICodeSLI.NFCV_FLAG_ADDRESS, (byte) 5);
			/* Display message in text view. */
			showMessage("Read: " + Utilities.dumpBytes(read), 'd');
			/* Close the connection. */
			iCodeSliX2.getReader().close();

		} catch (TagLostException e) {
			showMessage("TagLost Exception - Tap Again!", 't');
			e.printStackTrace();
		} catch (IOException e) {
			showMessage("IO Exception -  Check logcat!", 't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			showMessage("SmartCard Exception - Check logcat!", 't');
			e.printStackTrace();
		} catch (Throwable t) {
			showMessage("Exception - Check logcat!", 't');
			t.printStackTrace();
		}

	}

	/**
	 * Mifare DESFire Card Logic.
	 * 
	 * @throws SmartCardException
	 */
	protected void desfireCardLogic() throws SmartCardException {

		showImageSnap(R.drawable.desfire_ev1);
		tv.setText(" ");
		showMessage("Card Detected : " + mDESFire.getCardDetails().cardName,
				'n');

		try {
			mDESFire.getReader().setTimeout(2000);
			testDESFirepersonalize();
			testDESFireauthenticate();
			testDESFireupdatePICCMasterKey();
			testDESFireauthenticate();
			testDESFireupdateApplicationMasterKey();
			testDESFireauthenticate();
			testDESFireWrite();
			testDESFireRead();
			mDESFire.getReader().setTimeout(2000);
			showCardDetails(mDESFire.getCardDetails());
			testDESFireFormat();
			mDESFire.getReader().close();
		} catch (ReaderException e) {
			 
			e.printStackTrace();
		}
	}

	/**
	 * Ntag Operations are, getTagname(), getUID(), Write and Read.
	 * 
	 * @param tag
	 *            object
	 */
	private void ntagCardLogic(final INTag tag) {

		showImageSnap(R.drawable.ntag_p);
		tv.setText(" ");
		showMessage("Card Detected : " + tag.getTagName(), 'd');

		try {
			NxpLogUtils.d(TAG, "testBasicNtagFunctionality, start");

			showMessage("UID of the Tag: " + Utilities.dumpBytes(tag.getUID()),
					'd');
			showMessage("Tag Name: " + tag.getType().name(), 'd');
			for (int idx = tag.getFirstUserpage(); (idx < tag.getLastUserPage())
					&& idx <= 5; idx++) {
				byte[] data = new byte[] { (byte) idx, (byte) idx, (byte) idx,
						(byte) idx };
				tag.write(idx, data);
				showMessage("Written 4 Bytes Data at page No= " + idx + " "
						+ Utilities.dumpBytes(data), 'd');
			}
			for (int idx = tag.getFirstUserpage(); (idx < tag.getLastUserPage())
					&& idx <= 5; idx++) {
				showMessage("Read 16 Bytes of Data from page No= " + idx + " "
						+ Utilities.dumpBytes(tag.read(idx)), 'd');
			}
			//showCardDetails(tag.getCardDetails());
			tag.getReader().close();
			NxpLogUtils.d(TAG, "testBasicNtagFunctionality, End");
		} catch (TagLostException e) {
			showMessage("TagLost Exception - Tap Again!", 't');
			e.printStackTrace();
		} catch (IOException e) {
			
			showMessage("IO Exception -  Check logcat!", 't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			showMessage("SmartCard Exception - Check logcat!", 't');
			e.printStackTrace();
		} catch (Throwable t) {
			showMessage("Exception - Check logcat!", 't');
			t.printStackTrace();
		}
	}

	/** DESFire read IO Operations. */
	private void testDESFireRead() {

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFireRead, start");
			byte[] data = mDESFire.read(5);
			res = true;
			showMessage(
					"Data Read from the card..." + Utilities.dumpBytes(data),
					'd');
		} catch (SmartCardException e) {
			showMessage("Data Read from the card: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireRead, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireRead, End");
	}

	/** DESFire Write IO Operations. */
	private void testDESFireWrite() {

		byte[] data = new byte[] { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
				0x11 };

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFireWrite, start");
			mDESFire.write(data);
			res = true;
			showMessage("Data Written: " + Utilities.dumpBytes(data), 'd');
		} catch (SmartCardException e) {
			showMessage("Data Written: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireWrite, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireWrite, End");

	}

	/** DESFire Update Application master key IO Operations. */
	private void testDESFireupdateApplicationMasterKey() {
		byte[] oldKey = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		byte[] newKey = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		byte[] masterKey = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		byte[] appId = { 0x12, 0x12, 0x12 };
		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFireupdateApplicationMasterKey, start");
			mDESFire.updateApplicationMasterKey(masterKey, appId, oldKey,
					newKey);
			res = true;
			showMessage("Update Application MasterKey: " + res, 'd');
		} catch (SmartCardException e) {
			showMessage("Update Application MasterKey: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireupdateApplicationMasterKey, result is "
				+ res);
		NxpLogUtils.d(TAG, "testDESFireupdateApplicationMasterKey, End");
	}

	/** DESFire Authenticate IO Operations . */
	private void testDESFireauthenticate() {
		byte[] masterKey = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		byte[] appId = { 0x12, 0x12, 0x12 };
		byte[] appkey = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFireauthenticate, start");
			mDESFire.authenticate(masterKey, appId, appkey);
			res = true;
			showMessage("Authenticate: " + res, 'd');
		} catch (SmartCardException e) {
			showMessage("Authenticate: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireauthenticate, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireauthenticate, End");
	}

	/** DESFire personalize Operations. */
	private void testDESFirepersonalize() {
		byte[] mykey = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		byte[] appKey = new byte[] { 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFirepersonalize, start");

			mDESFire.personalize(mykey, new byte[] { 0x12, 0x12, 0x12 }, appKey);
			res = true;
			showMessage("personalize: " + res, 'd');
		} catch (SmartCardException e) {
			showMessage("personalize: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFirepersonalize, result is " + res);
		NxpLogUtils.d(TAG, "testDESFirepersonalize, End");

	}

	/** DESFire update PICC Master key Operations . */
	private void testDESFireupdatePICCMasterKey() {
		byte[] oldKey = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		byte[] newKey = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFireupdatePICCMasterKey, start");
			mDESFire.updatePICCMasterKey(oldKey, newKey);
			res = true;
			showMessage("DESFire Update PICC Master Key: " + res, 'd');
		} catch (SmartCardException e) {
			showMessage("DESFire Update PICC Master Key: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireupdatePICCMasterKey, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireupdatePICCMasterKey, End");

	}

	/** DESFire Format Operations . */
	private void testDESFireFormat() {
		byte[] mykey = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFireFormat, start");
			mDESFire.format(mykey);
			res = true;
			showMessage("Format: " + res, 'd');
		} catch (SmartCardException e) {
			showMessage("Format: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireFormat, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireFormat, End");
	}

	/**
	 * Mifare classic Card Logic.
	 * 
	 * @throws SmartCardException
	 */
	public void classicCardLogic() throws SmartCardException {

		showImageSnap(R.drawable.classic);
		tv.setText(" ");
		showMessage("Card Detected : " + classic.getCardDetails().cardName, 'n');

		try {
			showMessage("Uid :" + Utilities.dumpBytes(classic.getUID()), 'd');
			classic.getReader().setTimeout(2000);
			testClassicformat();
			testClassicpersonalize();
			testClassicupdateMasterKey();
			testClassicauthenticate();
			testClassicWrite();
			testClassicRead();
			// byte[] key = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte)
			// 0xFF,
			// (byte) 0xFF, (byte) 0xFF };
			//
			// classic.authenticateSectorWithKeyA(0, key);
			// showCardDetails(classic.getCardDetails());
			classic.getReader().close();
		} catch (ReaderException e) {
			 
			e.printStackTrace();
		}
	}

	/** Classic Write IO Operations. */
	private void testClassicWrite() {
		byte[] bdata = null;
		boolean res = false;

		try {
			NxpLogUtils.d(TAG, "testClassicWrite, start");

			bdata = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
			classic.write(bdata);
			res = true;
		} catch (SmartCardException e) {
			e.printStackTrace();
		}

		showMessage("Write :" + Utilities.dumpBytes(bdata), 'd');

		NxpLogUtils.d(TAG, "testClassicWrite, result is " + res);
		NxpLogUtils.d(TAG, "testClassicWrite, End");
	}

	/** Classic Read IO Operations. */
	private void testClassicRead() {
		byte[] read = null;
		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testClassicRead, start");
			read = classic.read(16);
			res = true;
		} catch (SmartCardException e) {
			e.printStackTrace();
		}
		showMessage("Read :" + Utilities.dumpBytes(read), 'd');
		NxpLogUtils.d(TAG, "testClassicRead, result is " + res);
		NxpLogUtils.d(TAG, "testClassicRead, End");
	}

	/** Classic Authenticate Operations. */
	private void testClassicauthenticate() {
		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testClassicauthenticate, start");
			byte sectorNo = 2;
			byte[] appId = new byte[] { 0x11, 0x11, 0x11 };
			byte[] key = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF };

			classic.authenticate(sectorNo, appId, key);
			res = true;
		} catch (SmartCardException e) {
			e.printStackTrace();
		}
		showMessage("authenticate :" + res, 'd');
		NxpLogUtils.d(TAG, "testClassicauthenticate, result is " + res);
		NxpLogUtils.d(TAG, "testClassicauthenticate, End");
	}

	/** Classic Update Master key Operations. */
	private void testClassicupdateMasterKey() {
		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testClassicupdateMasterKey, start");
			byte sectorNo = 2;
			byte[] oldKey = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
			byte[] newKey = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
					(byte) 0xFF, (byte) 0xFF, (byte) 0xFF };
			classic.updateApplicationMasterKey(sectorNo, oldKey, newKey);
			res = true;
		} catch (SmartCardException e) {
			e.printStackTrace();
		}

		showMessage("updateMasterKey : " + res, 'd');
		NxpLogUtils.d(TAG, "testClassicupdateMasterKey, result is " + res);
		NxpLogUtils.d(TAG, "testClassicupdateMasterKey, End");
	}

	/** Classic personalize Operations. */
	private void testClassicpersonalize() {
		byte sectorNo = 2;
		byte[] appId = new byte[] { 0x11, 0x11, 0x11 };
		byte[] key = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF };

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testClassicpersonalize, start");
			classic.personalize(sectorNo, appId, key);
			res = true;
		} catch (SmartCardException e) {
			e.printStackTrace();
		}
		showMessage("persionalize :" + res, 'd');
		NxpLogUtils.d(TAG, "testClassicpersonalize, result is " + res);
		NxpLogUtils.d(TAG, "testClassicpersonalize, End");
	}

	/** Classic Format Operations. */
	private void testClassicformat() {
		byte sectorNo = 2;
		byte[] key = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF };

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testClassicformat, start");
			classic.format(sectorNo, key);
			res = true;
		} catch (SmartCardException e) {
			 
			e.printStackTrace();
		}
		showMessage("farmat :" + res, 'd');
		NxpLogUtils.d(TAG, "testClassicformat, result is " + res);
		NxpLogUtils.d(TAG, "testClassicformat, End");
	}

	/**
	 * Plus lite operations.
	 * 
	 * @throws ProtocolException
	 *             when exception occur.
	 * @throws SmartCardException
	 *             when exception occur.
	 */
	public void plusCardLogic() throws ProtocolException, SmartCardException {

		byte sectorNo = 8;
		byte[] appId = new byte[] { 0x1, 0x1, 0x8 };
		byte[] appKey = new byte[] { (byte) 0x11, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00,
				(byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00, (byte) 0x00 };
		byte[] newAppKey = new byte[] { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
				(byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF };

		showImageSnap(R.drawable.plus);
		tv.setText(" ");
		showMessage("Card Detected: " + plus.getCardDetails().cardName + " "
				+ plus.getCardDetails().securityLevel, 'n');

		try {

			// this api will switch from plus sl0 to sl1. plus sl1 will be
			// detected as the classic card.
			// plus.personalizeCardToSL1();

		
			try {

				plus.personalizeSector(sectorNo, appId, appKey);
				NxpLogUtils.d(TAG, "Card personalize successful");
				byte[] testByte = new byte[] { (byte) 0x16, (byte) 0x00,
						(byte) 0x00, (byte) 0x00, (byte) 0xE9, (byte) 0xFF,
						(byte) 0xFF, (byte) 0xFF, (byte) 0x16, (byte) 0x00,
						(byte) 0x00, (byte) 0x00, (byte) 0x04, (byte) 0xFB,
						(byte) 0x04, (byte) 0xFB, (byte) 0x21, (byte) 0x00,
						(byte) 0x00, (byte) 0x00, (byte) 0xDE, (byte) 0xFF,
						(byte) 0xFF, (byte) 0xFF, (byte) 0x21, (byte) 0x00,
						(byte) 0x00, (byte) 0x00, (byte) 0x05, (byte) 0xFA,
						(byte) 0x05, (byte) 0xFA, (byte) 0x2C, (byte) 0x00,
						(byte) 0x00, (byte) 0x00, (byte) 0xD3, (byte) 0xFF,
						(byte) 0xFF, (byte) 0xFF };
				testPlusWriteBlock(testByte);
				testPlusReadBlock();
				plus.updateApplicationMasterKey(sectorNo, appId, appKey,
						newAppKey);
				showMessage("Restore sector app key to factory default", 'n');
				showMessage("Performing write/read again", 'n');
				testByte = new byte[] { (byte) 0xFF, (byte) 0xAA, (byte) 0x00,
						(byte) 0x00, (byte) 0xFF, (byte) 0xFF, (byte) 0xFF,
						(byte) 0xFF, (byte) 0x16, (byte) 0x00, (byte) 0x00,
						(byte) 0x00, (byte) 0x04, (byte) 0xFB, (byte) 0x04,
						(byte) 0xFB, (byte) 0x21, (byte) 0x00, (byte) 0x00,
						(byte) 0x00, (byte) 0xDE, (byte) 0xFF, (byte) 0xFF,
						(byte) 0xFF, (byte) 0x21, (byte) 0x00, (byte) 0x00,
						(byte) 0x00, (byte) 0x05, (byte) 0xFA, (byte) 0x05,
						(byte) 0xFA, (byte) 0x2C, (byte) 0x00, (byte) 0x00,
						(byte) 0x00, (byte) 0xD3, (byte) 0xFF, (byte) 0xFF,
						(byte) 0xFF };
				testPlusWriteBlock(testByte);
				testPlusReadBlock();
				showMessage("UID: " + Utilities.dumpBytes(plus.getUID()), 'd');
				showCardDetails(plus.getCardDetails());
				NxpLogUtils.d(TAG, "Card key application change successful");

			} catch (GeneralSecurityException e) {
				e.printStackTrace();
			} catch (SmartCardException e) {
				e.printStackTrace();
			}

			plus.getReader().close();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ReaderException e1) {
			 
			e1.printStackTrace();
		}
	}

	/**
	 * Mifare plus card write.
	 * 
	 */
	private void PlusSL1CardLogic() {

		showImageSnap(R.drawable.plus);
		tv.setText(" ");
		showMessage("Card Detected: " + plusSL1.getTagName()
				+ " " + "Security Level 1", 'n');
		showMessage("Uid :" + Utilities.dumpBytes(classic.getUID()), 'd');
		classic.getReader().setTimeout(2000);
		testClassicformat();
		testClassicpersonalize();
		testClassicupdateMasterKey();
		testClassicauthenticate();
		testClassicWrite();
		testClassicRead();
		// byte[] key = { (byte) 0xFF, (byte) 0xFF, (byte) 0xFF, (byte)
		// 0xFF,
		// (byte) 0xFF, (byte) 0xFF };
		//
		// classic.authenticateSectorWithKeyA(0, key);
		// showCardDetails(classic.getCardDetails());
		try {
			plusSL1.getReader().close();
		} catch (ReaderException e) {
			 
			e.printStackTrace();
		}

	}

	/**
	 * Mifare plus card write.
	 * 
	 * @param testByte
	 *            byte array.
	 * @throws ProtocolException
	 *             when exception occur.
	 * @throws SmartCardException
	 *             when exception occur.
	 */
	private void testPlusWriteBlock(final byte[] testByte)
			throws ProtocolException, SmartCardException {
		boolean resp = false;

		try {
			plus.write(testByte);
			resp = true;
		} catch (AuthenticationException e) {
			e.printStackTrace();
		} catch (PlusException e) {
			e.printStackTrace();
		} catch (SAMException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}

		showMessage("Write: " + resp, 'd');
	}

	/**
	 * Mifare plus read block.
	 * 
	 * @throws ProtocolException
	 *             when exception occur.
	 * @throws SmartCardException
	 *             when exception occur.
	 * */
	private void testPlusReadBlock() throws ProtocolException,
			SmartCardException {
		// boolean resp = false ;
		byte[] read = null;
		try {
			read = plus.read(40);
			// resp = true;
		} catch (AuthenticationException e) {
			e.printStackTrace();
		} catch (PlusException e) {
			e.printStackTrace();
		} catch (SAMException e) {
			e.printStackTrace();
		} catch (GeneralSecurityException e) {
			e.printStackTrace();
		}
		showMessage("Read Sector8: " + Utilities.dumpBytes(read), 'd');
	}

	/**
	 * creating the text record for NDEF Data.
	 * 
	 * @param payload
	 *            NDEF Data
	 * @param locale
	 *            locale
	 * @param encodeInUtf8
	 *            true/false
	 * @return ndefrecord instance.
	 */
	public static NdefRecord createTextRecord(final String payload,
			final Locale locale, final boolean encodeInUtf8) {
		byte[] langBytes = locale.getLanguage().getBytes(
				Charset.forName("US-ASCII"));
		Charset utfEncoding = encodeInUtf8 ? Charset.forName("UTF-8") : Charset
				.forName("UTF-16");
		byte[] textBytes = payload.getBytes(utfEncoding);
		int utfBit = encodeInUtf8 ? 0 : (1 << 7);
		char status = (char) (utfBit + langBytes.length);
		byte[] data = new byte[1 + langBytes.length + textBytes.length];
		data[0] = (byte) status;
		System.arraycopy(langBytes, 0, data, 1, langBytes.length);
		System.arraycopy(textBytes, 0, data, 1 + langBytes.length,
				textBytes.length);
		NdefRecord record = new NdefRecord(NdefRecord.TNF_WELL_KNOWN,
				NdefRecord.RTD_TEXT, new byte[0], data);
		return record;
	}

	/**
	 * Mifare classic Card Logic.
	 * 
	 * @throws SmartCardException
	 */
	public void ultralightCardLogic() throws SmartCardException {

		showImageSnap(R.drawable.ultralight);
		tv.setText(" ");
		showMessage("Card detected : " + mifareUL.getCardDetails().cardName,
				'n');

		try {

			testULformat();
			testWriteNdef();
			testULreadNdef();
			showCardDetails(mifareUL.getCardDetails());
			mifareUL.getReader().close();
		} catch (SmartCardException e) {
			 
			e.printStackTrace();
		} catch (ReaderException e) {
			 
			e.printStackTrace();
		}
	}

	/**
	 * Mifare Ultralight-C Card Logic.
	 * 
	 * @throws SmartCardException
	 */
	protected void ultralightcCardLogic() throws SmartCardException {

		showImageSnap(R.drawable.ultralight_c);
		tv.setText(" ");
		showMessage("Card Detected : " + objUlCardC.getCardDetails().cardName,
				'n');

		byte[] data;

		try {

			data = objUlCardC.readAll();
			showMessage("Read All o/p is : " + Utilities.dumpBytes(data), 'd');
			showCardDetails(objUlCardC.getCardDetails());
		} catch (IOException e) {
			showMessage(e.getMessage(), 'l');
			showMessage("IOException occured... check LogCat", 't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			 
			e.printStackTrace();
		}

	}

	/**
	 * Mifare Ultralight EV1 CardLogic.
	 * 
	 * @throws SmartCardException
	 */
	protected void ultralightEV1CardLogic() throws SmartCardException {

		showImageSnap(R.drawable.ultralight_ev1);
		tv.setText(" ");
		String str = "Card Detected : "
				+ objUlCardEV1.getCardDetails().cardName;
		showMessage(str, 'n');

		byte[] data;
		try {
			/** connect to card, authenticate and read data */

			data = objUlCardEV1.readAll();
			data = objUlCardEV1.read(DEFAULT_PAGENO_ULTRALIGHT);

			str = Utilities.dumpBytes(data);
			showMessage("Data read from card @ " + "page "
					+ DEFAULT_PAGENO_ULTRALIGHT + " is " + str, 'd');

			byte[] bytesData = DATA.getBytes();
			String s1 = new String(bytesData);
			showMessage("Input String is: " + s1, 'd');
			byte[] bytesEncData = encryptAESData(bytesData, bytesKey);
			str = "Enctrypted string is " + Utilities.dumpBytes(bytesEncData);
			showMessage(str, 'd');

			objUlCardEV1.write(4, Arrays.copyOfRange(bytesEncData, 0, 4));
			objUlCardEV1.write(5, Arrays.copyOfRange(bytesEncData, 4, 8));
			objUlCardEV1.write(6, Arrays.copyOfRange(bytesEncData, 8, 12));
			objUlCardEV1.write(7, Arrays.copyOfRange(bytesEncData, 12, 16));

			byte[] bytesDecData = decryptAESData(data, bytesKey);
			String s = new String(bytesDecData);
			str = "Decrypted string is " + s;
			showMessage(str, 'd');

			if (Arrays.equals(bytesData, bytesDecData)) {
				showMessage("Matches", 't');
			}

			showCardDetails(objUlCardEV1.getCardDetails());
		} catch (IOException e) {
			showMessage(e.getMessage(), 'l');
			showMessage("IOException occured... check LogCat", 't');
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			showMessage(e.getMessage(), 'l');
			showMessage("InvalidKeyException occured... check LogCat", 't');
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			showMessage(e.getMessage(), 'l');
			showMessage("NoSuchAlgorithmException occured... check LogCat", 't');
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			showMessage(e.getMessage(), 'l');
			showMessage("NoSuchPaddingException occured... check LogCat", 't');
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			showMessage(e.getMessage(), 'l');
			showMessage("IllegalBlockSizeException occured ... check LogCat",
					't');
			e.printStackTrace();
		} catch (BadPaddingException e) {
			showMessage(e.getMessage(), 'l');
			showMessage("BadPaddingException occured ... check LogCat", 't');
			e.printStackTrace();
		} catch (InvalidAlgorithmParameterException e) {
			showMessage(e.getMessage(), 'l');
			showMessage("InvalidAlgorithmParameterException ... check LogCat",
					't');
			e.printStackTrace();
		} catch (SmartCardException e) {
			 
			e.printStackTrace();
		}
		/* Save the logs in \sdcard\NxpLogDump\logdump.xml */
		NxpLogUtils.save();
	}

	/** Ultralight Read Ndef Operations. */
	private void testULreadNdef() {

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testULreadNdef, start");
			NdefMessage msgread = null;
			msgread = new NdefMessage(mifareUL.readNDEF().toByteArray());
			String sMsg = new String(msgread.getRecords()[0].getPayload());
			res = true;
			showMessage(
					"Read NDEF Data: "
							+ Utilities.dumpHexAscii(sMsg.getBytes()), 'd');
			NxpLogUtils.i(TAG,
					Utilities.dumpBytes(msgread.getRecords()[0].getPayload()));
			NxpLogUtils.i(TAG, sMsg);

		} catch (SmartCardException e) {
			showMessage("Read NDEF: " + res, 'd');
			e.printStackTrace();
		} catch (FormatException e) {
			 
			e.printStackTrace();
		}

		NxpLogUtils.d(TAG, "testULreadNdef, result is " + res);
		NxpLogUtils.d(TAG, "testULreadNdef, End");
	}

	/** Ultralight Format Operations. */
	private void testULformat() {
 

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testULformat, start");
			mifareUL.getReader().setTimeout(500);
			mifareUL.format();
			res = true;
			showMessage("Format: " + res, 'd');
		} catch (SmartCardException e) {
			showMessage("Format: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testULformat, result is " + res);
		NxpLogUtils.d(TAG, "testULformat, End");
	}

	/** Ultralight write ndef Operations. */
	public void testWriteNdef() {
		NdefRecord textRecord = createTextRecord(
				"MIFARE SDK by NXP Semiconductors Inc.", Locale.ENGLISH, true);
		NdefMessage message = new NdefMessage(new NdefRecord[] { textRecord });

		boolean res = false;

		try {

			NxpLogUtils.d(TAG, "testWriteNdef, start");
			mifareUL.formatT2T();
			mifareUL.writeNDEF(message);
			res = true;
			showMessage("NDEF - Create Text Record: " + res, 'd');
		} catch (SmartCardException e) {
			showMessage("NDEF - Create Text Record: " + res, 'd');
			e.printStackTrace();
		} catch (IOException e) {
			 
			e.printStackTrace();
		}

		NxpLogUtils.d(TAG, "testWriteNdef, result is " + res);
		NxpLogUtils.d(TAG, "testWriteNdef, End");

	}

	/**
	 * Update the card image on the screen.
	 * 
	 * @param cardTypeId
	 *            resource image id of the card image
	 * 
	 */



	/**
	 * This will display message in toast or logcat .
	 * 
	 * @param str
	 *            String to be logged or displayed
	 * @param where
	 *            't' for Toast; 'l' for Logcat; 'd' for Display in UI; 'n' for
	 *            logcat and textview 'a' for All
	 * 
	 */
	protected void showMessage(final String str, final char where) {

		switch (where) {

		case 't':
			Toast.makeText(MainLiteActivity.this, "\n" + str,
					Toast.LENGTH_SHORT).show();
			break;
		case 'l':
			NxpLogUtils.i(TAG, "\n" + str);
			break;
		case 'd':
			tv.setText(tv.getText() + "\n-----------------------------------\n"
					+ str);
			break;
		case 'a':
			Toast.makeText(MainLiteActivity.this, "\n" + str,
					Toast.LENGTH_SHORT).show();
			NxpLogUtils.i(TAG, "\n" + str);
			tv.setText(tv.getText() + "\n-----------------------------------\n"
					+ str);
			break;
		case 'n':
			NxpLogUtils.i(TAG, "Dump Data: " + str);
			tv.setText(tv.getText() + "\n-----------------------------------\n"
					+ str);
			break;
		default:
			break;
		}
		return;
	}

	/**
	 * Encrypt the supplied data with key provided.
	 * 
	 * @param data
	 *            data bytes to be encrypted
	 * @param key
	 *            Key to encrypt the buffer
	 * @return encrypted data bytes
	 * @throws NoSuchAlgorithmException
	 *             NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 *             NoSuchPaddingException
	 * @throws InvalidKeyException
	 *             InvalidKeyException
	 * @throws IllegalBlockSizeException
	 *             IllegalBlockSizeException
	 * @throws BadPaddingException
	 *             eption BadPaddingException
	 * @throws InvalidAlgorithmParameterException
	 *             InvalidAlgorithmParameterException
	 */
	protected byte[] encryptAESData(final byte[] data, final byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {
		final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		cipher.init(Cipher.ENCRYPT_MODE, keySpec, iv);
		byte[] encdata = cipher.doFinal(data);
		return encdata;
	}

	/**
	 * @param encdata
	 *            Encrypted input buffer.
	 * @param key
	 *            Key to decrypt the buffer.
	 * @return byte array.
	 * @throws NoSuchAlgorithmException
	 *             No such algorithm exce.
	 * @throws NoSuchPaddingException
	 *             NoSuchPaddingException.
	 * @throws InvalidKeyException
	 *             if key is invalid.
	 * @throws IllegalBlockSizeException
	 *             if block size is illegal.
	 * @throws BadPaddingException
	 *             if padding is bad.
	 * @throws InvalidAlgorithmParameterException
	 *             if algo. is not avaliable or not present.
	 */
	protected byte[] decryptAESData(final byte[] encdata, final byte[] key)
			throws NoSuchAlgorithmException, NoSuchPaddingException,
			InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, InvalidAlgorithmParameterException {

		final SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
		cipher.init(Cipher.DECRYPT_MODE, keySpec, iv);
		byte[] decdata = cipher.doFinal(encdata);
		return decdata;
	}
}

