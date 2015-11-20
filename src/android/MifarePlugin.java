package se.frostyelk.cordova.mifare;

import java.io.IOException;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Locale;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.http.ProtocolException;
import org.apache.http.auth.AuthenticationException;
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

       @Override
       public boolean execute(String action, JSONArray args, CallbackContext callbackContext) throws JSONException {
            
   if (action.equals("greet")) {

            String name = "33";
            String message = "Hello, " + name;
            callbackContext.success(message);

            return true;

        }  else if(action.equals("detected")){
   
   
   onNewIntent(args.getJSONObject(0), callbackContext);
    return true;
   } else {
            
            return false;

        }      
    }
    
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
protected void onNewIntent(final Intent intent,final JSONObject options, final CallbackContext callbackContext) {
          String name = "33233";
            String message = "Hellogesgse, " + name;
            callbackContext.success(message);
    
    
    	libInstance.filterIntent(intent, new Nxpnfcliblitecallback() {
    
    	public void onDESFireCardDetected (final IDESFireEV1 objDESFire) {
				mDESFire = objDESFire;
            String name = "33233";
            String message = "Hellogesgse, " + name;
            callbackContext.success(message);
				/* Insert your logic here by commenting the function call below. */
				try {
            //callbackContext.success("OK");
                //callbackContext.error("NOK");
					mDESFire.getReader().close();
					mDESFire.getReader().connect();
					desfireCardLogic();
              
               
				} catch (Throwable t) {
					t.printStackTrace();
					//showMessage("Unknown Error Tap Again!", 't');
          // callbackContext.success("NO");
                //callbackContext.error("NOTOK");
				}

			}
        });
    
}
    
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
			//showMessage("Authenticate: " + res, 'd');
		} catch (SmartCardException e) {
			//showMessage("Authenticate: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireauthenticate, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireauthenticate, End");
	}

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
			//showMessage("personalize: " + res, 'd');
		} catch (SmartCardException e) {
			//showMessage("personalize: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFirepersonalize, result is " + res);
		NxpLogUtils.d(TAG, "testDESFirepersonalize, End");

	}
    
    
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
			//showMessage("DESFire Update PICC Master Key: " + res, 'd');
		} catch (SmartCardException e) {
			//showMessage("DESFire Update PICC Master Key: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireupdatePICCMasterKey, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireupdatePICCMasterKey, End");

	}
    
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
			//showMessage("Update Application MasterKey: " + res, 'd');
		} catch (SmartCardException e) {
			//showMessage("Update Application MasterKey: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireupdateApplicationMasterKey, result is "
				+ res);
		NxpLogUtils.d(TAG, "testDESFireupdateApplicationMasterKey, End");
	}

    
    	private void testDESFireWrite() {

		byte[] data = new byte[] { 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
				0x11 };

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFireWrite, start");
			mDESFire.write(data);
			res = true;
			//showMessage("Data Written: " + Utilities.dumpBytes(data), 'd');
		} catch (SmartCardException e) {
			//showMessage("Data Written: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireWrite, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireWrite, End");

	}
    
    	private void testDESFireRead() {

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFireRead, start");
			byte[] data = mDESFire.read(5);
			res = true;
            //showMessage("Data Read from the card..." + Utilities.dumpBytes(data),'d');
		} catch (SmartCardException e) {
			//showMessage("Data Read from the card: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireRead, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireRead, End");
	}

	private void testDESFireFormat() {
		byte[] mykey = new byte[] { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

		boolean res = false;
		try {
			NxpLogUtils.d(TAG, "testDESFireFormat, start");
			mDESFire.format(mykey);
			res = true;
			//showMessage("Format: " + res, 'd');
		} catch (SmartCardException e) {
			//showMessage("Format: " + res, 'd');
			e.printStackTrace();
		}
		NxpLogUtils.d(TAG, "testDESFireFormat, result is " + res);
		NxpLogUtils.d(TAG, "testDESFireFormat, End");
	}
    
    	protected void desfireCardLogic() throws SmartCardException {

		//showImageSnap(R.drawable.desfire_ev1);
		//tv.setText(" ");
		//showMessage("Card Detected : " + mDESFire.getCardDetails().cardName,'n');

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
    
    
    


}
