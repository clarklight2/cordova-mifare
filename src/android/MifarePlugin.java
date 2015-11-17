package com.clark.nfcaes.plugin;

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



import org.apache.cordova.CallbackContext;
import org.apache.cordova.CordovaPlugin;
import org.apache.cordova.PluginResult;
import org.apache.cordova.PluginResult.Status;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.IOException;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;


public class MifarePlugin extends CordovaPlugin {
    	private NxpNfcLibLite libInstance = null;
    	private IDESFireEV1 mDESFire;
     private static final String LOGTAG = "MifarePlugin";
    private static final String ACTION_INIT = "init";
     private static final String ACTION_AUTHENTICATE = "Authenticate";
    private static final String ACTION_ENCRYPT = "Encrypt";
     private static final String ACTION_DECRYPT = "Decrypt";  
     private static final String ACTION_PERSONALIZE = "Personalize";  
   private static final String ACTION_UPDATEMASTERKEY = "Updatemasterkey";  
   private static final String ACTION_WRITE_TAG_DATA = "writeTag";  
        private static final String TAG_EVENT_DETECTED = "onTagDetected";
    private static final String TAG_EVENT_ERROR = "onTagError";
    private static final String TAG_EVENT_ERROR_TYPE_SECURITY = "Security";
    private static final String TAG_EVENT_ERROR_TYPE_IOREAD = "IORead";
    private static final String TAG_EVENT_ERROR_TYPE_CARD = "Card";
	static final String TAG = "SampleNxpNfcLibLite";
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
	private ImageView mImageView = null;
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


  private void init(CallbackContext callbackContext) {
        Log.d(TAG, "Enabling plugin " + getIntent());

        startNfc();
        if (!recycledIntent()) {
            parseMessage();
        }
        callbackContext.success();
    }



    private void registerDefaultTag(CallbackContext callbackContext) {
        
      
        
      addTagFilter();
      callbackContext.success();
  }









    
}
