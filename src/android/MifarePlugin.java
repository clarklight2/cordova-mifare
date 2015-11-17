
package se.frostyelk.cordova.mifare;

import android.content.Intent;
import android.nfc.NfcAdapter;
import android.nfc.Tag;
import com.nxp.nfclib.classic.MFClassic;
import com.nxp.nfclib.exceptions.SmartCardException;
import com.nxp.nfclib.icode.*;
import com.nxp.nfclib.ntag.*;
import com.nxp.nfclib.plus.PlusSL1;
import com.nxp.nfclib.ultralight.Ultralight;
import com.nxp.nfclib.ultralight.UltralightC;
import com.nxp.nfclib.ultralight.UltralightEV1;
import com.nxp.nfclib.utils.NxpLogUtils;
import com.nxp.nfclib.utils.Utilities;
import com.nxp.nfcliblite.Interface.NxpNfcLibLite;
import com.nxp.nfcliblite.Interface.Nxpnfcliblitecallback;
import com.nxp.nfcliblite.cards.DESFire;
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
