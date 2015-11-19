var nfc = {

    addTagDiscoveredListener: function (callback, win, fail) {
        document.addEventListener("tag", callback, false);
        cordova.exec(win, fail, "MifarePlugin", "registerTag", []);
    },

    addMimeTypeListener: function (mimeType, callback, win, fail) {
        document.addEventListener("ndef-mime", callback, false);
        cordova.exec(win, fail, "MifarePlugin", "registerMimeType", [mimeType]);
    },

    addNdefListener: function (callback, win, fail) {
        document.addEventListener("ndef", callback, false);
        cordova.exec(win, fail, "MifarePlugin", "registerNdef", []);
    },

    addNdefFormatableListener: function (callback, win, fail) {
        document.addEventListener("ndef-formatable", callback, false);
        cordova.exec(win, fail, "MifarePlugin", "registerNdefFormatable", []);
    },

    write: function (ndefMessage, win, fail) {
        cordova.exec(win, fail, "MifarePlugin", "writeTag", [ndefMessage]);
    },

    makeReadOnly: function (win, fail) {
        cordova.exec(win, fail, "MifarePlugin", "makeReadOnly", []);
    },


};

var mifareExport = {};

mifareExport.onDESFireCardDetected = function (data, successCallback, failureCallback) {
	cordova.exec(successCallback, failureCallback, 'MifarePlugin', 'onDESFireCardDetected',[name]);
	
	console.log("test");
};


module.exports = mifareExport;
