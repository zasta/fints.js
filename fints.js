var Hbci = (function initHbci() {
    var LOG_LEVEL = {
      FATAL: 0,
      ERROR: 1,
      WARN:  2,
      INFO:  3,
      DEBUG: 4
    };

    var self = {};
    self.debugFunc = console.log;

    function makeEncryptionEnvelope(segments) {
        var payload = segments.join("");

        return "HNVSD:999:1+@" + payload.length + "@" + payload + "'";
    }

    function makeMessage(version, msgNum, dialogId, blz, userId, pin, systemId, segments, TANMechanism) {
        if(msgNum === undefined) msgNum = 1;
        // Force strings for msgNum and dialogId
        msgNum += "";
        dialogId += "";

        // Constant parts of the message (needed for length calculation)
        var HEAD_LEN  = 29,
            TRAIL_LEN = 11;

        var secRef = Math.round(Math.random() * 999999 + 1000000);

        self.debugFunc( LOG_LEVEL.DEBUG, 'Entering makeMessage ' + version);

        if(version == "3.0") {
          var encHead   = "HNVSK:998:3+PIN:1+998+1+1::" + systemId + "+1:20140825:181000+2:2:13:@8@00000000:5:1+280:" + blz + ":" + userId + ":V:0:0+0'",
              sigHead   = "HNSHK:2:4+PIN:1+" + (TANMechanism || "999") + "+" + secRef + "+1+1+1::" + systemId + "+1+1:20140825:181000+1:999:1+6:10:16+280:" + blz + ":" + userId + ":S:0:0'",
              sigTrail  = "HNSHA:" + (segments.length + 3) + ":2+" + secRef + "++" + pin + "'";

        } else {
          var encHead   = "HNVSK:998:2+998+1+1::" + systemId + "+1:20140825:181000+2:2:13:@8@00000000:5:1+280:" + blz + ":" + userId + ":V:0:0+0'",
              sigHead   = "HNSHK:2:3+" + (TANMechanism || "900") + "+" + secRef + "+1+1+1::" + systemId + "+1+1:20140825:181000+1:999:1+6:10:16+280:" + blz + ":" + userId + ":S:0:0'",
              sigTrail  = "HNSHA:" + (segments.length + 3) + ":1+" + secRef + "++" + pin + "'";

        }

        segments = [sigHead].concat(segments, sigTrail);

        var payload   = makeEncryptionEnvelope(segments),
            msgLen    = HEAD_LEN + TRAIL_LEN + msgNum.length*2 + dialogId.length + payload.length + encHead.length,
            paddedLen = ("000000000000" + msgLen).substr(-12),
            msgHead   = "HNHBK:1:3+" + paddedLen + "+" + (version == "3.0" ? "300" : "220") +"+" + dialogId + "+" + msgNum + "'",
            msgEnd    = "HNHBS:" + (segments.length + 2) + ":1+" + msgNum + "'";

        self.debugFunc(LOG_LEVEL.DEBUG, "Message to be sent: " + msgHead + encHead + payload + msgEnd);

        return msgHead + encHead + payload + msgEnd;
    }

    function sendFinTSMessage(url, msg, callback) {
        var req = new XMLHttpRequest({mozSystem: true});
        req.onload = function() {
          if(req.status == "200") {
            self.debugFunc(LOG_LEVEL.DEBUG, "Received successful response");
            var payload = req.responseText.replace(/\s+/g, '');
            callback(false, atob(payload));
          } else {
            self.debugFunc(LOG_LEVEL.ERROR, "Received error response: " + req.status + " " + req.statusText);
            callback(req.statusText, null);
          }
        };
        req.onerror   = function(event) { callback(e.error, null) };
        req.ontimeout = function() { callback("Keine Antwort vom Bankserver", null) };
        req.open("post", url, true);
        req.timeout = 10000;
        req.setRequestHeader("Content-Type", "application/octet-stream");
        req.send(btoa(msg));
        self.debugFunc(LOG_LEVEL.INFO, "Sent message: " + msg);
    }

    function unwrapEncryptedMsg(msg) {
      return msg.replace(/(HNVSD:\d+:\d+)\+@\d+@(.*)''/, "\\$2'")
    }

    function parseDialogInitSegments(segments) {
      self.debugFunc(LOG_LEVEL.DEBUG, "Parsing message: " + segments.join(", ");
      var dialog = {};
      var i = segments.length - 1;
      while(i--) {
        var seg = segments[i];
        segType = seg.substr(0, seg.indexOf(":"))
        dataElems = seg.split("+")
        switch(segType) {
          case "HIRMS":
            for(var d=1;d<dataElems.length;d++) {
              var status = dataElems[d].split(":");
              if(status[0] == "3920") {
                if(status[2][0] == "9") dialog.TANMechanism = status[2];
                else dialog.TANMechanism = status[3];
              }
            }
            break;
          case "HNHBK":
            dialog.dialogId = dataElems[3];
            break;
          case "HISYN":
            dialog.systemId = dataElems[1]
            break;
          case "HNHBS":
            parsedMsgNum = parseInt(dataElems[1], 10);
            if(isNaN(parsedMsgNum) || parsedMsgNum === 0) {
              dialog.nextMsgNum = 2;
            } else {
              dialog.nextMsgNum = parsedMsgNum + 1;
            }
            break;
          case "HISALS":
            var segmentVersion = dataElems[0].split(":")[2];
            if(!dialog.segmentVersions) dialog.segmentVersions = {};
            if(!dialog.segmentVersions['HKSAL'] || dialog.segmentVersions['HKSAL'] < segmentVersion) {
              dialog.segmentVersions['HKSAL'] = segmentVersion;
            }
            break;
          case "HIUPD":
            var hbciAcc = dataElems[1],
                accName   = dataElems[8];

            if(hbciAcc == "") break;
            if(!dialog.accounts) dialog.accounts = [];

            dialog.accounts.push({label: accName || hbciAcc.split(":")[0], hbciAccount: hbciAcc})

            break;
        }
      }
      return dialog
    }

    function retrieveSegmentFromMsg(wantedSegmentType, msg, multiple) {
      var segments = msg.split("'");
      var i = segments.length - 1;
      var matches = [];
      while(i--) {
        var seg = segments[i];
        segType = seg.substr(0, seg.indexOf(":"))
        if(segType == wantedSegmentType) {
          if(!multiple) return segments[i];
          else matches.push(segments[i]);
        }
      }
      if(multiple) return matches;

      return null
    }

    /** Result can be one or multiple segments **/
    function makeHumanReadableErrorFromResult(result) {
      if(result instanceof Array) {
        var mostSpecificError = null;
        for(var s=0, len=result.length; s<len; s++) {
          var error = makeHumanReadableErrorFromSegment(result[s]);
          if(mostSpecificError == null || error.quality > mostSpecificError.quality) {
            mostSpecificError = error;
          }
        }
        if(!mostSpecificError) return "Unbekannter Fehler";
        return mostSpecificError.message + " (" + mostSpecificError.code + ")";
      }

      var error = makeHumanReadableErrorFromSegment(result);
      if(error) return error.message;
      else return null;
    }

    function makeHumanReadableErrorFromSegment(resultSegment) {
      var elements = resultSegment.split("+"),
          mostSpecificStatus = null;

      elements.shift();
      for(var i=0, len = elements.length; i<len;i++) {
        var result = elements[i].split(":"),
            quality = 0;

        // Move on if this isn't an error
        if(result[0][0] != "9") {
          continue
        }

        for(var d=0;d<4;d++) {
          if(result[0][d] !== "0") quality++;
        }

        if(mostSpecificStatus == null || quality > mostSpecificStatus.quality) {
          mostSpecificStatus = {code: result[0], message: result[2], quality: quality};
        }
      }

      return mostSpecificStatus;
    }

    function isMsgError(msg) {
      var msgStatus = retrieveSegmentFromMsg("HIRMG", msg);
      if(!msgStatus) return false;
      var dataElems = msgStatus.split("+");
      if(dataElems.length < 2) {
        return false
      }
      return dataElems[1].split(":")[0][0] == "9";
    }

    // Gets a systemId, dialogId and the list of accounts, leave systemID empty if you call this.
    // Callback takes two params: error (human readable), dialog
    function initialiseDialog(credentials, bank, callback) {
        var segments = [];
        self.debugFunc(LOG_LEVEL.INFO, "SYNCing");
        
        // TODO: Factor this out into its own function
        if(bank.version == "3.0") {
          segments = [
            "HKIDN:3:2+280:" + bank.blz + "+" + credentials.loginId + "+0+1'",
            "HKVVB:4:3+0+0+0+Zasta+1.0'",
            "HKSYN:5:3+0'"
          ];
        } else {
          segments = [
            "HKIDN:3:2+280:" + bank.blz + "+" + credentials.loginId + "+0+1'",
            "HKVVB:4:2+0+0+0+Zasta+1.0'",
            "HKSYN:5:2+0'"
          ];
        }

        // Get us a System ID
        var syncMsg = makeMessage(bank.version, "1", "0", bank.blz, credentials.loginId, credentials.pin, "0", segments);

        sendFinTSMessage(bank.url, syncMsg, function(err, data) {
            if(err) {
              callback(err, null);
              return
            }
            var syncResponse = unwrapEncryptedMsg(data);

            self.debugFunc(LOG_LEVEL.INFO, "SYNC Received: " + data);

            // Parse Dialog ID, System ID and pass that back to the callback
            var dialog = parseDialogInitSegments(syncResponse.split("'"));

            // Did something fail?
            if(!dialog.systemId || isMsgError(syncResponse)) {
              self.debugFunc(LOG_LEVEL.ERROR, "SYNC failed: " + data);
              var result = retrieveSegmentFromMsg("HIRMS", syncResponse, true);
              if(result.length == 0) { // No segment status was included, so fallback to the message status
                result = retrieveSegmentFromMsg("HIRMG", syncResponse);
              }
              callback(makeHumanReadableErrorFromResult(result) || "Unknown error", null);
              return;
            }

            self.debugFunc(LOG_LEVEL.INFO, "INITing...");

            if(bank.version == "3.0") {
              segments = [
                "HKIDN:3:2+280:" + bank.blz + "+" + credentials.loginId + "+" + dialog.systemId + "+1'",
                "HKVVB:4:3+0+0+0+Zasta+1.0'",
              ];
            } else {
              segments = [
                "HKIDN:3:2+280:" + bank.blz + "+" + credentials.loginId + "+" + dialog.systemId + "+1'",
                "HKVVB:4:2+0+0+0+Zasta+1.0'",
              ];
            }

            var initMsg = makeMessage(bank.version, "1", "0", bank.blz, credentials.loginId, credentials.pin, dialog.systemId, segments, dialog.TANMechanism);
            sendFinTSMessage(bank.url, initMsg, function(err, data) {
              if(err) {
                callback(err, null);
                return;
              }

              self.debugFunc(LOG_LEVEL.DEBUG, "INIT Received: " + data);
              var initResponse = unwrapEncryptedMsg(data),
                  dialog2 = parseDialogInitSegments(initResponse.split("'"));

              dialog2.systemId = dialog.systemId;
              dialog2.TANMechanism = dialog.TANMechanism;

              if(!dialog2.accounts || isMsgError(initResponse)) {
                self.debugFunc(LOG_LEVEL.ERROR, "INIT failed: " + data);

                var result = retrieveSegmentFromMsg("HIRMS", initResponse, true);
                if(result == []) { // No segment status was included, so fallback to the message status
                  result = retrieveSegmentFromMsg("HIRMG", initResponse);
                }

                callback("Fehler bei der Anmeldung: " + makeHumanReadableErrorFromResult(result), []);
                return;
              }

              callback(null, dialog2);
            });
        });
    }

    // Gets balances and returns them to the callback. Callback has these params: error (human readable), balances ([{acc, balance}])
    self.getKontostand = function(credentials, bank, callback){
        initialiseDialog(credentials, bank, function(error, dialog) {
          if(error) {
              callback(error, []);
              return
          }
          self.debugFunc(LOG_LEVEL.INFO, "Dialog initialised. Fetching balance...");
          // We do have the dialog now.

          // So we send a new message to actually fetch the balances by supplying a HKSAL segment each
          var numAccs = dialog.accounts.length;
          segments = [];
          for(var i=0;i<numAccs; i++) {
            self.debugFunc(LOG_LEVEL.DEBUG, "Account found: " + dialog.accounts[i].hbciAccount);
            if(dialog.segmentVersions['HKSAL'] == '7'){
              var acc = '::' + dialog.accounts[i].hbciAccount;
            } else {
              var acc = dialog.accounts[i].hbciAccount;
            }
            segments.push("HKSAL:" + (3 + i) + ":" + dialog.segmentVersions['HKSAL'] + "+" + acc + "+N'")
          }

          var balanceFetchMsg = makeMessage(bank.version, dialog.nextMsgNum, dialog.dialogId, bank.blz, credentials.loginId, credentials.pin, dialog.systemId, segments, dialog.TANMechanism);
          sendFinTSMessage(bank.url, balanceFetchMsg, function(err, data) {
            if(err) {
              self.debugFunc(LOG_LEVEL.ERROR, "HKSAL Error:" + err);
              callback(err, []);
              return;
            }

            var message = unwrapEncryptedMsg(data);
            self.debugFunc(LOG_LEVEL.DEBUG, "-------- Balances --------");
            self.debugFunc(LOG_LEVEL.DEBUG, "Result (message): " + retrieveSegmentFromMsg("HIRMG", message));
            self.debugFunc(LOG_LEVEL.DEBUG, "Result (segment): " + retrieveSegmentFromMsg("HIRMS", message));
            self.debugFunc(LOG_LEVEL.DEBUG, "Received: " + data);

            var balanceFound = false, balances = [];
            do {
              var balanceResponse = retrieveSegmentFromMsg("HISAL", message);
              if(!balanceResponse) {
                break;
              }
              balanceFound = true;

              var elems   = balanceResponse.split("+"),
                  balance = parseFloat(elems[4].split(":")[1].replace(',', '.')).toFixed(2),
                  accName = elems[2] || elems[1].split(":")[0]; // Try the name field. If empty, use the number field.

              if(elems[4].split(":")[0].toUpperCase() === 'D') balance *= -1;

              balances.push({account: accName, balance: balance});
              message = message.replace(balanceResponse, "");
            } while(balanceResponse);
            if(balanceFound) {
              callback(false, balances);
            } else {
              callback(makeHumanReadableErrorFromResult(retrieveSegmentFromMsg("HIRMS", message, true) || retrieveSegmentFromMsg("HIRMG", message)), []);
            }
          })
        });
    }

    return self;
})();
