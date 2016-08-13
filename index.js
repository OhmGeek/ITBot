//start by declaring dependencies needed:
const
  bodyParser = require("body-parser");
  config = require("config");
  crypto = require("crypto");
  express = require("express");
  https = require("https");
  request = require("request");



var STATES = {
  START: {value: 0, text: "Hi there, I'm ITBot. First of all, what Operating System do you have installed on your computer? ('Windows', 'Mac', 'Linux')", options: [
    {optionText: "windows", nextStateValue: 1},
    {optionText: "mac", nextStateValue: 2},
    {optionText: "linux", nextStateValue: 3}
  ]},
  WINDOWS: {value: 1, text: "If you are using Windows, you need to install anti-virus. Do you have an anti-virus program installed? ('yes','no')", options: [
    {optionText: "yes", nextStateValue: 4},
    {optionText: "no", nextStateValue: 5}
  ]},
  WINDOWS_INSTALL_AVAST: {value: 5, text: "Ok, you will need to install anti-virus before connecting due to the security policy. As you are on Windows, you will need to install 'Avast'. Please click on the following link, download the file, and run it. If any security warnings appear, it's fine! Then go through the installation process. ('Ok') Link: https://www.avast.com/en-gb/download-thank-you.php?product=FAV-ONLINE&locale=en-gb", options: [
    {optionText: "ok", nextStateValue: 6}
  ]},
  WINDOWS_ANTIVIRUS_INSTALLED: {value: 4, text: "Even though you have anti-virus installed, do you have 'Avast'? ('yes','no')", options: [
    {optionText: "yes", nextStateValue: 6},
    {optionText: "no", nextStateValue: 7}
  ]},

  WINDOWS_AVAST_NO: {value: 7, text: "We cannot guarantee that any other package works with the Durham internet. Norton sometimes works, but it's not guaranteed. Do you want to install Avast? ('yes','no')", options: [
    {optionText: "yes", nextStateValue: 8},
    {optionText: "no", nextStateValue: 6}
  ]},

  WINDOWS_UNINSTALL_CURRENT: {value: 8, text: "Before installing Avast, please uninstall the current anti-virus. You can do this by going to Control Panel > Add or Remove Programs > and then select the software to uninstall e.g. McAfee, AVG. Norton. Once it's uninstalled we can continue. ('ok') ", options: [
    {optionText: "ok", nextStateValue: 5}
  ]},
  WINDOWS_AVAST_INSTALLED: {value: 6, text: "Wonderful! You (hopefully) should be able to pass the scan now :) Are you currently in college? ('yes','no')",options: [
    {optionText: "yes", nextStateValue: 0}
  ]}
};





//first, let's get all the necessary details from the config file.
const APP_SECRET = config.get("apiDetails.APP_SECRET");
const VALIDATION_TOKEN = config.get("apiDetails.VALIDATION_TOKEN");
const PAGE_ACCESS_TOKEN = config.get("apiDetails.PAGE_TOKEN");

//let's open up the app now!
var app = express();

//set the PORT
app.set('port', process.env.PORT || 5000);

//deal with signatures
app.use(bodyParser.json({ verify: verifyRequestSignature }));
app.use(express.static('public'));

//create an object to store all sessions.
var sessions = {}

//now we need the validation code for FB:

app.get('/sshbot', function(req, res) {
  if (req.query['hub.mode'] === 'subscribe' &&
      req.query['hub.verify_token'] === VALIDATION_TOKEN) {
    console.log("Validating webhook");
    res.status(200).send(req.query['hub.challenge']);
  } else {
    console.error("Failed validation. Make sure the validation tokens match.");
    res.sendStatus(403);
  }
});

//this is where the main code lies...
app.post('/sshbot', function (req, res) {
  var data = req.body;

  // Make sure this is a page subscription
  if (data.object == 'page') {
    // Iterate over each entry
    // There may be multiple if batched
    data.entry.forEach(function(pageEntry) {
      var pageID = pageEntry.id;
      var timeOfEvent = pageEntry.time;

      // Iterate over each messaging event
      pageEntry.messaging.forEach(function(messagingEvent) {
        if (messagingEvent.optin) {
          receivedAuthentication(messagingEvent);
        } else if (messagingEvent.message) {
          receivedMessage(messagingEvent);
        } else if (messagingEvent.delivery) {
          receivedDeliveryConfirmation(messagingEvent);
        } else if (messagingEvent.postback) {
          receivedPostback(messagingEvent);
        } else {
          console.log("Webhook received unknown messagingEvent: ", messagingEvent);
        }
      });
    });

    // Assume all went well.
    //
    // You must send back a 200, within 20 seconds, to let us know you've
    // successfully received the callback. Otherwise, the request will time out.
    res.sendStatus(200);
  }
});

//determines whether callback came from FB
function verifyRequestSignature(req, res, buf) {
  var signature = req.headers["x-hub-signature"];

  if (!signature) {
    // For testing, let's log an error. In production, you should throw an
    // error.
    console.error("Couldn't validate the signature.");
  } else {
    var elements = signature.split('=');
    var method = elements[0];
    var signatureHash = elements[1];

    var expectedHash = crypto.createHmac('sha1', APP_SECRET)
                        .update(buf)
                        .digest('hex');

    if (signatureHash != expectedHash) {
      throw new Error("Couldn't validate the request signature.");
    }
  }
}
/*
 * Authorization Event
 *
 * The value for 'optin.ref' is defined in the entry point. For the "Send to
 * Messenger" plugin, it is the 'data-ref' field. Read more at
 * https://developers.facebook.com/docs/messenger-platform/webhook-reference#auth
 *
 */
function receivedAuthentication(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfAuth = event.timestamp;

  // The 'ref' field is set in the 'Send to Messenger' plugin, in the 'data-ref'
  // The developer can set this to an arbitrary value to associate the
  // authentication callback with the 'Send to Messenger' click event. This is
  // a way to do account linking when the user clicks the 'Send to Messenger'
  // plugin.
  var passThroughParam = event.optin.ref;

  console.log("Received authentication for user %d and page %d with pass " +
    "through param '%s' at %d", senderID, recipientID, passThroughParam,
    timeOfAuth);

  // When an authentication is received, we'll send a message back to the sender
  // to let them know it was successful.
  sendTextMessage(senderID, "Authentication successful");
}


/*
 * Message Event
 *
 * This event is called when a message is sent to your page. The 'message'
 * object format can vary depending on the kind of message that was received.
 * Read more at https://developers.facebook.com/docs/messenger-platform/webhook-reference#received_message
 *
 * For this example, we're going to echo any text that we get. If we get some
 * special keywords ('button', 'generic', 'receipt'), then we'll send back
 * examples of those bubbles to illustrate the special message bubbles we've
 * created. If we receive a message with an attachment (image, video, audio),
 * then we'll simply confirm that we've received the attachment.
 *
 */

 function receivedMessage(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfMessage = event.timestamp;
  var message = event.message;

  console.log("Received message for user %d and page %d at %d with message:",
    senderID, recipientID, timeOfMessage);
  console.log(JSON.stringify(message));

  var messageId = message.mid;

  // You may get a text or attachment but not both
  var messageText = message.text;
  var messageAttachments = message.attachments;
  if(messageText) {
    manageStateMachine(messageText,senderID);
  }
}

function getStateByID(stateID) {

  for (var prop in STATES) {
    console.log(STATES[prop]);
    var obj = STATES[prop];
      if(obj["value"] == stateID) {
        console.log(prop);
        console.log(obj);
        return obj;
      }
  }

}


function isInStateOptions(textToFind,state) {
  console.log("Entered isInStateOptions");

  var options = state["options"];
  console.log("Total list of options");
  console.log(options);

  for (var elem in options) {
    console.log(elem);
    if(elem["optionText"] == textToFind) {
      console.log("Going searching for next state");
//      console.log(elem["optionText"]);
    var nextState = getStateByID(elem["nextStateValue"]);
    return nextState;
    }
  }
  return null;
}


function manageStateMachine(messageText,senderID) {
  console.log("State Machine start");
  //if senderID not in the collection, set new state to START.
  var state;
  if(!sessions.hasOwnProperty(senderID)) {
    console.log("Starting");
    sessions[senderID] = STATES.START;
    state = STATES.START;
    console.log("Current state:");
    console.log(state);
  }
  //otherwise, take the data and process the input.
  else {
    console.log("Continuation message");
    state = sessions[senderID];

    console.log("Fetch current state:");
    console.log(state);

    var lowercaseMessage = messageText.toLowerCase();
    var newState = isInStateOptions(lowercaseMessage,state)

    console.log("New state:");
    console.log(newState);
    if(newState != null) {
      //transition to new state
      console.log("Replacing old state");
      state = newState;
      }
    else {
      console.log("Invalid input");
      sendTextMessage(senderID, "I couldn't understand that command (I'm not very smart).");
    }
  }
  sessions[senderID] = state;
  sendTextMessage(senderID,state.text);
}
/*
 * Delivery Confirmation Event
 *
 * This event is sent to confirm the delivery of a message. Read more about
 * these fields at https://developers.facebook.com/docs/messenger-platform/webhook-reference#message_delivery
 *
 */
function receivedDeliveryConfirmation(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var delivery = event.delivery;
  var messageIDs = delivery.mids;
  var watermark = delivery.watermark;
  var sequenceNumber = delivery.seq;

  if (messageIDs) {
    messageIDs.forEach(function(messageID) {
      console.log("Received delivery confirmation for message ID: %s",
        messageID);
    });
  }

  console.log("All message before %d were delivered.", watermark);
}

/*
 * Postback Event
 *
 * This event is called when a postback is tapped on a Structured Message. Read
 * more at https://developers.facebook.com/docs/messenger-platform/webhook-reference#postback
 *
 */
function receivedPostback(event) {
  var senderID = event.sender.id;
  var recipientID = event.recipient.id;
  var timeOfPostback = event.timestamp;

  // The 'payload' param is a developer-defined field which is set in a postback
  // button for Structured Messages.
  var payload = event.postback.payload;

  console.log("Received postback for user %d and page %d with payload '%s' " +
    "at %d", senderID, recipientID, payload, timeOfPostback);

  // When a postback is called, we'll send a message back to the sender to
  // let them know it was successful
  sendTextMessage(senderID, "Postback called");
}


/*
 * Send a message with an using the Send API.
 *
 */
function sendImageMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "image",
        payload: {
          url: "http://i.imgur.com/zYIlgBl.png"
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a text message using the Send API.
 *
 */
function sendTextMessage(recipientId, messageText) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      text: messageText
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a button message using the Send API.
 *
 */
function sendButtonMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "button",
          text: "This is test text",
          buttons:[{
            type: "web_url",
            url: "https://www.oculus.com/en-us/rift/",
            title: "Open Web URL"
          }, {
            type: "postback",
            title: "Call Postback",
            payload: "Developer defined postback"
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a Structured Message (Generic Message type) using the Send API.
 *
 */
function sendGenericMessage(recipientId) {
  var messageData = {
    recipient: {
      id: recipientId
    },
    message: {
      attachment: {
        type: "template",
        payload: {
          template_type: "generic",
          elements: [{
            title: "rift",
            subtitle: "Next-generation virtual reality",
            item_url: "https://www.oculus.com/en-us/rift/",
            image_url: "http://messengerdemo.parseapp.com/img/rift.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/rift/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for first bubble",
            }],
          }, {
            title: "touch",
            subtitle: "Your Hands, Now in VR",
            item_url: "https://www.oculus.com/en-us/touch/",
            image_url: "http://messengerdemo.parseapp.com/img/touch.png",
            buttons: [{
              type: "web_url",
              url: "https://www.oculus.com/en-us/touch/",
              title: "Open Web URL"
            }, {
              type: "postback",
              title: "Call Postback",
              payload: "Payload for second bubble",
            }]
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Send a receipt message using the Send API.
 *
 */
function sendReceiptMessage(recipientId) {
  // Generate a random receipt ID as the API requires a unique ID
  var receiptId = "order" + Math.floor(Math.random()*1000);

  var messageData = {
    recipient: {
      id: recipientId
    },
    message:{
      attachment: {
        type: "template",
        payload: {
          template_type: "receipt",
          recipient_name: "Peter Chang",
          order_number: receiptId,
          currency: "USD",
          payment_method: "Visa 1234",
          timestamp: "1428444852",
          elements: [{
            title: "Oculus Rift",
            subtitle: "Includes: headset, sensor, remote",
            quantity: 1,
            price: 599.00,
            currency: "USD",
            image_url: "http://messengerdemo.parseapp.com/img/riftsq.png"
          }, {
            title: "Samsung Gear VR",
            subtitle: "Frost White",
            quantity: 1,
            price: 99.99,
            currency: "USD",
            image_url: "http://messengerdemo.parseapp.com/img/gearvrsq.png"
          }],
          address: {
            street_1: "1 Hacker Way",
            street_2: "",
            city: "Menlo Park",
            postal_code: "94025",
            state: "CA",
            country: "US"
          },
          summary: {
            subtotal: 698.99,
            shipping_cost: 20.00,
            total_tax: 57.67,
            total_cost: 626.66
          },
          adjustments: [{
            name: "New Customer Discount",
            amount: -50
          }, {
            name: "$100 Off Coupon",
            amount: -100
          }]
        }
      }
    }
  };

  callSendAPI(messageData);
}

/*
 * Call the Send API. The message data goes in the body. If successful, we'll
 * get the message id in a response
 *
 */
function callSendAPI(messageData) {
  request({
    uri: 'https://graph.facebook.com/v2.6/me/messages',
    qs: { access_token: PAGE_ACCESS_TOKEN },
    method: 'POST',
    json: messageData

  }, function (error, response, body) {
    if (!error && response.statusCode == 200) {
      var recipientId = body.recipient_id;
      var messageId = body.message_id;

      console.log("Successfully sent generic message with id %s to recipient %s",
        messageId, recipientId);
    } else {
      console.error("Unable to send message.");
      console.error(response);
      console.error(error);
    }
  });
}

// Start server
// Webhooks must be available via SSL with a certificate signed by a valid
// certificate authority.
app.listen(app.get('port'), function() {
  console.log('Node app is running on port', app.get('port'));
});

module.exports = app;
