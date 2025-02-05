import express from 'express';
import fs from 'fs';
import path from 'path';
import readline from 'readline';

const app = express();
const LOG_FILE = "test.txt";

// Middleware to parse URL-encoded form data (for POST requests)
app.use(express.urlencoded({ extended: true }));

// Set up the view engine and directories (similar to Flask’s template_folder and static_folder)
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, '..', 'templates'));
app.use('/logs/static', express.static(path.join(__dirname, '..', 'static')));

// ----- Helper Types and Functions -----

// Define the shape of a call flow event.
interface CallFlowEvent {
  event: string;
  destination?: number;
  log: string;
  party?: string;
  reason?: string;
  detailed_reason?: string;
  who_ended?: string;
}

/**
 * Given a hangup reason code, returns a human-readable explanation.
 */
function interpretHangupReason(reason: string | null): string {
  const explanations: { [key: string]: string } = {
    "NORMAL_CLEARING": "The call ended normally.",
    "NO_ANSWER": "The call was not answered.",
    "USER_BUSY": "The callee was busy.",
    "CALL_REJECTED": "The call was rejected by the callee.",
    "ORIGINATOR_CANCEL": "The caller canceled the call before it was answered.",
    "NETWORK_OUT_OF_ORDER": "Network connectivity issues caused the call to drop.",
    "CS_EXECUTE": "The call was terminated while executing a dialplan action (e.g., IVR, script, or early termination).",
    "DESTINATION_OUT_OF_ORDER": "Call failed - Destination number is out of service or unreachable.",
    "WRONG_CALL_STATE": "Call failed due to an invalid call state."
  };
  return reason ? (explanations[reason] || "Unknown reason - check logs for more details.") : "";
}

/**
 * Processes a single log line to determine call routing events.
 */
function processCallFlowLine(line: string, callFlow: CallFlowEvent[]): void {
  const destinationMatch = line.match(/Transfer .*? to XML\[(\d+)@/);
  if (destinationMatch) {
    const destination = parseInt(destinationMatch[1], 10);
    let eventDescription = "Call Routed";
    if (destination >= 800 && destination <= 899) {
      eventDescription = "Time Condition Applied";
    } else if (destination >= 400 && destination <= 499) {
      eventDescription = "Call Sent to Ring Group";
    } else if (destination >= 200 && destination <= 399) {
      eventDescription = "Call Routed to an Extension";
    } else if (destination >= 600 && destination <= 699) {
      eventDescription = "Call Passed Through an IVR";
    }
    callFlow.push({
      event: eventDescription,
      destination,
      log: line.trim()
    });
  }
}

/**
 * Searches the log file for the last (most recent) Call-ID associated with the given dialed number.
 */
async function getLastCallId(dialedNumber: string): Promise<string | null> {
    if (!fs.existsSync(LOG_FILE)) return null;
    let lastCallId: string | null = null;
    try {
      const rl = readline.createInterface({
        input: fs.createReadStream(LOG_FILE, { encoding: 'utf8' }),
        crlfDelay: Infinity
      });
      for await (const line of rl) {
        if (line.includes(dialedNumber)) {
          const match = line.match(/([a-f0-9-]{36})/i);
          if (match) lastCallId = match[1];
        }
      }
    } catch (err) {
      const rl = readline.createInterface({
        input: fs.createReadStream(LOG_FILE, { encoding: 'latin1' }),
        crlfDelay: Infinity
      });
      for await (const line of rl) {
        if (line.includes(dialedNumber)) {
          const match = line.match(/([a-f0-9-]{36})/i);
          if (match) lastCallId = match[1];
        }
      }
    }
    return lastCallId;
  }
  

// Define the type for hangup details.
interface HangupDetails {
  firstHangup: string | null;
  hangupParty: string | null;
  hangupReason: string | null;
}

/**
 * Finds the first hangup details for the given Call-ID.
 */
async function findHangupDetails(callId: string): Promise<HangupDetails> {
  const details: HangupDetails = { firstHangup: null, hangupParty: null, hangupReason: null };
  if (!fs.existsSync(LOG_FILE)) {
    return details;
  }
  try {
    const rl = readline.createInterface({
      input: fs.createReadStream(LOG_FILE, { encoding: 'utf8' }),
      crlfDelay: Infinity
    });
    for await (const line of rl) {
      if (line.includes(callId) && line.includes("hanging up")) {
        const hangupMatch = line.match(/Channel (sofia\/\S+) hanging up, cause: (\S+)/);
        if (hangupMatch) {
          details.firstHangup = hangupMatch[1];
          details.hangupParty = hangupMatch[1];
          details.hangupReason = hangupMatch[2];
          break; // Only the first occurrence is needed.
        }
      }
    }
  } catch (err) {
    // Fallback: try with 'latin1' encoding
    const rl = readline.createInterface({
      input: fs.createReadStream(LOG_FILE, { encoding: 'latin1' }),
      crlfDelay: Infinity
    });
    for await (const line of rl) {
      if (line.includes(callId) && line.includes("hanging up")) {
        const hangupMatch = line.match(/Channel (sofia\/\S+) hanging up, cause: (\S+)/);
        if (hangupMatch) {
          details.firstHangup = hangupMatch[1];
          details.hangupParty = hangupMatch[1];
          details.hangupReason = hangupMatch[2];
          break;
        }
      }
    }
  }
  return details;
}


/**
 * Reads the SIP log file and returns the lines that contain the given extension and domain.
 * For example, for extension "200" and domain "9506.ip-com.co.il",
 * it will filter for lines containing "200@9506.ip-com.co.il".
 *
 * @param extension The extension provided by the user.
 * @param domain The domain provided by the user.
 * @returns A Promise that resolves to a string with matching log lines.
 */
interface SIPAuthResult {
    type: 'info' | 'warning' | 'danger';
    message: string;
    logs?: string;
  }
  
  async function getSIPAuthFailures(extension: string, domain: string): Promise<SIPAuthResult> {
    if (!fs.existsSync(LOG_FILE
)) {
      return {
        type: 'danger',
        message: `Log file ${LOG_FILE
} does not exist.`
      };
    }
    
    const searchString = `${extension}@${domain}`;
    const results: string[] = [];
    
    try {
      const rl = readline.createInterface({
        input: fs.createReadStream(LOG_FILE
, { encoding: 'utf8' }),
        crlfDelay: Infinity
      });
      for await (const line of rl) {
        if (line.includes(searchString)) {
          results.push(line);
        }
      }
    } catch (err) {
      const rl = readline.createInterface({
        input: fs.createReadStream(LOG_FILE
, { encoding: 'latin1' }),
        crlfDelay: Infinity
      });
      for await (const line of rl) {
        if (line.includes(searchString)) {
          results.push(line);
        }
      }
    }
    
    // Attempt to extract the SIP IP from the first matching line (if available)
    let sipIP: string = "";
    const ipRegex = /from ip\s+(\d+\.\d+\.\d+\.\d+)/i;
    for (const line of results) {
      const match = ipRegex.exec(line);
      if (match && match[1]) {
        sipIP = match[1];
        break;
      }
    }
    
    // Case 1: No matching lines found.
    if (results.length === 0) {
      return {
        type: 'info',
        message: `We did not receive a registration request for ${searchString} to the server. This likely means your device is sending its SIP request to a different domain than the one you entered (${domain}). Please check your SIP configuration and update the domain if necessary (for example, you might need to use a domain like xxxx.ip-com.co.il).`
      };
    }
    
    // Case 2: Extension does not exist (if any line contains "Can't find user").
    const extensionNotFound = results.some(line => line.includes("Can't find user"));
    if (extensionNotFound) {
      return {
        type: 'danger',
        message: `Extension ${searchString} does not exist on the server. Request sent from SIP IP: ${sipIP}`
      };
    }
    
    // Case 3: Registration attempt was sent (likely due to a wrong password).
    return {
      type: 'danger',
      message: `Registration request for ${searchString} was sent from SIP IP: ${sipIP}, but authentication failed due to a wrong password.`,
      logs: results.join('\n')
    };
  }
  
  
  
  
/**
 * Extracts call flow details using the most recent Call-ID.
 */
async function parseCallFlow(callId: string, dialedNumber: string): Promise<CallFlowEvent[]> {
  const callFlow: CallFlowEvent[] = [];
  if (!fs.existsSync(LOG_FILE)) {
    return callFlow;
  }
  const seenLogs = new Set<string>();
  try {
    const rl = readline.createInterface({
      input: fs.createReadStream(LOG_FILE, { encoding: 'utf8' }),
      crlfDelay: Infinity
    });
    for await (const line of rl) {
      if (line.includes(callId) && !seenLogs.has(line)) {
        seenLogs.add(line);
        processCallFlowLine(line, callFlow);
      }
    }
  } catch (err) {
    const rl = readline.createInterface({
      input: fs.createReadStream(LOG_FILE, { encoding: 'latin1' }),
      crlfDelay: Infinity
    });
    for await (const line of rl) {
      if (line.includes(callId) && !seenLogs.has(line)) {
        seenLogs.add(line);
        processCallFlowLine(line, callFlow);
      }
    }
  }
  
  const { hangupParty, hangupReason } = await findHangupDetails(callId);
  const detailedReason = hangupReason ? interpretHangupReason(hangupReason) : "";
  
  if (hangupReason && hangupParty) {
    const whoEnded = dialedNumber && hangupParty.includes(dialedNumber)
      ? "Callee Disconnected First"
      : "Caller Disconnected First";
    callFlow.push({
      event: "Call Ended",
      party: hangupParty,
      reason: hangupReason,
      detailed_reason: detailedReason,
      who_ended: whoEnded,
      log: `${whoEnded} - Hangup by ${hangupParty} due to ${hangupReason} (${detailedReason})`
    });
  }
  
  return callFlow;
}

// ----- Route Handlers -----

app.post('/logs/', async (req, res) => {
    // Identify which form was submitted via a hidden "action" field.
    const action: string = req.body.action;
    
    if (action === 'callflow') {
      // Handle Call Flow Search (existing logic)
      const number: string = req.body.number || "";
      let flow: any[] = [];
      if (number) {
        const callId = await getLastCallId(number);
        if (callId) {
          flow = await parseCallFlow(callId, number);
        }
      }
      res.render('index', { number, flow, sipAuthResult: null });
      
    } else if (action === 'sipauth') {
      // Handle SIP Auth Analysis
      const extension: string = req.body.extension;
      const domain: string = req.body.domain;
      const sipAuthResult = await getSIPAuthFailures(extension, domain);
      res.render('index', { number: '', flow: null, sipAuthResult });
      
    } else {
      res.render('index', { number: '', flow: null, sipAuthResult: null });
    }
  });
  
  app.get('/logs/', (req, res) => {
    res.render('index', { number: '', flow: null, sipAuthResult: null });
  });
  
  // Start the server.
  const PORT = 5000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`Server running on http://0.0.0.0:${PORT}`);
  });
