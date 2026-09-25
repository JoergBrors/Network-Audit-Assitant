import { broadcastResponseToMainFrame } from "@azure/msal-browser/redirect-bridge";

/**
 * Entry point of redirect.html (the MSAL v5 redirect bridge). Popup and silent flows return here;
 * the response is broadcast to the main window, which completes token acquisition.
 */
broadcastResponseToMainFrame().catch((error: unknown) => {
  console.error("MSAL redirect bridge failed", error);
});
