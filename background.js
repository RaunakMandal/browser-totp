const SESSION_KEY = "sessionKey";
const AUTO_LOCK_ALARM = "autoLock";

chrome.runtime.onInstalled.addListener(() => {
  console.log("Browser TOTP extension installed.");
});

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name === AUTO_LOCK_ALARM) {
    chrome.storage.session.remove(SESSION_KEY);
  }
});
