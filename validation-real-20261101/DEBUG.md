# Device reconnection — 2026-11-01

## Observations

- `adb devices -l` returns an empty list; restarting the ADB server does not change it.
- Windows sees the expected USB instance `USB\VID_22D9&PID_2769\PJ696HEY9DNRLFFQ`.
- Its Android ADB Interface uses WinUSB / oem167.inf and reports problem code 10 (CM_PROB_FAILED_START), status 0xC0000001.
- The DroidBridge connector also has no polling tunnel-client connection.
- The original and first supplemental captures remain intact and stopped.

## Hypotheses

### H1: The ADB server has stale transport state
- Supports: reconnection is needed after the prior session.
- Conflicts: the Windows device itself has a failed-start status.
- Test: restart the ADB server and enumerate devices.
- Result: rejected as the sufficient cause; the device list remains empty.

### H2: The Windows ADB USB interface failed to initialize (primary current blocker)
- Supports: the exact expected device is present and reports CM_PROB_FAILED_START.
- Conflicts: the reason the driver failed to initialize is not yet known.
- Test: restart only this device instance, then enumerate ADB.
- Result: inconclusive as a repair; pnputil was denied access. No driver was installed or removed.

### H3: The physical USB/debugging state needs renewed enumeration or authorization
- Supports: USB enumeration can see the phone but the debugging transport is unavailable.
- Conflicts: this is not an `unauthorized` ADB entry, so missing authorization alone is not established.
- Test: unplug/replug the phone and unlock it, then check Windows problem code and ADB state again.
- Result: after the user restored the USB connection, ADB enumerated the expected device and Windows reported the interface as OK. This resolves the connection blocker; it does not identify the underlying cause of the earlier failed-start status.

## Experiments

1. `adb reconnect offline` and mDNS discovery: no transport/service found.
2. Stop/start ADB server: still no device.
3. Query PnP device properties: code 10 confirmed, expected serial and WinUSB driver.
4. Restart this exact PnP instance: access denied; no privileged workaround attempted.

## Current conclusion

Connection recovered. The game still runs version 69.114.1, with new PID 3705. Frida 16.7.19 successfully attached through local port 37043 to the existing phone listener on 27042. A second listener was unnecessary (the attempted server startup reported address already in use). The isolated port-28472 capture then collected and acknowledged 10 frames with zero errors, including two non-null optional_long_104 branches. All temporary capture and observation hooks and the receiver were stopped after verification. No driver was installed or removed.
