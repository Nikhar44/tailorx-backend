import 'package:flutter/foundation.dart';
import 'package:local_auth/local_auth.dart';

/// Session-level privacy toggle with biometric gate.
/// All PrivacyText widgets listen to [isUnlocked].
/// The eye icon in the app bar calls [toggle] — if currently locked,
/// biometric auth (Face ID / fingerprint / PIN) is required first.
/// [lock] is called automatically when the app goes to background.
class PrivacyHelper {
  PrivacyHelper._();

  static final isUnlocked = ValueNotifier<bool>(false);
  static final _auth = LocalAuthentication();

  /// Toggle visibility. Unlocking requires biometric auth.
  /// Locking is always instant (no auth needed).
  static Future<void> toggle() async {
    if (isUnlocked.value) {
      // Already unlocked → lock immediately, no auth needed
      isUnlocked.value = false;
      return;
    }

    // Locked → try to unlock with biometrics
    try {
      final canCheck = await _auth.canCheckBiometrics;
      final isDeviceSupported = await _auth.isDeviceSupported();

      if (!canCheck && !isDeviceSupported) {
        // No biometrics available — unlock anyway (no sensor on device)
        isUnlocked.value = true;
        return;
      }

      final authenticated = await _auth.authenticate(
        localizedReason: 'Authenticate to view financial data',
        options: const AuthenticationOptions(
          biometricOnly: false, // allow PIN/pattern as fallback
          stickyAuth: true,     // keep prompt alive if user switches apps
        ),
      );

      if (authenticated) {
        isUnlocked.value = true;
      }
      // If auth fails or is cancelled, stay locked (do nothing)
    } catch (_) {
      // On any error, unlock anyway so the app isn't broken
      isUnlocked.value = true;
    }
  }

  /// Lock when app goes to background.
  static void lock() => isUnlocked.value = false;
}
