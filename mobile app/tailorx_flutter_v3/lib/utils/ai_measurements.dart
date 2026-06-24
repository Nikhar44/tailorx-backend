// AI Measurement Suggestion Engine
// Uses body proportion analysis to suggest tailoring measurements
// Based on industry-standard ratios used by professional tailors

class AIMeasurements {
  static const String slim    = 'Slim';
  static const String average = 'Average';
  static const String plus    = 'Plus Size';

  // ─── MALE suggestions ────────────────────────────────────────────
  // Inputs: heightCm, chest (inches), bodyType
  static Map<String, Map<String, double>> suggestMale({
    required double heightCm,
    required double chest,
    required String bodyType,
  }) {
    final h = heightCm / 2.54; // convert to inches

    final waistOffset = bodyType == slim ? -14.0 : bodyType == plus ? -6.0  : -10.0;
    final seatOffset  = bodyType == slim ?  -2.0 : bodyType == plus ?  6.0  :   2.0;

    final waist = chest + waistOffset;
    final seat  = chest + seatOffset;

    return {
      'top': {
        'Length':   _r(h * 0.415),
        'Chest':    chest,
        'Waist':    _r(waist),
        'Seat':     _r(seat),
        'Sleeves':  _r(h * 0.345),
        'Shoulder': _r(chest / 2.5 + 1.5),
        'Collar':   _r(chest / 3.0 + 1.0),
        'Cuff':     5.5,
        'Front 1':  _r(h * 0.415 * 0.5),
        'Front 2':  _r(h * 0.415 * 0.6),
        'Front 3':  _r(h * 0.415 * 0.7),
      },
      'bottom': {
        'Length':   _r(h * 0.55),
        'Waist':    _r(waist),
        'Seat':     _r(seat),
        'Thigh':    _r(seat / 2.0 + 2.5),
        'Knee':     _r(seat / 2.0 - 1.5),
        'Bottom':   _r(seat / 2.0 - 4.0),
        'In Length':_r(h * 0.47),
        'Jolo':     _r(h * 0.12),
        'Fly':      _r(h * 0.10),
      },
    };
  }

  // ─── FEMALE suggestions ──────────────────────────────────────────
  // Inputs: heightCm, bust = Chest 1 (inches), bodyType
  static Map<String, Map<String, double>> suggestFemale({
    required double heightCm,
    required double bust,
    required String bodyType,
  }) {
    final h = heightCm / 2.54;

    final waistOffset = bodyType == slim ? -14.0 : bodyType == plus ? -6.0 : -11.0;
    final hipOffset   = bodyType == slim ?   0.0 : bodyType == plus ?  8.0 :   4.0;

    final waist = bust + waistOffset;
    final hip   = bust + hipOffset;

    return {
      'blouse': {
        'Length':       _r(h * 0.245),
        'Front':        _r(bust / 2.0 + 1.0),
        'Chest 1':      bust,
        'Chest 2':      _r(bust - 3.0),
        'Waist':        _r(waist),
        'Shoulder':     _r(bust / 2.5 + 0.5),
        'Sleeve':       _r(h * 0.315),
        'Sleeve Bottom':11.0,
      },
      'dress': {
        'Length':       _r(h * 0.60),
        'Front':        _r(bust / 2.0 + 1.0),
        'Chest 1':      bust,
        'Chest 2':      _r(bust - 3.0),
        'Waist':        _r(waist),
        'Hips':         _r(hip),
        'Shoulder':     _r(bust / 2.5 + 0.5),
        'Sleeve':       _r(h * 0.315),
        'Sleeve Bottom':11.0,
      },
      'bottom': {
        'Length': _r(h * 0.605),
        'Waist':  _r(waist),
        'Hips':   _r(hip),
        'Thigh':  _r(hip / 2.0 + 1.5),
        'Knee':   _r(hip / 2.0 - 2.5),
        'Bottom': _r(hip / 2.0 - 4.0),
      },
    };
  }

  // Round to nearest 0.5 inch
  static double _r(double v) => (v * 2).round() / 2.0;

  // Convert feet+inches string like "5'7" to cm
  static double feetToCm(double feet, double inches) =>
      (feet * 12 + inches) * 2.54;
}
