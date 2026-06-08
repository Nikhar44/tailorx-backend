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
    final hipOffset   = bodyType == slim ?  -2.0 : bodyType == plus ?  6.0  :   2.0;

    final waist = chest + waistOffset;
    final hip   = chest + hipOffset;

    return {
      'top': {
        'Chest':        chest,
        'Shoulder':     _r(chest / 2.5 + 1.5),
        'Neck':         _r(chest / 3.0 + 1.0),
        'Sleeve':       _r(h * 0.345),
        'Shirt Length': _r(h * 0.415),
        'Back Width':   _r(chest / 2.0 - 1.0),
      },
      'bottom': {
        'Waist':         _r(waist),
        'Hip':           _r(hip),
        'Inseam':        _r(h * 0.47),
        'Trouser Waist': _r(waist),
        'Thigh':         _r(hip / 2.0 + 2.5),
        'Knee':          _r(hip / 2.0 - 1.5),
        'Ankle':         _r(hip / 2.0 - 5.5),
        'Pant Length':   _r(h * 0.55),
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
        'Length':            _r(h * 0.245),
        'Front':             _r(bust / 2.0 + 1.0),
        'Chest 1':           bust,
        'Chest 2':           _r(bust - 3.0),
        'Shoulder':          _r(bust / 2.5 + 0.5),
        'Sleeve':            _r(h * 0.315),
        'Sleeve Bottom':     11.0,
        'Back/Front Length': _r(h * 0.22),
        'Neck Depth':        3.5,
        'Armhole':           _r(bust / 4.0 + 1.0),
      },
      'dress': {
        'Length':        _r(h * 0.60),
        'Chest 1':       bust,
        'Chest 2':       _r(bust - 3.0),
        'Waist':         _r(waist),
        'Shoulder':      _r(bust / 2.5 + 0.5),
        'Sleeve':        _r(h * 0.315),
        'Sleeve Bottom': 11.0,
        'Back Length':   _r(h * 0.22),
        'Neck Depth':    3.5,
        'Armhole':       _r(bust / 4.0 + 1.0),
      },
      'bottom': {
        'Salwar Length': _r(h * 0.605),
        'Waist':         _r(waist),
        'Hip':           _r(hip),
        'Thigh':         _r(hip / 2.0 + 1.5),
        'Knee':          _r(hip / 2.0 - 2.5),
      },
    };
  }

  // Round to nearest 0.5 inch
  static double _r(double v) => (v * 2).round() / 2.0;

  // Convert feet+inches string like "5'7" to cm
  static double feetToCm(double feet, double inches) =>
      (feet * 12 + inches) * 2.54;
}
