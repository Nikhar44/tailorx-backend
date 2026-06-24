class C {
  static const String supabaseUrl = 'https://qhujzhjuamizvsvuwcnr.supabase.co';
  static const String supabaseKey = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6InFodWp6aGp1YW1penZzdnV3Y25yIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NzU0NDQxOTcsImV4cCI6MjA5MTAyMDE5N30.7Zb7Mp8WDV88Ozy6ZFUzHTiD9HMZ8C9jeGRx9sYGgNM';

  static const String baseUrl = 'https://tailorx-backend.onrender.com';
  static const String login = '$baseUrl/api/auth/login';
  static const String register = '$baseUrl/api/auth/register';
  static const String customers = '$baseUrl/api/customers';
  static String customer(int id) => '$baseUrl/api/customers/$id';
  static const String orders = '$baseUrl/api/orders';
  static String order(int id) => '$baseUrl/api/orders/$id';
  static String orderStatus(int id) => '$baseUrl/api/orders/$id/status';
  static const String invoices = '$baseUrl/api/invoices';
  static String invoice(int id) => '$baseUrl/api/invoices/$id';
  static const String notifications = '$baseUrl/api/notifications';
  static const String dashboard = '$baseUrl/api/dashboard';

  static const statuses = ['Received','Cutting','Stitching','Trial','Ready','Delivered'];
  static const garments = ['Blouse','Lehenga','Suit','Kurta','Sherwani','Saree Blouse',
    'Salwar Kameez','Shirt','Trouser','Dupatta','Petticoat','Gown','Jacket','Waistcoat','Other'];
  static const priorities = ['Normal','Urgent','Rush'];

  static const maleTop = ['Length','Chest','Waist','Seat','Sleeves','Shoulder','Collar','Cuff','Front 1','Front 2','Front 3'];
  static const maleBottom = ['Length','Waist','Seat','Thigh','Knee','Bottom','In Length','Jolo','Fly'];
  // Separate blouse and dress field lists for female top
  static const femaleTopBlouse = ['Length','Front','Chest 1','Chest 2','Waist','Shoulder','Sleeve','Sleeve Bottom'];
  static const femaleTopDress  = ['Length','Front','Chest 1','Chest 2','Waist','Hips','Shoulder','Sleeve','Sleeve Bottom'];
  static const femaleBottom = ['Length','Waist','Hips','Thigh','Knee','Bottom'];

  // Maps each measurement section + field display name to the illustration
  // asset key in assets/measurement_guides/<key>.png
  static const Map<String, Map<String, String>> measurementGuides = {
    'maleTop': {
      'Chest': 'm_chest',
      'Shoulder': 'm_shoulder',
      'Sleeves': 'm_sleeve',
      'Length': 'm_shirt_length',
    },
    'maleBottom': {
      'Waist': 'b_waist',
      'Thigh': 'b_thigh',
      'Knee': 'b_knee',
      'Length': 'b_pant_length',
    },
    'femaleTopBlouse': {
      'Length': 'length',
      'Front': 'front',
      'Chest 1': 'chest_1',
      'Chest 2': 'chest_2',
      'Shoulder': 'shoulder',
      'Sleeve': 'sleeve',
      'Sleeve Bottom': 'sleeve_bottom',
    },
    'femaleTopDress': {
      'Length': 'length',
      'Front': 'front',
      'Chest 1': 'chest_1',
      'Chest 2': 'chest_2',
      'Waist': 'waist',
      'Shoulder': 'shoulder',
      'Sleeve': 'sleeve',
      'Sleeve Bottom': 'sleeve_bottom',
    },
    'femaleBottom': {
      'Length': 'b_salwar_length',
      'Waist': 'b_waist',
      'Hips': 'b_hip',
      'Thigh': 'b_thigh',
      'Knee': 'b_knee',
    },
  };

  /// Returns the measurement guide asset key for a given section + field
  /// display name, or null if no illustration exists for it (e.g. custom fields).
  static String? guideAsset(String section, String field) =>
      measurementGuides[section]?[field];
}
