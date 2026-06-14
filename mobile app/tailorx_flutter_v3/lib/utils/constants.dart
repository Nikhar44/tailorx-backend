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

  static const maleTop = ['Chest','Shoulder','Neck','Sleeve','Shirt Length','Back Width'];
  static const maleBottom = ['Waist','Hip','Inseam','Trouser Waist','Thigh','Knee','Ankle','Pant Length'];
  static const femaleTop = ['Length','Front','Chest 1','Chest 2','Shoulder','Sleeve',
    'Sleeve Bottom','Blouse Length','Back/Front Length','Neck Depth','Armhole'];
  // Separate blouse and dress field lists for female top
  static const femaleTopBlouse = ['Length','Front','Chest 1','Chest 2','Shoulder','Sleeve',
    'Sleeve Bottom','Back/Front Length','Neck Depth','Armhole'];
  static const femaleTopDress  = ['Length','Chest 1','Chest 2','Waist','Shoulder','Sleeve',
    'Sleeve Bottom','Back Length','Neck Depth','Armhole'];
  static const femaleBottom = ['Salwar Length','Waist','Hip','Thigh','Knee'];

  // Maps each measurement section + field display name to the illustration
  // asset key in assets/measurement_guides/<key>.png
  static const Map<String, Map<String, String>> measurementGuides = {
    'maleTop': {
      'Chest': 'm_chest',
      'Shoulder': 'm_shoulder',
      'Neck': 'm_neck',
      'Sleeve': 'm_sleeve',
      'Shirt Length': 'm_shirt_length',
      'Back Width': 'm_back_width',
    },
    'maleBottom': {
      'Waist': 'b_waist',
      'Hip': 'b_hip',
      'Inseam': 'b_inseam',
      'Trouser Waist': 'b_trouser_waist',
      'Thigh': 'b_thigh',
      'Knee': 'b_knee',
      'Ankle': 'b_ankle',
      'Pant Length': 'b_pant_length',
    },
    'femaleTopBlouse': {
      'Length': 'length',
      'Front': 'front',
      'Chest 1': 'chest_1',
      'Chest 2': 'chest_2',
      'Shoulder': 'shoulder',
      'Sleeve': 'sleeve',
      'Sleeve Bottom': 'sleeve_bottom',
      'Back/Front Length': 'back_front_length',
      'Neck Depth': 'neck_depth',
      'Armhole': 'armhole',
    },
    'femaleTopDress': {
      'Length': 'length',
      'Chest 1': 'chest_1',
      'Chest 2': 'chest_2',
      'Waist': 'waist',
      'Shoulder': 'shoulder',
      'Sleeve': 'sleeve',
      'Sleeve Bottom': 'sleeve_bottom',
      'Back Length': 'back_length',
      'Neck Depth': 'neck_depth',
      'Armhole': 'armhole',
    },
    'femaleBottom': {
      'Salwar Length': 'b_salwar_length',
      'Waist': 'b_waist',
      'Hip': 'b_hip',
      'Thigh': 'b_thigh',
      'Knee': 'b_knee',
    },
  };

  /// Returns the measurement guide asset key for a given section + field
  /// display name, or null if no illustration exists for it (e.g. custom fields).
  static String? guideAsset(String section, String field) =>
      measurementGuides[section]?[field];
}
