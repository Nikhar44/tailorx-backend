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
}
