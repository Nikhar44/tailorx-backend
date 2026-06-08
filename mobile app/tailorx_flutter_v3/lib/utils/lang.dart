import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';

class AppLang extends ChangeNotifier {
  static final AppLang _i = AppLang._();
  factory AppLang() => _i;
  AppLang._();

  String _locale = 'en';
  String get locale => _locale;

  static const Map<String, String> supportedLanguages = {
    'en': 'English',
    'hi': 'हिन्दी',
    'gu': 'ગુજરાતી',
    'mr': 'मराठी',
  };

  Future<void> init() async {
    final p = await SharedPreferences.getInstance();
    _locale = p.getString('lang') ?? 'en';
    notifyListeners();
  }

  Future<void> setLocale(String code) async {
    _locale = code;
    final p = await SharedPreferences.getInstance();
    await p.setString('lang', code);
    notifyListeners();
  }

  String t(String key) => (_translations[_locale] ?? _translations['en']!)[key] ?? _translations['en']![key] ?? key;

  static const Map<String, Map<String, String>> _translations = {
    // ─── ENGLISH ───────────────────────────────────────────────────────────────
    'en': {
      // Nav
      'dashboard': 'Dashboard', 'customers': 'Customers', 'orders': 'Orders',
      'invoices': 'Invoices', 'settings': 'Settings',
      // Dashboard
      'overview': 'Overview', 'total_customers': 'Customers', 'total_orders': 'Total Orders',
      'revenue': 'Revenue', 'pending': 'Pending', 'pending_orders': 'Pending Orders',
      'require_attention': 'Require your attention', 'recent_orders': 'Recent Orders',
      'no_orders_yet': 'No orders yet', 'quick_actions': 'Quick Actions',
      'new_customer': 'New Customer', 'new_order': 'New Order',
      // Customers
      'search_customers': 'Search by name or phone...', 'add_customer': 'Add Customer',
      'edit_customer': 'Edit Customer', 'no_customers': 'No Customers',
      'add_first_customer': 'Add your first customer to get started',
      'name': 'Name', 'phone': 'Phone', 'email': 'Email', 'address': 'Address',
      'city': 'City', 'gender': 'Gender', 'male': 'Male', 'female': 'Female',
      'notes': 'Notes', 'notification_pref': 'Notification Preference',
      'measurements': 'Measurements', 'top_measurements': 'Top', 'bottom_measurements': 'Bottom',
      'add_custom_field': '+ Add Custom Field', 'custom_field_name': 'Field Name',
      'save_changes': 'Save Changes', 'customer_added': 'Customer added',
      'customer_updated': 'Customer updated', 'required': 'Required',
      // Orders
      'all': 'All', 'create_order': 'Create Order', 'no_orders': 'No Orders',
      'create_first_order': 'Create your first order', 'customer': 'Customer',
      'select_customer': 'Select customer', 'order_items': 'Order Items',
      'add_item': '+ Add Item', 'garment': 'Garment', 'fabric': 'Fabric',
      'qty': 'Qty', 'price': 'Price', 'subtotal': 'Subtotal',
      'advance_paid': 'Advance Paid', 'balance_due': 'Balance Due',
      'priority': 'Priority', 'delivery_date': 'Delivery Date', 'trial_date': 'Trial Date',
      'select_date': 'Select date', 'order_created': 'Order created',
      'update_status': 'Update Status', 'status_updated': 'Status updated',
      'add_customers_first': 'Add customers first',
      'total': 'Total', 'advance': 'Advance', 'balance': 'Balance', 'due': 'Due',
      // Invoices
      'unpaid': 'Unpaid', 'partial': 'Partial', 'paid': 'Paid',
      'no_invoices': 'No Invoices', 'invoices_auto': 'Invoices are created with orders',
      'record_payment': 'Record Payment', 'payment_amount': 'Payment Amount',
      'payment_recorded': 'Payment recorded', 'share_bill': 'Share Bill',
      'pay': 'Pay', 'share': 'Share',
      // Settings
      'boutique_info': 'Boutique Info', 'boutique_name': 'Boutique Name',
      'language': 'Language', 'select_language': 'Select Language',
      'support': 'Support', 'contact_support': 'Contact & Support',
      'whatsapp_support': 'WhatsApp Support', 'email_us': 'Email Us',
      'report_bug': 'Report a Bug', 'about': 'About', 'version': 'Version',
      'sign_out': 'Sign Out', 'sign_out_confirm': 'Are you sure?',
      'cancel': 'Cancel', 'crafted': 'Crafted for the finest tailors',
      // Auth
      'welcome_back': 'Welcome Back', 'create_account': 'Create Account',
      'sign_in_subtitle': 'Sign in to manage your boutique',
      'register_subtitle': 'Set up your boutique in seconds',
      'sign_in': 'Sign In', 'register': 'Register',
      'no_account': "Don't have an account?", 'have_account': 'Already have an account?',
      'password': 'Password', 'min_chars': 'Min 6 characters', 'invalid_email': 'Invalid email',
      'owner_name': 'Owner Name', 'shop_address': 'Shop Address', 'shop_details': 'Shop Details',
      'register_step2_subtitle': 'Almost done! Add your contact info',
      'invalid_phone': 'Enter a valid phone number',
      'optional': 'Optional', 'back': 'Back', 'next': 'Next',
      // Status
      'received': 'Received', 'cutting': 'Cutting', 'stitching': 'Stitching',
      'trial': 'Trial', 'ready': 'Ready', 'delivered': 'Delivered',
      // Misc
      'error': 'Error', 'retry': 'Retry', 'connection_error': 'Connection Error',
      'server_waking': 'Server may be waking up. Pull down to retry.',
      'notifications': 'Notifications', 'search': 'Search',
    },

    // ─── HINDI ─────────────────────────────────────────────────────────────────
    'hi': {
      // Nav
      'dashboard': 'डैशबोर्ड', 'customers': 'ग्राहक', 'orders': 'ऑर्डर',
      'invoices': 'बिल', 'settings': 'सेटिंग्स',
      // Dashboard
      'overview': 'अवलोकन', 'total_customers': 'ग्राहक', 'total_orders': 'कुल ऑर्डर',
      'revenue': 'आय', 'pending': 'बाकी', 'pending_orders': 'बाकी ऑर्डर',
      'require_attention': 'ध्यान की जरूरत है', 'recent_orders': 'हाल के ऑर्डर',
      'no_orders_yet': 'अभी कोई ऑर्डर नहीं', 'quick_actions': 'त्वरित कार्रवाई',
      'new_customer': 'नया ग्राहक', 'new_order': 'नया ऑर्डर',
      // Customers
      'search_customers': 'नाम या फोन से खोजें...', 'add_customer': 'ग्राहक जोड़ें',
      'edit_customer': 'ग्राहक संपादित करें', 'no_customers': 'कोई ग्राहक नहीं',
      'add_first_customer': 'शुरू करने के लिए पहला ग्राहक जोड़ें',
      'name': 'नाम', 'phone': 'फोन', 'email': 'ईमेल', 'address': 'पता',
      'city': 'शहर', 'gender': 'लिंग', 'male': 'पुरुष', 'female': 'महिला',
      'notes': 'नोट्स', 'notification_pref': 'सूचना प्राथमिकता',
      'measurements': 'नाप', 'top_measurements': 'ऊपर', 'bottom_measurements': 'नीचे',
      'add_custom_field': '+ कस्टम फ़ील्ड जोड़ें', 'custom_field_name': 'फ़ील्ड नाम',
      'save_changes': 'बदलाव सहेजें', 'customer_added': 'ग्राहक जोड़ा गया',
      'customer_updated': 'ग्राहक अपडेट किया गया', 'required': 'आवश्यक',
      // Orders
      'all': 'सभी', 'create_order': 'ऑर्डर बनाएं', 'no_orders': 'कोई ऑर्डर नहीं',
      'create_first_order': 'पहला ऑर्डर बनाएं', 'customer': 'ग्राहक',
      'select_customer': 'ग्राहक चुनें', 'order_items': 'ऑर्डर आइटम',
      'add_item': '+ आइटम जोड़ें', 'garment': 'पोशाक', 'fabric': 'कपड़ा',
      'qty': 'मात्रा', 'price': 'कीमत', 'subtotal': 'उप-कुल',
      'advance_paid': 'अग्रिम भुगतान', 'balance_due': 'बकाया राशि',
      'priority': 'प्राथमिकता', 'delivery_date': 'डिलीवरी तारीख', 'trial_date': 'ट्रायल तारीख',
      'select_date': 'तारीख चुनें', 'order_created': 'ऑर्डर बनाया गया',
      'update_status': 'स्थिति अपडेट करें', 'status_updated': 'स्थिति अपडेट की गई',
      'add_customers_first': 'पहले ग्राहक जोड़ें',
      'total': 'कुल', 'advance': 'अग्रिम', 'balance': 'बाकी', 'due': 'बकाया',
      // Invoices
      'unpaid': 'अवैतनिक', 'partial': 'आंशिक', 'paid': 'भुगतान किया',
      'no_invoices': 'कोई बिल नहीं', 'invoices_auto': 'बिल ऑर्डर के साथ बनाए जाते हैं',
      'record_payment': 'भुगतान दर्ज करें', 'payment_amount': 'भुगतान राशि',
      'payment_recorded': 'भुगतान दर्ज किया गया', 'share_bill': 'बिल शेयर करें',
      'pay': 'भुगतान करें', 'share': 'शेयर',
      // Settings
      'boutique_info': 'बुटीक जानकारी', 'boutique_name': 'बुटीक नाम',
      'language': 'भाषा', 'select_language': 'भाषा चुनें',
      'support': 'सहायता', 'contact_support': 'संपर्क और सहायता',
      'whatsapp_support': 'WhatsApp सहायता', 'email_us': 'ईमेल करें',
      'report_bug': 'बग रिपोर्ट करें', 'about': 'बारे में', 'version': 'संस्करण',
      'sign_out': 'लॉग आउट', 'sign_out_confirm': 'क्या आप निश्चित हैं?',
      'cancel': 'रद्द', 'crafted': 'श्रेष्ठ दर्जियों के लिए बनाया गया',
      // Auth
      'welcome_back': 'वापस स्वागत है', 'create_account': 'खाता बनाएं',
      'sign_in_subtitle': 'अपना बुटीक प्रबंधित करने के लिए साइन इन करें',
      'register_subtitle': 'कुछ ही सेकंड में अपना बुटीक सेट करें',
      'sign_in': 'साइन इन', 'register': 'रजिस्टर',
      'no_account': 'खाता नहीं है?', 'have_account': 'पहले से खाता है?',
      'password': 'पासवर्ड', 'min_chars': 'कम से कम 6 अक्षर', 'invalid_email': 'अमान्य ईमेल',
      'owner_name': 'मालिक का नाम', 'shop_address': 'दुकान का पता', 'shop_details': 'दुकान विवरण',
      'register_step2_subtitle': 'लगभग हो गया! अपनी संपर्क जानकारी जोड़ें',
      'invalid_phone': 'वैध फोन नंबर दर्ज करें',
      'optional': 'वैकल्पिक', 'back': 'वापस', 'next': 'अगला',
      // Status
      'received': 'प्राप्त', 'cutting': 'कटाई', 'stitching': 'सिलाई',
      'trial': 'ट्रायल', 'ready': 'तैयार', 'delivered': 'डिलीवर',
      // Misc
      'error': 'त्रुटि', 'retry': 'पुनः प्रयास', 'connection_error': 'कनेक्शन त्रुटि',
      'server_waking': 'सर्वर जाग रहा है। नीचे खींचें।',
      'notifications': 'सूचनाएं', 'search': 'खोजें',
    },

    // ─── GUJARATI ──────────────────────────────────────────────────────────────
    'gu': {
      // Nav
      'dashboard': 'ડેશબોર્ડ', 'customers': 'ગ્રાહકો', 'orders': 'ઓર્ડર',
      'invoices': 'બિલ', 'settings': 'સેટિંગ્સ',
      // Dashboard
      'overview': 'અવલોકન', 'total_customers': 'ગ્રાહકો', 'total_orders': 'કુલ ઓર્ડર',
      'revenue': 'આવક', 'pending': 'બાકી', 'pending_orders': 'બાકી ઓર્ડર',
      'require_attention': 'ધ્યાન જોઈએ', 'recent_orders': 'તાજેતરના ઓર્ડર',
      'no_orders_yet': 'હજુ કોઈ ઓર્ડર નથી', 'quick_actions': 'ઝડપી ક્રિયા',
      'new_customer': 'નવો ગ્રાહક', 'new_order': 'નવો ઓર્ડર',
      // Customers
      'search_customers': 'નામ અથવા ફોન દ્વારા શોધો...', 'add_customer': 'ગ્રાહક ઉમેરો',
      'edit_customer': 'ગ્રાહક સંપાદિત કરો', 'no_customers': 'કોઈ ગ્રાહક નથી',
      'add_first_customer': 'શરૂ કરવા માટે પ્રથમ ગ્રાહક ઉમેરો',
      'name': 'નામ', 'phone': 'ફોન', 'email': 'ઇમેઇલ', 'address': 'સરનામું',
      'city': 'શહેર', 'gender': 'જાતિ', 'male': 'પુરુષ', 'female': 'સ્ત્રી',
      'notes': 'નોંધ', 'notification_pref': 'સૂચના પ્રાધાન્ય',
      'measurements': 'માપ', 'top_measurements': 'ઉપર', 'bottom_measurements': 'નીચે',
      'add_custom_field': '+ કસ્ટમ ક્ષેત્ર ઉમેરો', 'custom_field_name': 'ક્ષેત્ર નામ',
      'save_changes': 'ફેરફારો સાચવો', 'customer_added': 'ગ્રાહક ઉમેર્યો',
      'customer_updated': 'ગ્રાહક અપડેટ થયો', 'required': 'જરૂરી',
      // Orders
      'all': 'બધા', 'create_order': 'ઓર્ડર બનાવો', 'no_orders': 'કોઈ ઓર્ડર નથી',
      'create_first_order': 'પ્રથમ ઓર્ડર બનાવો', 'customer': 'ગ્રાહક',
      'select_customer': 'ગ્રાહક પસંદ કરો', 'order_items': 'ઓર્ડર આઇટમ',
      'add_item': '+ આઇટમ ઉમેરો', 'garment': 'વસ્ત્ર', 'fabric': 'કપડું',
      'qty': 'જથ્થો', 'price': 'કિંમત', 'subtotal': 'પેટા-કુલ',
      'advance_paid': 'અગ્રિમ ભુગતાન', 'balance_due': 'બાકી રકમ',
      'priority': 'પ્રાધાન્ય', 'delivery_date': 'ડિલિવરી તારીખ', 'trial_date': 'ટ્રાયલ તારીખ',
      'select_date': 'તારીખ પસંદ કરો', 'order_created': 'ઓર્ડર બન્યો',
      'update_status': 'સ્થિતિ અપડેટ કરો', 'status_updated': 'સ્થિતિ અપડેટ થઈ',
      'add_customers_first': 'પ્રથમ ગ્રાહક ઉમેરો',
      'total': 'કુલ', 'advance': 'અગ્રિમ', 'balance': 'બાકી', 'due': 'બાકી',
      // Invoices
      'unpaid': 'ન ચૂકવ્યું', 'partial': 'આંશિક', 'paid': 'ચૂકવ્યું',
      'no_invoices': 'કોઈ બિલ નથી', 'invoices_auto': 'બિલ ઓર્ડર સાથે બનાવાય છે',
      'record_payment': 'ભુગતાન નોંધો', 'payment_amount': 'ભુગતાન રકમ',
      'payment_recorded': 'ભુગતાન નોંધ્યું', 'share_bill': 'બિલ શેર કરો',
      'pay': 'ભુગતાન', 'share': 'શેર',
      // Settings
      'boutique_info': 'બુટિક માહિતી', 'boutique_name': 'બુટિક નામ',
      'language': 'ભાષા', 'select_language': 'ભાષા પસંદ કરો',
      'support': 'સહાય', 'contact_support': 'સંપર્ક અને સહાય',
      'whatsapp_support': 'WhatsApp સહાય', 'email_us': 'ઇમેઇલ કરો',
      'report_bug': 'બગ રિપોર્ટ', 'about': 'વિશે', 'version': 'આવૃત્તિ',
      'sign_out': 'લોગ આઉટ', 'sign_out_confirm': 'શું તમે ખાતરી છો?',
      'cancel': 'રદ', 'crafted': 'શ્રેષ્ઠ દર્જીઓ માટે બનાવેલ',
      // Auth
      'welcome_back': 'પાછા આવો', 'create_account': 'ખાતું બનાવો',
      'sign_in_subtitle': 'તમારી બુટિક સંચાલિત કરવા સાઇન ઇન કરો',
      'register_subtitle': 'ગણતરીની ક્ષણોમાં સેટ અપ કરો',
      'sign_in': 'સાઇન ઇન', 'register': 'નોંધણી',
      'no_account': 'ખાતું નથી?', 'have_account': 'પહેલેથી ખાતું છે?',
      'password': 'પાસવર્ડ', 'min_chars': 'ઓછામાં ઓછા 6 અક્ષર', 'invalid_email': 'અમાન્ય ઇમેઇલ',
      'owner_name': 'માલિકનું નામ', 'shop_address': 'દુકાનનું સરનામું', 'shop_details': 'દુકાનની વિગત',
      'register_step2_subtitle': 'લગભગ થઈ ગયું! સંપર્ક માહિતી ઉમેરો',
      'invalid_phone': 'માન્ય ફોન નંબર દાખલ કરો',
      'optional': 'વૈકલ્પિક', 'back': 'પાછા', 'next': 'આગળ',
      // Status
      'received': 'મળ્યો', 'cutting': 'કટિંગ', 'stitching': 'સીવણ',
      'trial': 'ટ્રાયલ', 'ready': 'તૈયાર', 'delivered': 'ડિલિવર',
      // Misc
      'error': 'ભૂલ', 'retry': 'ફરી પ્રયાસ', 'connection_error': 'કનેક્શન ભૂલ',
      'server_waking': 'સર્વર ઊઠી રહ્યો છે. ખેંચો.',
      'notifications': 'સૂચનાઓ', 'search': 'શોધો',
    },

    // ─── MARATHI ───────────────────────────────────────────────────────────────
    'mr': {
      // Nav
      'dashboard': 'डॅशबोर्ड', 'customers': 'ग्राहक', 'orders': 'ऑर्डर',
      'invoices': 'बिल', 'settings': 'सेटिंग्स',
      // Dashboard
      'overview': 'आढावा', 'total_customers': 'ग्राहक', 'total_orders': 'एकूण ऑर्डर',
      'revenue': 'उत्पन्न', 'pending': 'बाकी', 'pending_orders': 'प्रलंबित ऑर्डर',
      'require_attention': 'लक्ष आवश्यक आहे', 'recent_orders': 'अलीकडील ऑर्डर',
      'no_orders_yet': 'अजून कोणतेही ऑर्डर नाही', 'quick_actions': 'त्वरित कृती',
      'new_customer': 'नवीन ग्राहक', 'new_order': 'नवीन ऑर्डर',
      // Customers
      'search_customers': 'नाव किंवा फोनने शोधा...', 'add_customer': 'ग्राहक जोडा',
      'edit_customer': 'ग्राहक संपादित करा', 'no_customers': 'कोणताही ग्राहक नाही',
      'add_first_customer': 'सुरू करण्यासाठी पहिला ग्राहक जोडा',
      'name': 'नाव', 'phone': 'फोन', 'email': 'इमेल', 'address': 'पत्ता',
      'city': 'शहर', 'gender': 'लिंग', 'male': 'पुरुष', 'female': 'स्त्री',
      'notes': 'नोट्स', 'notification_pref': 'सूचना प्राधान्य',
      'measurements': 'माप', 'top_measurements': 'वरील', 'bottom_measurements': 'खालील',
      'add_custom_field': '+ कस्टम फील्ड जोडा', 'custom_field_name': 'फील्ड नाव',
      'save_changes': 'बदल जतन करा', 'customer_added': 'ग्राहक जोडला',
      'customer_updated': 'ग्राहक अपडेट केला', 'required': 'आवश्यक',
      // Orders
      'all': 'सर्व', 'create_order': 'ऑर्डर तयार करा', 'no_orders': 'कोणतेही ऑर्डर नाही',
      'create_first_order': 'पहिला ऑर्डर तयार करा', 'customer': 'ग्राहक',
      'select_customer': 'ग्राहक निवडा', 'order_items': 'ऑर्डर आयटम',
      'add_item': '+ आयटम जोडा', 'garment': 'पोशाख', 'fabric': 'कापड',
      'qty': 'प्रमाण', 'price': 'किंमत', 'subtotal': 'उप-एकूण',
      'advance_paid': 'आगाऊ रक्कम', 'balance_due': 'बाकी रक्कम',
      'priority': 'प्राधान्य', 'delivery_date': 'वितरण तारीख', 'trial_date': 'ट्रायल तारीख',
      'select_date': 'तारीख निवडा', 'order_created': 'ऑर्डर तयार झाला',
      'update_status': 'स्थिती अपडेट करा', 'status_updated': 'स्थिती अपडेट झाली',
      'add_customers_first': 'आधी ग्राहक जोडा',
      'total': 'एकूण', 'advance': 'आगाऊ', 'balance': 'बाकी', 'due': 'बाकी',
      // Invoices
      'unpaid': 'न दिलेले', 'partial': 'आंशिक', 'paid': 'दिलेले',
      'no_invoices': 'कोणतेही बिल नाही', 'invoices_auto': 'बिले ऑर्डरसह तयार होतात',
      'record_payment': 'देयक नोंदवा', 'payment_amount': 'देयक रक्कम',
      'payment_recorded': 'देयक नोंदवले', 'share_bill': 'बिल शेअर करा',
      'pay': 'पैसे द्या', 'share': 'शेअर',
      // Settings
      'boutique_info': 'बुटीक माहिती', 'boutique_name': 'बुटीकचे नाव',
      'language': 'भाषा', 'select_language': 'भाषा निवडा',
      'support': 'सहाय्य', 'contact_support': 'संपर्क आणि सहाय्य',
      'whatsapp_support': 'WhatsApp सहाय्य', 'email_us': 'ईमेल करा',
      'report_bug': 'बग नोंदवा', 'about': 'माहिती', 'version': 'आवृत्ती',
      'sign_out': 'लॉग आउट', 'sign_out_confirm': 'तुम्हाला खात्री आहे का?',
      'cancel': 'रद्द', 'crafted': 'उत्कृष्ट शिंप्यांसाठी तयार',
      // Auth
      'welcome_back': 'पुन्हा स्वागत आहे', 'create_account': 'खाते तयार करा',
      'sign_in_subtitle': 'तुमची बुटीक व्यवस्थापित करण्यासाठी साइन इन करा',
      'register_subtitle': 'काही सेकंदात सेट अप करा',
      'sign_in': 'साइन इन', 'register': 'नोंदणी',
      'no_account': 'खाते नाही?', 'have_account': 'आधीच खाते आहे?',
      'password': 'पासवर्ड', 'min_chars': 'किमान 6 अक्षरे', 'invalid_email': 'अवैध ईमेल',
      'owner_name': 'मालकाचे नाव', 'shop_address': 'दुकानाचा पत्ता', 'shop_details': 'दुकानाचे तपशील',
      'register_step2_subtitle': 'जवळपास झाले! तुमची संपर्क माहिती जोडा',
      'invalid_phone': 'वैध फोन नंबर टाका',
      'optional': 'पर्यायी', 'back': 'मागे', 'next': 'पुढे',
      // Status
      'received': 'प्राप्त', 'cutting': 'कटिंग', 'stitching': 'शिवणकाम',
      'trial': 'ट्रायल', 'ready': 'तयार', 'delivered': 'वितरित',
      // Misc
      'error': 'त्रुटी', 'retry': 'पुन्हा प्रयत्न', 'connection_error': 'कनेक्शन त्रुटी',
      'server_waking': 'सर्वर सुरू होत आहे. खाली ओढा.',
      'notifications': 'सूचना', 'search': 'शोधा',
    },
  };
}
