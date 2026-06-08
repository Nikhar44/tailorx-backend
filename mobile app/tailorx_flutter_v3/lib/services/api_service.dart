import 'dart:convert';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';
import '../models/models.dart';

class Api {
  static final Api _i = Api._();
  factory Api() => _i;
  Api._();

  static const bool _isProduction = true;

  static const String _baseUrl = _isProduction
    ? 'https://tailorx-backend.onrender.com'
    : 'http://192.168.1.210:3000';

  String? _token;
  Map<String, dynamic>? _boutique;

  String? get token => _token;
  String? get boutiqueName    => _boutique?['name'] ?? 'My Boutique';
  String? get boutiqueEmail   => _boutique?['email'];
  String? get boutiqueAddress => _boutique?['address'];
  String? get boutiquePhone   => _boutique?['phone'];
  String? get boutiqueGST     => _boutique?['gstin'] ?? _boutique?['gst'];
  String? get boutiqueLogo    => _boutique?['logo_url'];

  // Terms & Conditions — stored locally per device
  String _termsAndConditions = '';
  String get termsAndConditions => _termsAndConditions;
  Future<void> setTermsAndConditions(String v) async {
    _termsAndConditions = v;
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('terms_and_conditions', v);
  }
  Future<void> loadTermsAndConditions() async {
    final prefs = await SharedPreferences.getInstance();
    _termsAndConditions = prefs.getString('terms_and_conditions') ?? '';
  }
  bool get isLoggedIn => _token != null;
  bool get isFree => _boutique?['is_free'] == true;
  String? get boutiquePlan => _boutique?['plan'];

  // Pro plan = free account OR active trial OR plan contains 'pro'
  bool get isProPlan =>
    isFree ||
    isTrialActive ||
    (boutiquePlan?.toLowerCase().contains('pro') == true);

  // Returns how many days are left in the 15-day trial (0 if expired)
  int get trialDaysRemaining {
    final createdAt = _boutique?['created_at'];
    if (createdAt == null) return 15;
    try {
      final created = DateTime.parse(createdAt.toString());
      final expiry = created.add(const Duration(days: 15));
      final remaining = expiry.difference(DateTime.now()).inDays;
      return remaining < 0 ? 0 : remaining;
    } catch (_) { return 0; }
  }

  bool get isTrialActive => trialDaysRemaining > 0;

  // ─── HTTP HELPER ────────────────────────────────────────────────
  Future<dynamic> _call(String endpoint, {String method = 'GET', Map<String, dynamic>? body}) async {
    final uri = Uri.parse('$_baseUrl$endpoint');
    final headers = {'Content-Type': 'application/json'};
    if (_token != null) headers['Authorization'] = 'Bearer $_token';

    http.Response res;
    try {
      if (method == 'POST') {
        res = await http.post(uri, headers: headers, body: body != null ? jsonEncode(body) : null);
      } else if (method == 'PUT') {
        res = await http.put(uri, headers: headers, body: body != null ? jsonEncode(body) : null);
      } else if (method == 'DELETE') {
        res = await http.delete(uri, headers: headers);
      } else {
        res = await http.get(uri, headers: headers);
      }
    } catch (e) {
      throw Exception('Connection error. Is your server running?');
    }

    dynamic data;
    try {
      data = jsonDecode(res.body);
    } catch (_) {
      throw Exception('Server error (${res.statusCode}). Please try again.');
    }
    if (res.statusCode == 401) {
      _token = null;
      _boutique = null;
      final prefs = await SharedPreferences.getInstance();
      await prefs.clear();
      throw Exception('Session expired. Please login again.');
    }
    if (res.statusCode >= 400) {
      throw Exception(data['error'] ?? 'Request failed');
    }
    return data;
  }

  // ─── WARM UP (wake Render from sleep) ───────────────────────────
  Future<bool> warmUp({int maxAttempts = 8}) async {
    for (int i = 0; i < maxAttempts; i++) {
      try {
        final uri = Uri.parse('$_baseUrl/health');
        final res = await http.get(uri).timeout(const Duration(seconds: 8));
        if (res.statusCode == 200) return true;
      } catch (_) {
        if (i < maxAttempts - 1) await Future.delayed(const Duration(seconds: 3));
      }
    }
    return false; // server unreachable after all attempts
  }

  // ─── INIT ───────────────────────────────────────────────────────
  Future<bool> init() async {
    try {
      final prefs = await SharedPreferences.getInstance();
      _token = prefs.getString('tx_token');
      final bStr = prefs.getString('tx_boutique');
      if (bStr != null) _boutique = jsonDecode(bStr);
      await loadTermsAndConditions();
    } catch (e) {
      print('Storage Init Error: $e');
    }
    return isLoggedIn;
  }

  // ─── LICENSE ────────────────────────────────────────────────────
  Future<Map<String, dynamic>> verifyLicense(String key) async {
    final data = await _call('/api/license/verify', method: 'POST', body: {'license_key': key});
    return data;
  }

  // ─── AUTH ───────────────────────────────────────────────────────
  Future<Map<String, dynamic>> login(String email, String pass) async {
    try {
      final data = await _call('/api/auth/login', method: 'POST', body: {'email': email, 'password': pass});
      _token = data['token'];
      _boutique = data['boutique'];
      
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('tx_token', _token!);
      await prefs.setString('tx_boutique', jsonEncode(_boutique));
      
      return {'success': true, 'boutique': _boutique?['name']};
    } catch (e) {
      return {'success': false, 'message': e.toString()};
    }
  }

  // ─── OTP: Send ──────────────────────────────────────────────────
  Future<Map<String, dynamic>> sendOtp(String name, String email, String pass, {
    String? ownerName, String? phone, String? city, String? address,
  }) async {
    try {
      await _call('/api/auth/send-otp', method: 'POST', body: {
        'name': name, 'email': email, 'password': pass,
        if (ownerName != null && ownerName.isNotEmpty) 'ownerName': ownerName,
        if (phone != null && phone.isNotEmpty) 'phone': phone,
        if (city != null && city.isNotEmpty) 'city': city,
        if (address != null && address.isNotEmpty) 'address': address,
      });
      return {'success': true};
    } catch (e) {
      return {'success': false, 'message': e.toString()};
    }
  }

  // ─── OTP: Verify ────────────────────────────────────────────────
  Future<Map<String, dynamic>> verifyOtp(String email, String otp) async {
    try {
      final data = await _call('/api/auth/verify-otp', method: 'POST',
          body: {'email': email, 'otp': otp});
      _token    = data['token'];
      _boutique = data['boutique'];
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('tx_token',    _token!);
      await prefs.setString('tx_boutique', jsonEncode(_boutique));
      return {'success': true};
    } catch (e) {
      return {'success': false, 'message': e.toString()};
    }
  }

  Future<Map<String, dynamic>> register(String name, String email, String pass, {
    String? ownerName, String? phone, String? city, String? address,
  }) async {
    try {
      final data = await _call('/api/auth/register', method: 'POST', body: {
        'name': name,
        'email': email,
        'password': pass,
        if (ownerName != null && ownerName.isNotEmpty) 'ownerName': ownerName,
        if (phone != null && phone.isNotEmpty) 'phone': phone,
        if (city != null && city.isNotEmpty) 'city': city,
        if (address != null && address.isNotEmpty) 'address': address,
      });
      _token = data['token'];
      _boutique = data['boutique'];
      
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('tx_token', _token!);
      await prefs.setString('tx_boutique', jsonEncode(_boutique));
      
      return {'success': true};
    } catch (e) {
      return {'success': false, 'message': e.toString()};
    }
  }

  Future<Map<String, dynamic>> socialLogin({
    required String provider,
    required String idToken,
    String? name,
    String? email,
  }) async {
    try {
      final data = await _call('/api/auth/social', method: 'POST', body: {
        'provider': provider,
        'idToken':  idToken,
        if (name  != null) 'name':  name,
        if (email != null) 'email': email,
      });
      _token    = data['token'];
      _boutique = data['boutique'];
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('tx_token',    _token!);
      await prefs.setString('tx_boutique', jsonEncode(_boutique));
      return {'success': true, 'isNewUser': data['isNewUser'] ?? false};
    } catch (e) {
      return {'success': false, 'message': e.toString()};
    }
  }

  Future<void> resetPassword(String email) async {
    await _call('/api/auth/forgot-password', method: 'POST', body: {'email': email});
  }

  Future<void> updateBoutiqueProfile({String? name, String? ownerName, String? phone, String? city, String? address, String? gst, String? logoUrl}) async {
    // Send full profile so the server doesn't null-out fields we didn't change
    final Map<String, dynamic> body = {
      'name':      name      ?? _boutique?['name']       ?? '',
      'ownerName': ownerName ?? _boutique?['owner_name'] ?? '',
      'phone':     phone     ?? _boutique?['phone']      ?? '',
      'city':      city      ?? _boutique?['city']       ?? '',
      'address':   address   ?? _boutique?['address']    ?? '',
      'gstin':     gst       ?? _boutique?['gstin']      ?? '',
      'logo_url':  logoUrl   ?? _boutique?['logo_url'],
    };

    final data = await _call('/api/auth/me', method: 'PUT', body: body);
    // Server returns the boutique row directly (not wrapped in {'boutique': ...})
    _boutique = data is Map<String, dynamic> ? data : data['boutique'];
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('tx_boutique', jsonEncode(_boutique));
  }

  // Refresh boutique profile from server and update local cache
  Future<void> refreshProfile() async {
    try {
      final data = await _call('/api/auth/me');
      if (data is Map<String, dynamic>) {
        _boutique = data;
        final prefs = await SharedPreferences.getInstance();
        await prefs.setString('tx_boutique', jsonEncode(_boutique));
      }
    } catch (e) {
      // Silently fail — keep cached data
      print('Profile refresh error: $e');
    }
  }

  Future<void> logout() async {
    _token = null;
    _boutique = null;
    final prefs = await SharedPreferences.getInstance();
    await prefs.clear();
  }

  // ─── ADMIN ──────────────────────────────────────────────────────
  Future<List<Map<String, dynamic>>> adminGetBoutiques(String secret) async {
    final uri = Uri.parse('$_baseUrl/api/admin/boutiques');
    final res = await http.get(uri, headers: {'x-admin-secret': secret});
    if (res.statusCode == 403) throw Exception('Invalid admin secret');
    if (res.statusCode != 200) throw Exception('Failed to load boutiques');
    final data = jsonDecode(res.body) as List;
    return data.cast<Map<String, dynamic>>();
  }

  Future<void> adminToggleHold(String secret, int boutiqueId, bool isActive) async {
    final uri = Uri.parse('$_baseUrl/api/admin/boutiques/$boutiqueId/hold');
    final res = await http.patch(uri,
        headers: {'x-admin-secret': secret, 'Content-Type': 'application/json'},
        body: jsonEncode({'is_active': isActive}));
    if (res.statusCode == 403) throw Exception('Invalid admin secret');
    if (res.statusCode != 200) throw Exception('Failed to update account status');
  }

  // ─── DASHBOARD ──────────────────────────────────────────────────
  Future<DashboardData> getDashboard() async {
    try {
      // Fetch dashboard stats, invoices, and all orders in parallel
      final results = await Future.wait([
        _call('/api/dashboard'),
        _call('/api/invoices').catchError((_) => []),
        _call('/api/orders').catchError((_) => []),
      ]);

      final data = results[0] as Map<String, dynamic>;
      final stats = data['stats'] ?? {};
      final recentOrdersList = data['recentOrders'] as List? ?? [];
      final recentOrders = recentOrdersList.map((e) => Order.fromJson(e)).toList();

      // Calculate revenue/pending locally from invoices so stale DB values
      // (total_amount=0, due_amount not updated) don't corrupt the dashboard.
      final invList = (results[1] as List).map((e) => Invoice.fromJson(e as Map<String, dynamic>)).toList();
      double totalRevenue = 0;
      double pendingPayments = 0;
      for (final inv in invList) {
        // effective total: prefer totalAmount, fall back to advance+dueAmount for old data
        final effective = inv.totalAmount > 0 ? inv.totalAmount : (inv.advance + inv.dueAmount);
        totalRevenue += effective;
        if (inv.status != 'paid') pendingPayments += inv.dueAmount;
      }

      // Calculate active orders locally — case-insensitive, excludes Delivered/Dispensed only
      // Received → Cutting → Stitching → Trial → Ready are all "active"
      final allOrders = (results[2] as List).map((e) => Order.fromJson(e as Map<String, dynamic>)).toList();
      final activeOrders = allOrders.where((o) {
        final s = o.stage.toLowerCase();
        return s != 'delivered' && s != 'dispensed';
      }).length;

      return DashboardData(
        totalCustomers: stats['totalCustomers'] ?? 0,
        totalOrders: stats['totalOrders'] ?? 0,
        pendingOrders: activeOrders,
        totalRevenue: totalRevenue,
        pendingPayments: pendingPayments,
        recentOrders: recentOrders,
      );
    } catch (e) {
      print('Dashboard Error: $e');
      return DashboardData(recentOrders: []);
    }
  }

  // ─── CUSTOMERS ──────────────────────────────────────────────────
  Future<List<Customer>> getCustomers({String? search}) async {
    try {
      final data = await _call('/api/customers');
      var list = (data as List).map((e) => Customer.fromJson(e)).toList();
      if (search != null && search.isNotEmpty) {
        final q = search.toLowerCase();
        list = list.where((c) => c.name.toLowerCase().contains(q) || (c.phone).contains(q)).toList();
      }
      return list;
    } catch (e) {
      print('Customers Fetch Error: $e');
      return [];
    }
  }

  Future<Customer> createCustomer(Customer c) async {
    final json = c.toJson();
    json.remove('id');
    json.remove('boutique_id');
    print('🔵 SENDING CUSTOMER: $json');
    final data = await _call('/api/customers', method: 'POST', body: json);
    print('🟢 CUSTOMER RETURNED: $data');
    return Customer.fromJson(data as Map<String, dynamic>);
  }

  Future<Customer> updateCustomer(dynamic id, Customer c) async {
    final json = c.toJson();
    json.remove('id');
    json.remove('boutique_id');
    final data = await _call('/api/customers/$id', method: 'PUT', body: json);
    return Customer.fromJson(data);
  }

  Future<void> deleteCustomer(dynamic id) async {
    await _call('/api/customers/$id', method: 'DELETE');
  }

  // ─── ORDERS ─────────────────────────────────────────────────────
  Future<List<Order>> getOrders({String? status, String? search}) async {
    try {
      final data = await _call('/api/orders');
      var list = (data as List).map((e) => Order.fromJson(e)).toList();
      if (status != null && status.isNotEmpty) {
        list = list.where((o) => o.stage == status).toList();
      }
      if (search != null && search.isNotEmpty) {
        final q = search.toLowerCase();
        list = list.where((o) => (o.customerName ?? '').toLowerCase().contains(q) || (o.garment ?? '').toLowerCase().contains(q)).toList();
      }
      return list;
    } catch (e) {
      print('Orders Fetch Error: $e');
      return [];
    }
  }

  Future<Order> createOrder(Order o) async {
    final json = o.toJson();
    json.remove('id');
    json.remove('boutique_id');
    print('🔵 SENDING ORDER: $json');
    final data = await _call('/api/orders', method: 'POST', body: json);
    print('🟢 SERVER RETURNED: $data');
    return Order.fromJson(data);
  }

  Future<Order> updateOrder(dynamic id, {String? garment, String? fabric, double? amount, double? advance, String? dueDate, String? notes}) async {
    final body = <String, dynamic>{};
    if (garment != null) body['garment'] = garment;
    if (fabric != null) body['fabric'] = fabric;
    if (amount != null) { body['amount'] = amount; body['total_amount'] = amount; }
    if (advance != null) { body['advance'] = advance; body['advance_paid'] = advance; }
    if (amount != null || advance != null) {
      final a = amount ?? 0; final adv = advance ?? 0;
      final bal = (a - adv).clamp(0.0, double.infinity);
      body['balance'] = bal; body['balance_due'] = bal;
    }
    if (dueDate != null) body['due_date'] = dueDate;
    if (notes != null) body['notes'] = notes;
    final data = await _call('/api/orders/$id', method: 'PUT', body: body);
    return Order.fromJson(data);
  }

  Future<void> deleteOrder(dynamic id) async {
    await _call('/api/orders/$id', method: 'DELETE');
  }

  Future<Order> updateOrderStatus(dynamic id, String stage, {double amount = 0, double advance = 0}) async {
    final bal = (amount - advance).clamp(0, double.infinity);
    final data = await _call('/api/orders/$id', method: 'PUT', body: {
      'stage': stage,
      'status': stage,             // old server compat
      'amount': amount,
      'total_amount': amount,      // old server compat
      'advance': advance,
      'advance_paid': advance,     // old server compat
      'balance': bal,
      'balance_due': bal,          // old server compat
    });
    return Order.fromJson(data);
  }

  // ─── INVOICES ───────────────────────────────────────────────────
  Future<List<Invoice>> getInvoices({String? status}) async {
    try {
      final data = await _call('/api/invoices');
      var list = (data as List).map((e) => Invoice.fromJson(e)).toList();
      if (status != null && status.isNotEmpty) {
        list = list.where((i) => i.status == status).toList();
      }
      return list;
    } catch (e) {
      print('Invoices Fetch Error: $e');
      return [];
    }
  }

  Future<Invoice> createInvoice(Invoice inv) async {
    final json = inv.toJson();
    json.remove('id');
    json.remove('boutique_id');
    print('🔵 SENDING INVOICE: $json');
    final data = await _call('/api/invoices', method: 'POST', body: json);
    print('🟢 INVOICE RETURNED: $data');
    return Invoice.fromJson(data);
  }

  Future<Invoice> updateInvoicePayment(dynamic id, Invoice inv, double newAdvance) async {
    final newDue = (inv.totalAmount - newAdvance).clamp(0.0, double.infinity);
    final newStatus = newDue <= 0 ? 'paid' : (newAdvance > 0 ? 'partial' : 'unpaid');
    print('🔵 UPDATING INVOICE PAYMENT: advance=$newAdvance due=$newDue status=$newStatus');
    final data = await _call('/api/invoices/$id', method: 'PUT', body: {
      'advance': newAdvance,
      'advance_paid': newAdvance,   // old server compat
      'due_amount': newDue,
      'balance_due': newDue,        // old server compat
      'status': newStatus,
      // Include full invoice data so old server doesn't zero out other fields
      'subtotal': inv.subtotal,
      'amount': inv.subtotal,       // old server compat
      'total_amount': inv.totalAmount,
      'discount_pct': inv.discountPct,
      'discount_amt': inv.discountAmt,
      'tax': inv.discountAmt,       // old server compat
    });
    print('🟢 INVOICE PAYMENT RETURNED: $data');
    return Invoice.fromJson(data);
  }

  // ─── NOTIFICATIONS ─────────────────────────────────────────────
  Future<List<Map<String, dynamic>>> getNotifications() async {
    try {
      final data = await _call('/api/notifications');
      return (data as List).map((e) => e as Map<String, dynamic>).toList();
    } catch (e) {
      return [];
    }
  }
}
