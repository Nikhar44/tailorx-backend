import 'dart:convert';
import 'package:flutter/material.dart';

double _n(dynamic v) {
  if (v == null) return 0;
  if (v is num) return v.toDouble();
  if (v is String) return double.tryParse(v) ?? 0;
  return 0;
}

int _i(dynamic v) {
  if (v == null) return 0;
  if (v is int) return v;
  if (v is num) return v.toInt();
  if (v is String) return int.tryParse(v) ?? 0;
  return 0;
}

class Customer {
  final String? id;
  final String? boutiqueId;
  final String name;
  final String phone;
  final String? email;
  final String? city;
  final String? address;
  final String? dob;
  final String? gender;
  final String? notify;
  final String? notes;
  final Map<String, dynamic>? measurementsTop;
  final Map<String, dynamic>? measurementsBottom;
  final String? createdAt;

  Customer({
    this.id, this.boutiqueId, required this.name, required this.phone,
    this.email, this.city, this.address, this.dob, this.gender, this.notify, this.notes,
    this.measurementsTop, this.measurementsBottom, this.createdAt,
  });

  String get initials => name.trim().split(' ').where((e) => e.isNotEmpty).take(2)
      .map((e) => e[0].toUpperCase()).join();

  Map<String, dynamic> get allMeasurements {
    final m = <String, dynamic>{};
    if (measurementsTop != null) m.addAll(measurementsTop!);
    if (measurementsBottom != null) m.addAll(measurementsBottom!);
    return m;
  }

  String? get preferredNotification => notify;

  factory Customer.fromJson(Map<String, dynamic> j) {
    Map<String, dynamic>? _parseM(dynamic v) {
      if (v == null) return null;
      if (v is String && v.isNotEmpty) {
        try { return Map<String, dynamic>.from(jsonDecode(v)); } catch (_) {}
      }
      if (v is Map) return Map<String, dynamic>.from(v);
      return null;
    }
    return Customer(
      id: j['id']?.toString(),
      boutiqueId: j['boutique_id']?.toString(),
      name: j['name'] ?? '',
      phone: j['phone'] ?? '',
      email: j['email'],
      city: j['city'],
      address: j['address'],
      dob: j['dob'],
      gender: j['gender'],
      notify: j['notify'],
      notes: j['notes'],
      measurementsTop: _parseM(j['measurements_top']),
      measurementsBottom: _parseM(j['measurements_bottom']),
      createdAt: j['created_at'],
    );
  }

  Map<String, dynamic> toJson() {
    final m = <String, dynamic>{
      'name': name,
      'phone': phone,
    };
    if (email?.isNotEmpty == true) m['email'] = email;
    if (city?.isNotEmpty == true) m['city'] = city;
    if (address?.isNotEmpty == true) m['address'] = address;
    if (dob?.isNotEmpty == true) m['dob'] = dob;
    if (gender?.isNotEmpty == true) m['gender'] = gender;
    if (notify?.isNotEmpty == true) m['notify'] = notify;
    if (notes?.isNotEmpty == true) m['notes'] = notes;
    if (measurementsTop != null) m['measurements_top'] = measurementsTop;
    if (measurementsBottom != null) m['measurements_bottom'] = measurementsBottom;
    return m;
  }
}

class Order {
  final String? id;
  final String? boutiqueId;
  final String? customerId;
  final String? customerName;
  final String? customerPhone;
  final String? city;
  final String? address;
  final String? garment;
  final String? fabric;
  final String? dueDate;
  final double amount;
  final double advance;
  final double balance;
  final String stage;
  final bool notify;
  final String? notes;
  final String? clothPhotoUrl;
  final String? designPhotoUrl;
  final String? createdAt;
  final String? updatedAt;

  Order({
    this.id, this.boutiqueId, this.customerId, this.customerName,
    this.customerPhone, this.city, this.address,
    this.garment, this.fabric, this.dueDate,
    this.amount = 0, this.advance = 0, this.balance = 0,
    this.stage = 'Received', this.notify = true, this.notes,
    this.clothPhotoUrl, this.designPhotoUrl,
    this.createdAt, this.updatedAt,
  });

  String get description => garment ?? '';
  String get status => stage;
  double get totalAmount => amount;
  double get advanceAmount => advance;
  double get balanceAmount => balance > 0 ? balance : (amount - advance);

  factory Order.fromJson(Map<String, dynamic> j) => Order(
    id: j['id']?.toString(),
    boutiqueId: j['boutique_id']?.toString(),
    customerId: j['customer_id']?.toString(),
    customerName: j['customer_name'],
    customerPhone: j['customer_phone'],
    city: j['customer_city'] ?? j['city'],
    address: j['customer_address'] ?? j['address'],
    garment: j['garment'],
    fabric: j['fabric'],
    dueDate: j['due_date'] ?? j['delivery_date'],
    amount: _n(j['amount'] ?? j['total_amount']),
    advance: _n(j['advance'] ?? j['advance_paid']),
    balance: _n(j['balance'] ?? j['balance_due']),
    stage: j['stage'] ?? j['status'] ?? 'Received',
    notify: j['notify'] != false,
    notes: j['notes'],
    clothPhotoUrl: j['cloth_photo_url'],
    designPhotoUrl: j['design_photo_url'],
    createdAt: j['created_at'],
    updatedAt: j['updated_at'],
  );

  Map<String, dynamic> toJson() {
    final m = <String, dynamic>{
      'customer_id': customerId,
      'customer_name': customerName ?? '',
      'garment': garment ?? '',
      'fabric': fabric ?? '',
      'amount': amount,
      'total_amount': amount,      // old server compat
      'advance': advance,
      'advance_paid': advance,     // old server compat
      'balance': amount - advance,
      'balance_due': amount - advance, // old server compat
      'stage': stage,
      'status': stage,             // old server compat
      'notify': notify,
    };
    if (dueDate != null) m['due_date'] = dueDate;
    if (notes?.isNotEmpty == true) m['notes'] = notes;
    if (clothPhotoUrl != null) m['cloth_photo_url'] = clothPhotoUrl;
    if (designPhotoUrl != null) m['design_photo_url'] = designPhotoUrl;
    return m;
  }
}

class Invoice {
  final String? id;
  final String? boutiqueId;
  final String? orderId;
  final String? customerId;
  final String? customerName;
  final String? customerPhone;
  final String? customerCity;
  final String? customerAddress;
  final String? garment;
  final String? billDate;
  final String? trialDate;
  final String? deliveryDate;
  final double subtotal;
  final double discountPct;
  final double discountAmt;
  final double advance;
  final double dueAmount;
  final bool gstEnabled;
  final double gstPct;
  final double gstAmt;
  final String? remarks;
  final String status;
  final String? createdAt;

  Invoice({
    this.id, this.boutiqueId, this.orderId, this.customerId,
    this.customerName, this.customerPhone, this.customerCity,
    this.customerAddress, this.garment, this.billDate,
    this.trialDate, this.deliveryDate,
    this.subtotal = 0, this.discountPct = 0, this.discountAmt = 0,
    this.advance = 0, this.dueAmount = 0,
    this.gstEnabled = false, this.gstPct = 0, this.gstAmt = 0,
    this.remarks,
    this.status = 'unpaid', this.createdAt,
  });

  double get totalAmount => subtotal - discountAmt + gstAmt;
  double get paidAmount => advance;
  double get balanceAmount => dueAmount;
  double get progress => totalAmount > 0 ? (advance / totalAmount).clamp(0.0, 1.0) : 0.0;

  factory Invoice.fromJson(Map<String, dynamic> j) => Invoice(
    id: j['id']?.toString(),
    boutiqueId: j['boutique_id']?.toString(),
    orderId: j['order_id']?.toString(),
    customerId: j['customer_id']?.toString(),
    customerName: j['customer_name'],
    customerPhone: j['customer_phone'],
    customerCity: j['customer_city'],
    customerAddress: j['customer_address'],
    garment: j['garment'],
    billDate: j['bill_date'],
    trialDate: j['trial_date'],
    deliveryDate: j['delivery_date'] ?? j['due_date'],
    subtotal: _n(j['subtotal'] ?? j['amount']),
    discountPct: _n(j['discount_pct']),
    discountAmt: _n(j['discount_amt'] ?? j['tax']),
    advance: _n(j['advance'] ?? j['advance_paid']),
    dueAmount: _n(j['due_amount'] ?? j['balance_due']),
    gstEnabled: j['gst_enabled'] == true,
    gstPct: _n(j['gst_pct']),
    gstAmt: _n(j['gst_amt']),
    remarks: j['remarks'],
    status: j['status'] ?? 'unpaid',
    createdAt: j['created_at'],
  );

  Map<String, dynamic> toJson() {
    final m = <String, dynamic>{
      'order_id': orderId,
      'customer_id': customerId,
      'customer_name': customerName,
      'customer_phone': customerPhone,
      'garment': garment,
      'subtotal': subtotal,
      'amount': subtotal,           // old server compat
      'discount_pct': discountPct,
      'discount_amt': discountAmt,
      'tax': discountAmt,           // old server compat
      'total_amount': totalAmount,
      'advance': advance,
      'advance_paid': advance,      // old server compat
      'due_amount': dueAmount,
      'balance_due': dueAmount,     // old server compat
      'gst_enabled': gstEnabled,
      'gst_pct': gstPct,
      'gst_amt': gstAmt,
      'status': status,
    };
    if (remarks?.isNotEmpty == true) m['remarks'] = remarks;
    if (trialDate?.isNotEmpty == true) m['trial_date'] = trialDate;
    if (deliveryDate?.isNotEmpty == true) m['delivery_date'] = deliveryDate;
    return m;
  }
}

class TodayTask {
  final String id;
  final String type; // 'Trial' | 'Delivery' | 'Payment'
  final String stage;
  final String title;
  final String sub;
  final String? customerName;
  final String? garment;
  final double balance;

  TodayTask({
    required this.id, required this.type, this.stage = '',
    required this.title, required this.sub,
    this.customerName, this.garment, this.balance = 0,
  });

  factory TodayTask.fromJson(Map<String, dynamic> j) => TodayTask(
    id: j['id']?.toString() ?? '',
    type: j['type'] ?? '',
    stage: j['stage'] ?? '',
    title: j['title'] ?? '',
    sub: j['sub'] ?? '',
    customerName: j['customer_name'],
    garment: j['garment'],
    balance: _n(j['balance']),
  );
}

class DashboardData {
  final int totalCustomers;
  final int totalOrders;
  final int pendingOrders;
  final double totalRevenue;
  final double pendingPayments;
  final List<Order> recentOrders;
  final List<TodayTask> todayTasks;

  DashboardData({
    this.totalCustomers = 0,
    this.totalOrders = 0,
    this.pendingOrders = 0,
    this.totalRevenue = 0,
    this.pendingPayments = 0,
    this.recentOrders = const [],
    this.todayTasks = const [],
  });

  factory DashboardData.fromJson(Map<String, dynamic> j) {
    final s = j['stats'] as Map<String, dynamic>? ?? j;
    final o = j['recentOrders'] ?? j['recent_orders'] ?? [];
    final t = j['todayTasks'] ?? j['today_tasks'] ?? [];
    return DashboardData(
      totalCustomers: _i(s['totalCustomers'] ?? s['total_customers']),
      totalOrders: _i(s['totalOrders'] ?? s['total_orders']),
      pendingOrders: _i(s['pendingOrders'] ?? s['pending_orders']),
      totalRevenue: _n(s['totalRevenue'] ?? s['total_revenue']),
      pendingPayments: _n(s['pendingPayments'] ?? s['pending_payments']),
      recentOrders: (o as List).map((e) => Order.fromJson(e)).toList(),
      todayTasks: (t as List).map((e) => TodayTask.fromJson(e)).toList(),
    );
  }
}

class AppNotification {
  final String id, title, body, type, time;
  final IconData icon;
  final Color color;
  final dynamic data;

  AppNotification({
    required this.id, required this.title, required this.body,
    required this.type, required this.time, required this.icon,
    required this.color, this.data
  });
}
