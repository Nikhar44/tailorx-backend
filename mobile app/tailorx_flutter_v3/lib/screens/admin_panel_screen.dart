import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import '../services/api_service.dart';
import '../utils/theme.dart';

// ─── Plan helpers ─────────────────────────────────────────────────────────────
String _planLabel(String? plan) {
  switch (plan) {
    case 'pro':         return 'PRO YEARLY';
    case 'pro_monthly': return 'PRO MONTHLY';
    case 'yearly':      return 'BASIC YEARLY';
    case 'monthly':     return 'BASIC MONTHLY';
    case 'free':        return 'FREE';
    case 'trial':       return 'TRIAL';
    default:            return (plan ?? 'UNKNOWN').toUpperCase();
  }
}

Color _planColor(String? plan) {
  switch (plan) {
    case 'pro':         return const Color(0xFF9B59B6);
    case 'pro_monthly': return const Color(0xFF8E44AD);
    case 'yearly':      return T.accent;
    case 'monthly':     return T.info;
    case 'free':        return T.success;
    case 'trial':       return T.warning;
    default:            return T.text3;
  }
}

// ─── Filter enum ─────────────────────────────────────────────────────────────
enum _Filter { all, trial, active, expiring, onHold }

String _filterLabel(_Filter f) {
  switch (f) {
    case _Filter.all:      return 'All';
    case _Filter.trial:    return 'Trial';
    case _Filter.active:   return 'Active';
    case _Filter.expiring: return 'Expiring';
    case _Filter.onHold:   return 'On Hold';
  }
}

// ─── Main screen ─────────────────────────────────────────────────────────────
class AdminPanelScreen extends StatefulWidget {
  final String adminSecret;
  const AdminPanelScreen({super.key, required this.adminSecret});

  @override
  State<AdminPanelScreen> createState() => _AdminPanelScreenState();
}

class _AdminPanelScreenState extends State<AdminPanelScreen> {
  final _api        = Api();
  final _searchCtrl = TextEditingController();

  List<Map<String, dynamic>> _boutiques = [];
  bool   _loading = true;
  String? _error;
  _Filter _filter  = _Filter.all;
  bool    _sortExpiry = false; // false = newest first, true = expiry soonest first

  @override
  void initState() {
    super.initState();
    _load();
    _searchCtrl.addListener(() => setState(() {}));
  }

  @override
  void dispose() {
    _searchCtrl.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final list = await _api.adminGetBoutiques(widget.adminSecret);
      if (mounted) setState(() { _boutiques = list; _loading = false; });
    } catch (e) {
      if (mounted) setState(() {
        _error = e.toString().replaceFirst('Exception: ', '');
        _loading = false;
      });
    }
  }

  List<Map<String, dynamic>> get _filtered {
    final q = _searchCtrl.text.trim().toLowerCase();
    var list = _boutiques.where((b) {
      // Search filter
      if (q.isNotEmpty) {
        final name  = (b['name']  ?? '').toLowerCase();
        final phone = (b['phone'] ?? '').toLowerCase();
        final email = (b['email'] ?? '').toLowerCase();
        final city  = (b['city']  ?? '').toLowerCase();
        if (!name.contains(q) && !phone.contains(q) &&
            !email.contains(q) && !city.contains(q)) return false;
      }
      // Status filter
      switch (_filter) {
        case _Filter.all:
          return true;
        case _Filter.trial:
          return (b['plan'] as String?) == 'trial';
        case _Filter.active:
          final exp = b['expires_at'] != null ? DateTime.tryParse(b['expires_at']) : null;
          final isFree = b['is_free'] as bool? ?? false;
          return (b['is_active'] != false) &&
              (isFree || (exp != null && exp.isAfter(DateTime.now()) &&
                  exp.difference(DateTime.now()).inDays > 7));
        case _Filter.expiring:
          final exp = b['expires_at'] != null ? DateTime.tryParse(b['expires_at']) : null;
          if (exp == null) return false;
          final days = exp.difference(DateTime.now()).inDays;
          return days >= 0 && days <= 7;
        case _Filter.onHold:
          return b['is_active'] == false;
      }
    }).toList();

    // Sort
    if (_sortExpiry) {
      list.sort((a, b) {
        final aExp = a['expires_at'] != null ? DateTime.tryParse(a['expires_at']) : null;
        final bExp = b['expires_at'] != null ? DateTime.tryParse(b['expires_at']) : null;
        if (aExp == null && bExp == null) return 0;
        if (aExp == null) return 1;
        if (bExp == null) return -1;
        return aExp.compareTo(bExp);
      });
    }

    return list;
  }

  void _showSnack(String msg, {bool error = false}) {
    if (!mounted) return;
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(msg),
      backgroundColor: error ? T.danger : T.success,
    ));
  }

  // ── Toggle Hold ──────────────────────────────────────────────────
  Future<void> _toggleHold(Map<String, dynamic> b) async {
    final isActive = b['is_active'] as bool? ?? true;
    final newState = !isActive;
    final name = b['name'] ?? 'this boutique';

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: T.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Text(newState ? 'Reactivate Account?' : 'Put On Hold?', style: T.heading),
        content: Text(
          newState
            ? 'Reactivate "$name"? They can log in again.'
            : 'Put "$name" on hold? They won\'t be able to log in.',
          style: T.body,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: newState ? T.success : T.danger),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(newState ? 'REACTIVATE' : 'HOLD'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await _api.adminToggleHold(widget.adminSecret, b['id'] as int, newState);
      await _load();
      _showSnack(newState ? '"$name" reactivated.' : '"$name" put on hold.');
    } catch (e) {
      _showSnack(e.toString().replaceFirst('Exception: ', ''), error: true);
    }
  }

  // ── Change Plan ──────────────────────────────────────────────────
  Future<void> _changePlan(Map<String, dynamic> b) async {
    final currentPlan = b['plan'] as String? ?? 'trial';
    final name = b['name'] ?? 'this boutique';

    final plans = [
      {'value': 'monthly',     'label': 'Basic Monthly', 'sub': '₹199/month'},
      {'value': 'yearly',      'label': 'Basic Yearly',  'sub': '₹1,999/year'},
      {'value': 'pro_monthly', 'label': 'Pro Monthly',   'sub': '₹399/month'},
      {'value': 'pro',         'label': 'Pro Yearly',    'sub': '₹3,999/year'},
      {'value': 'free',        'label': 'Free Forever',  'sub': 'No payment needed'},
    ];

    String? selected = currentPlan;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(builder: (ctx, setLocal) => AlertDialog(
        backgroundColor: T.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Change Plan', style: T.heading.copyWith(fontSize: 18)),
          Text(name, style: T.bodySm.copyWith(fontSize: 12, color: T.text3)),
        ]),
        contentPadding: const EdgeInsets.fromLTRB(8, 8, 8, 0),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: plans.map((p) => RadioListTile<String>(
            title: Text(p['label']!, style: T.body.copyWith(fontSize: 14, fontWeight: FontWeight.w600)),
            subtitle: Text(p['sub']!, style: T.bodySm.copyWith(fontSize: 11)),
            value: p['value']!,
            groupValue: selected,
            activeColor: T.accent,
            dense: true,
            onChanged: (v) => setLocal(() => selected = v),
          )).toList(),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: T.accent),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text('APPLY', style: TextStyle(color: T.headerDark, fontWeight: FontWeight.w800)),
          ),
        ],
      )),
    );
    if (confirmed != true || selected == null || selected == currentPlan) return;
    try {
      await _api.adminChangePlan(widget.adminSecret, b['id'] as int, selected!);
      await _load();
      _showSnack('"$name" → ${_planLabel(selected)}');
    } catch (e) {
      _showSnack(e.toString().replaceFirst('Exception: ', ''), error: true);
    }
  }

  // ── Renew ────────────────────────────────────────────────────────
  Future<void> _renew(Map<String, dynamic> b) async {
    final name = b['name'] ?? 'this boutique';
    int months = 1;
    double? amount;

    final monthsCtrl = TextEditingController(text: '1');
    final amountCtrl = TextEditingController();
    final notesCtrl  = TextEditingController();

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: T.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Renew Subscription', style: T.heading.copyWith(fontSize: 18)),
          Text(name, style: T.bodySm.copyWith(fontSize: 12, color: T.text3)),
        ]),
        content: Column(
          mainAxisSize: MainAxisSize.min,
          children: [
            TextField(
              controller: monthsCtrl,
              keyboardType: TextInputType.number,
              inputFormatters: [FilteringTextInputFormatter.digitsOnly],
              decoration: InputDecoration(
                labelText: 'Months *',
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                helperText: '1 = monthly plan  ·  12 = yearly plan',
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: amountCtrl,
              keyboardType: const TextInputType.numberWithOptions(decimal: true),
              decoration: InputDecoration(
                labelText: 'Amount received (₹)',
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                prefixText: '₹ ',
              ),
            ),
            const SizedBox(height: 12),
            TextField(
              controller: notesCtrl,
              decoration: InputDecoration(
                labelText: 'Notes (optional)',
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
                hintText: 'e.g. "UPI payment via GPay"',
              ),
            ),
          ],
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: T.accent),
            onPressed: () {
              months = int.tryParse(monthsCtrl.text.trim()) ?? 1;
              amount = double.tryParse(amountCtrl.text.trim());
              Navigator.pop(ctx, true);
            },
            child: Text('RENEW', style: TextStyle(color: T.headerDark, fontWeight: FontWeight.w800)),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await _api.adminRenew(widget.adminSecret, b['id'] as int, months, amount: amount);
      await _load();
      _showSnack('"$name" renewed for $months month(s).');
    } catch (e) {
      _showSnack(e.toString().replaceFirst('Exception: ', ''), error: true);
    }
  }

  // ── Toggle Free ──────────────────────────────────────────────────
  Future<void> _toggleFree(Map<String, dynamic> b) async {
    final isFree = b['is_free'] as bool? ?? false;
    final newFree = !isFree;
    final name = b['name'] ?? 'this boutique';

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: T.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Text(newFree ? 'Grant Free Access?' : 'Remove Free Access?', style: T.heading),
        content: Text(
          newFree
            ? 'Give "$name" permanent free access — no payment needed ever.'
            : 'Remove free access from "$name". They\'ll need a paid plan after trial.',
          style: T.body,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(
                backgroundColor: newFree ? T.success : T.danger),
            onPressed: () => Navigator.pop(ctx, true),
            child: Text(newFree ? 'GRANT FREE' : 'REMOVE FREE'),
          ),
        ],
      ),
    );
    if (confirmed != true) return;
    try {
      await _api.adminToggleFree(widget.adminSecret, b['id'] as int, newFree);
      await _load();
      _showSnack(newFree ? '"$name" given free access.' : 'Free access removed from "$name".');
    } catch (e) {
      _showSnack(e.toString().replaceFirst('Exception: ', ''), error: true);
    }
  }

  // ── Reset Password ───────────────────────────────────────────────
  Future<void> _resetPassword(Map<String, dynamic> b) async {
    final name = b['name'] ?? 'this boutique';
    final pwCtrl = TextEditingController();
    bool _obscure = true;

    final confirmed = await showDialog<bool>(
      context: context,
      builder: (ctx) => StatefulBuilder(builder: (ctx, setLocal) => AlertDialog(
        backgroundColor: T.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text('Reset Password', style: T.heading.copyWith(fontSize: 18)),
          Text(name, style: T.bodySm.copyWith(fontSize: 12, color: T.text3)),
        ]),
        content: TextField(
          controller: pwCtrl,
          obscureText: _obscure,
          decoration: InputDecoration(
            labelText: 'New Password (min 8 chars)',
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
            suffixIcon: IconButton(
              icon: Icon(_obscure ? Icons.visibility_rounded : Icons.visibility_off_rounded),
              onPressed: () => setLocal(() => _obscure = !_obscure),
            ),
          ),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: T.warning),
            onPressed: () {
              if (pwCtrl.text.trim().length < 8) return;
              Navigator.pop(ctx, true);
            },
            child: const Text('RESET', style: TextStyle(fontWeight: FontWeight.w800)),
          ),
        ],
      )),
    );
    if (confirmed != true) return;
    try {
      await _api.adminResetPassword(widget.adminSecret, b['id'] as int, pwCtrl.text.trim());
      _showSnack('Password reset for "$name".');
    } catch (e) {
      _showSnack(e.toString().replaceFirst('Exception: ', ''), error: true);
    }
  }

  // ── Detail sheet ─────────────────────────────────────────────────
  void _showDetail(Map<String, dynamic> b) {
    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      useSafeArea: true,
      builder: (ctx) => DraggableScrollableSheet(
        initialChildSize: 0.75,
        minChildSize: 0.4,
        maxChildSize: 0.95,
        expand: false,
        builder: (ctx, scrollCtrl) => _BoutiqueDetailSheet(
          boutique: b,
          adminSecret: widget.adminSecret,
          api: _api,
          scrollCtrl: scrollCtrl,
          onToggleHold:     () { Navigator.pop(ctx); _toggleHold(b); },
          onChangePlan:     () { Navigator.pop(ctx); _changePlan(b); },
          onRenew:          () { Navigator.pop(ctx); _renew(b); },
          onToggleFree:     () { Navigator.pop(ctx); _toggleFree(b); },
          onResetPassword:  () { Navigator.pop(ctx); _resetPassword(b); },
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    final visible   = _filtered;
    final total     = _boutiques.length;
    final active    = _boutiques.where((b) => b['is_active'] != false).length;
    final onHold    = total - active;
    final expiring  = _boutiques.where((b) {
      final exp = b['expires_at'] != null ? DateTime.tryParse(b['expires_at']) : null;
      if (exp == null) return false;
      final days = exp.difference(DateTime.now()).inDays;
      return days >= 0 && days <= 7;
    }).length;

    return Scaffold(
      backgroundColor: T.bg,
      appBar: AppBar(
        backgroundColor: T.headerDark,
        foregroundColor: Colors.white,
        elevation: 0,
        title: Row(children: [
          const Icon(Icons.admin_panel_settings_rounded, color: T.accent, size: 20),
          const SizedBox(width: 8),
          Text('Admin Panel', style: GoogleFonts.prata(fontSize: 20, color: Colors.white)),
        ]),
        actions: [
          // Sort toggle
          IconButton(
            icon: Icon(
              _sortExpiry ? Icons.sort_rounded : Icons.access_time_rounded,
              color: _sortExpiry ? T.accent : Colors.white70,
            ),
            tooltip: _sortExpiry ? 'Sorted by expiry' : 'Sort by expiry',
            onPressed: () => setState(() => _sortExpiry = !_sortExpiry),
          ),
          IconButton(
            icon: const Icon(Icons.refresh_rounded),
            onPressed: _load,
            tooltip: 'Refresh',
          ),
        ],
      ),
      body: _loading
        ? const Center(child: CircularProgressIndicator())
        : _error != null
          ? _ErrorState(error: _error!, onRetry: _load)
          : Column(children: [
              // ── Stats bar ──
              Container(
                padding: const EdgeInsets.fromLTRB(16, 12, 16, 8),
                decoration: BoxDecoration(
                  gradient: T.headerGrad,
                  boxShadow: [BoxShadow(
                    color: T.headerDark.withOpacity(0.3),
                    blurRadius: 8, offset: const Offset(0, 2))],
                ),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceAround,
                  children: [
                    _StatPill(label: 'Total',    value: '$total',    color: Colors.white),
                    _StatPill(label: 'Active',   value: '$active',   color: T.success),
                    _StatPill(label: 'On Hold',  value: '$onHold',   color: T.danger),
                    _StatPill(label: 'Expiring', value: '$expiring', color: T.warning),
                  ],
                ),
              ),

              // ── Search bar ──
              Padding(
                padding: const EdgeInsets.fromLTRB(14, 12, 14, 6),
                child: TextField(
                  controller: _searchCtrl,
                  decoration: InputDecoration(
                    hintText: 'Search by name, phone, city…',
                    prefixIcon: const Icon(Icons.search_rounded, size: 20),
                    suffixIcon: _searchCtrl.text.isNotEmpty
                      ? IconButton(
                          icon: const Icon(Icons.clear_rounded, size: 18),
                          onPressed: () => _searchCtrl.clear(),
                        )
                      : null,
                    contentPadding: const EdgeInsets.symmetric(vertical: 10, horizontal: 14),
                    border: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: BorderSide(color: T.border),
                    ),
                    enabledBorder: OutlineInputBorder(
                      borderRadius: BorderRadius.circular(12),
                      borderSide: BorderSide(color: T.border),
                    ),
                  ),
                ),
              ),

              // ── Filter chips ──
              SizedBox(
                height: 36,
                child: ListView(
                  padding: const EdgeInsets.symmetric(horizontal: 12),
                  scrollDirection: Axis.horizontal,
                  children: _Filter.values.map((f) {
                    final active = _filter == f;
                    return Padding(
                      padding: const EdgeInsets.only(right: 8),
                      child: ChoiceChip(
                        label: Text(_filterLabel(f),
                            style: TextStyle(
                                fontSize: 12,
                                fontWeight: FontWeight.w600,
                                color: active ? T.headerDark : T.text2)),
                        selected: active,
                        selectedColor: T.accent,
                        backgroundColor: T.card,
                        side: BorderSide(color: active ? T.accent : T.border),
                        padding: const EdgeInsets.symmetric(horizontal: 4),
                        onSelected: (_) => setState(() => _filter = f),
                      ),
                    );
                  }).toList(),
                ),
              ),
              const SizedBox(height: 6),

              // ── List ──
              Expanded(
                child: visible.isEmpty
                  ? Center(
                      child: Column(mainAxisSize: MainAxisSize.min, children: [
                        Icon(Icons.search_off_rounded, size: 48, color: T.text3),
                        const SizedBox(height: 8),
                        Text('No boutiques found',
                            style: T.bodySm.copyWith(color: T.text3)),
                      ]),
                    )
                  : RefreshIndicator(
                      onRefresh: _load,
                      child: ListView.builder(
                        padding: const EdgeInsets.fromLTRB(14, 4, 14, 32),
                        itemCount: visible.length,
                        itemBuilder: (_, i) => _BoutiqueCard(
                          boutique: visible[i],
                          onTap: () => _showDetail(visible[i]),
                        ),
                      ),
                    ),
              ),
            ]),
    );
  }
}

// ─── Boutique card ────────────────────────────────────────────────────────────
class _BoutiqueCard extends StatelessWidget {
  final Map<String, dynamic> boutique;
  final VoidCallback onTap;
  const _BoutiqueCard({required this.boutique, required this.onTap});

  @override
  Widget build(BuildContext context) {
    final isActive  = boutique['is_active'] as bool? ?? true;
    final isFree    = boutique['is_free']   as bool? ?? false;
    final name      = boutique['name']      ?? 'Unknown';
    final email     = boutique['email']     ?? '';
    final phone     = boutique['phone']     ?? '';
    final plan      = boutique['plan']      as String?;
    final expiresAt = boutique['expires_at'] != null
        ? DateTime.tryParse(boutique['expires_at']) : null;

    final initials = name.trim().split(' ').where((e) => e.isNotEmpty).take(2)
        .map((e) => e[0].toUpperCase()).join();

    // Expiry label + color
    String expLabel = '';
    Color expColor  = T.text3;
    if (isFree) {
      expLabel = '∞ Free Forever';
      expColor = T.success;
    } else if (expiresAt != null) {
      final days = expiresAt.difference(DateTime.now()).inDays;
      if (days < 0) {
        expLabel = 'Expired ${(-days)}d ago';
        expColor = T.danger;
      } else if (days == 0) {
        expLabel = 'Expires today!';
        expColor = T.danger;
      } else if (days <= 7) {
        expLabel = 'Expires in ${days}d';
        expColor = T.warning;
      } else {
        expLabel = 'Until ${DateFormat("d MMM yy").format(expiresAt)}';
        expColor = T.text3;
      }
    }

    return GestureDetector(
      onTap: onTap,
      child: Container(
        margin: const EdgeInsets.only(bottom: 8),
        decoration: BoxDecoration(
          color: T.card,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: !isActive
                ? T.danger.withOpacity(0.5)
                : expiresAt != null &&
                    expiresAt.difference(DateTime.now()).inDays <= 3 &&
                    !isFree
                    ? T.warning.withOpacity(0.5)
                    : T.border,
            width: isActive ? 1 : 1.5,
          ),
          boxShadow: T.shadowCard,
        ),
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
          child: Row(children: [
            // Avatar
            Container(
              width: 42, height: 42,
              decoration: BoxDecoration(
                gradient: isActive ? T.accentGrad : LinearGradient(
                    colors: [T.danger.withOpacity(0.6), T.danger.withOpacity(0.3)]),
                borderRadius: BorderRadius.circular(10),
              ),
              child: Center(child: Text(initials.isNotEmpty ? initials : '?',
                  style: TextStyle(fontSize: 15, fontWeight: FontWeight.w800,
                      color: isActive ? T.headerDark : Colors.white))),
            ),
            const SizedBox(width: 10),

            // Info
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Row(children: [
                Expanded(child: Text(name,
                    style: T.heading.copyWith(fontSize: 14),
                    overflow: TextOverflow.ellipsis)),
                if (!isActive)
                  _Badge('HOLD', T.danger),
                if (isFree) ...[
                  const SizedBox(width: 4),
                  _Badge('FREE', T.success),
                ],
              ]),
              const SizedBox(height: 2),
              if (phone.isNotEmpty)
                Text(phone,
                    style: T.bodySm.copyWith(fontSize: 11),
                    overflow: TextOverflow.ellipsis)
              else if (email.isNotEmpty)
                Text(email,
                    style: T.bodySm.copyWith(fontSize: 11),
                    overflow: TextOverflow.ellipsis),
              const SizedBox(height: 4),
              Row(children: [
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                  decoration: BoxDecoration(
                    color: _planColor(plan).withOpacity(0.12),
                    borderRadius: BorderRadius.circular(4),
                    border: Border.all(color: _planColor(plan).withOpacity(0.3)),
                  ),
                  child: Text(_planLabel(plan),
                      style: TextStyle(fontSize: 9, fontWeight: FontWeight.w700,
                          color: _planColor(plan))),
                ),
                if (expLabel.isNotEmpty) ...[
                  const SizedBox(width: 6),
                  Text(expLabel,
                      style: TextStyle(fontSize: 10, color: expColor,
                          fontWeight: FontWeight.w500)),
                ],
              ]),
            ])),

            const SizedBox(width: 6),
            const Icon(Icons.chevron_right_rounded, color: T.text3, size: 18),
          ]),
        ),
      ),
    );
  }
}

// ─── Detail sheet ─────────────────────────────────────────────────────────────
class _BoutiqueDetailSheet extends StatefulWidget {
  final Map<String, dynamic> boutique;
  final String adminSecret;
  final Api api;
  final ScrollController scrollCtrl;
  final VoidCallback onToggleHold;
  final VoidCallback onChangePlan;
  final VoidCallback onRenew;
  final VoidCallback onToggleFree;
  final VoidCallback onResetPassword;

  const _BoutiqueDetailSheet({
    required this.boutique,
    required this.adminSecret,
    required this.api,
    required this.scrollCtrl,
    required this.onToggleHold,
    required this.onChangePlan,
    required this.onRenew,
    required this.onToggleFree,
    required this.onResetPassword,
  });

  @override
  State<_BoutiqueDetailSheet> createState() => _BoutiqueDetailSheetState();
}

class _BoutiqueDetailSheetState extends State<_BoutiqueDetailSheet> {
  Map<String, dynamic>? _stats;
  bool _loadingStats = true;

  @override
  void initState() {
    super.initState();
    _loadStats();
  }

  Future<void> _loadStats() async {
    try {
      final s = await widget.api.adminGetStats(
          widget.adminSecret, widget.boutique['id'] as int);
      if (mounted) setState(() { _stats = s; _loadingStats = false; });
    } catch (_) {
      if (mounted) setState(() => _loadingStats = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final b = widget.boutique;
    final isActive = b['is_active'] as bool? ?? true;
    final isFree   = b['is_free']  as bool? ?? false;
    final name     = b['name']     ?? 'Unknown';
    final email    = b['email']    ?? '';
    final phone    = b['phone']    ?? '';
    final city     = b['city']     ?? '';
    final plan     = b['plan']     as String?;

    final createdAt = b['created_at'] != null
        ? DateFormat('d MMM yyyy').format(DateTime.parse(b['created_at'])) : '—';
    final expiresAt = b['expires_at'] != null
        ? DateFormat('d MMM yyyy').format(DateTime.parse(b['expires_at'])) : '—';
    final lastLogin = b['last_login_at'] != null
        ? _timeAgo(DateTime.parse(b['last_login_at'])) : 'Never';
    final lastAction       = b['last_action']        as String?;
    final lastActionDetail = b['last_action_detail'] as String?;
    final lastActionAt     = b['last_action_at'] != null
        ? DateFormat('d MMM, HH:mm').format(DateTime.parse(b['last_action_at'])) : null;

    final initials = name.trim().split(' ').where((e) => e.isNotEmpty).take(2)
        .map((e) => e[0].toUpperCase()).join();

    return Container(
      decoration: const BoxDecoration(
        color: T.bg,
        borderRadius: BorderRadius.vertical(top: Radius.circular(20)),
      ),
      child: ListView(
        controller: widget.scrollCtrl,
        padding: const EdgeInsets.fromLTRB(20, 0, 20, 32),
        children: [
          // Handle
          Center(child: Padding(
            padding: const EdgeInsets.symmetric(vertical: 12),
            child: Container(width: 36, height: 4,
                decoration: BoxDecoration(color: T.border,
                    borderRadius: BorderRadius.circular(2))),
          )),

          // ── Header ──
          Row(children: [
            Container(
              width: 54, height: 54,
              decoration: BoxDecoration(
                gradient: isActive ? T.accentGrad : LinearGradient(
                    colors: [T.danger.withOpacity(0.6), T.danger.withOpacity(0.3)]),
                borderRadius: BorderRadius.circular(14),
              ),
              child: Center(child: Text(initials.isNotEmpty ? initials : '?',
                  style: TextStyle(fontSize: 20, fontWeight: FontWeight.w800,
                      color: isActive ? T.headerDark : Colors.white))),
            ),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(name, style: T.heading.copyWith(fontSize: 18)),
              if (city.isNotEmpty)
                Text(city, style: T.bodySm.copyWith(fontSize: 12, color: T.text3)),
            ])),
            Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
              _Badge(isActive ? 'ACTIVE' : 'ON HOLD', isActive ? T.success : T.danger),
              if (isFree) ...[
                const SizedBox(height: 4),
                _Badge('FREE', T.success),
              ],
            ]),
          ]),
          const SizedBox(height: 16),

          // ── Contact info (tap to copy) ──
          if (phone.isNotEmpty) _CopyRow(
            icon: Icons.phone_rounded, label: phone,
            onCopy: () => _copy(context, phone, 'Phone copied'),
          ),
          if (email.isNotEmpty) _CopyRow(
            icon: Icons.email_rounded, label: email,
            onCopy: () => _copy(context, email, 'Email copied'),
          ),
          const SizedBox(height: 4),
          Row(children: [
            Expanded(child: _InfoTile('Joined', createdAt, Icons.calendar_today_rounded)),
            const SizedBox(width: 8),
            Expanded(child: _InfoTile('Last Login', lastLogin,
                Icons.login_rounded,
                valueColor: lastLogin == 'Never' ? T.danger : null)),
          ]),
          const SizedBox(height: 12),

          // ── Plan + Expiry ──
          Container(
            padding: const EdgeInsets.all(14),
            decoration: BoxDecoration(
              color: T.card,
              borderRadius: BorderRadius.circular(12),
              border: Border.all(color: _planColor(plan).withOpacity(0.3)),
            ),
            child: Row(children: [
              Container(
                width: 40, height: 40,
                decoration: BoxDecoration(
                  color: _planColor(plan).withOpacity(0.12),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Icon(Icons.workspace_premium_rounded,
                    color: _planColor(plan), size: 22),
              ),
              const SizedBox(width: 12),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(_planLabel(plan),
                    style: TextStyle(fontSize: 16, fontWeight: FontWeight.w800,
                        color: _planColor(plan))),
                Text(isFree ? 'Free forever — no expiry'
                    : 'Expires: $expiresAt',
                    style: T.bodySm.copyWith(fontSize: 12)),
              ])),
            ]),
          ),
          const SizedBox(height: 10),

          // ── Usage stats (loaded async) ──
          _loadingStats
            ? Container(
                height: 60,
                alignment: Alignment.center,
                child: const SizedBox(width: 20, height: 20,
                    child: CircularProgressIndicator(strokeWidth: 2)),
              )
            : _stats != null
              ? Row(children: [
                  Expanded(child: _StatCard(
                      label: 'Customers',
                      value: '${_stats!['customers'] ?? 0}',
                      icon: Icons.people_rounded,
                      color: T.accent)),
                  const SizedBox(width: 8),
                  Expanded(child: _StatCard(
                      label: 'Orders',
                      value: '${_stats!['orders'] ?? 0}',
                      icon: Icons.receipt_long_rounded,
                      color: T.info)),
                  const SizedBox(width: 8),
                  Expanded(child: _StatCard(
                      label: 'Invoices',
                      value: '${_stats!['invoices'] ?? 0}',
                      icon: Icons.description_rounded,
                      color: T.success)),
                ])
              : const SizedBox.shrink(),
          const SizedBox(height: 10),

          // ── Last admin action ──
          if (lastAction != null)
            Container(
              padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(
                color: T.surface,
                borderRadius: BorderRadius.circular(10),
                border: Border.all(color: T.border),
              ),
              child: Row(children: [
                const Icon(Icons.history_rounded, size: 16, color: T.text3),
                const SizedBox(width: 8),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(lastAction,
                      style: T.body.copyWith(fontSize: 13, fontWeight: FontWeight.w600)),
                  if (lastActionDetail != null)
                    Text(lastActionDetail, style: T.bodySm.copyWith(fontSize: 11)),
                  if (lastActionAt != null)
                    Text(lastActionAt, style: T.bodySm.copyWith(fontSize: 10, color: T.text3)),
                ])),
              ]),
            ),

          const SizedBox(height: 20),
          Text('ACTIONS', style: T.label.copyWith(fontSize: 11)),
          const SizedBox(height: 10),

          // ── Action buttons row 1 ──
          Row(children: [
            Expanded(child: _ActionBtn(
              icon: Icons.swap_horiz_rounded,
              label: 'Change Plan',
              color: T.accent,
              onTap: widget.onChangePlan,
            )),
            const SizedBox(width: 10),
            Expanded(child: _ActionBtn(
              icon: Icons.autorenew_rounded,
              label: 'Renew',
              color: T.info,
              onTap: widget.onRenew,
            )),
          ]),
          const SizedBox(height: 10),

          // ── Action buttons row 2 ──
          Row(children: [
            Expanded(child: _ActionBtn(
              icon: isActive ? Icons.pause_circle_rounded : Icons.play_circle_rounded,
              label: isActive ? 'Put On Hold' : 'Reactivate',
              color: isActive ? T.danger : T.success,
              onTap: widget.onToggleHold,
            )),
            const SizedBox(width: 10),
            Expanded(child: _ActionBtn(
              icon: isFree ? Icons.money_off_rounded : Icons.card_giftcard_rounded,
              label: isFree ? 'Remove Free' : 'Grant Free',
              color: isFree ? T.warning : T.purple,
              onTap: widget.onToggleFree,
            )),
          ]),
          const SizedBox(height: 10),

          // ── Reset password (full width, warning color) ──
          _ActionBtn(
            icon: Icons.lock_reset_rounded,
            label: 'Reset Password',
            color: T.warning,
            onTap: widget.onResetPassword,
            fullWidth: true,
          ),
        ],
      ),
    );
  }

  void _copy(BuildContext context, String text, String message) {
    Clipboard.setData(ClipboardData(text: text));
    ScaffoldMessenger.of(context).showSnackBar(
      SnackBar(content: Text(message), duration: const Duration(seconds: 1)));
  }

  String _timeAgo(DateTime dt) {
    final diff = DateTime.now().difference(dt);
    if (diff.inDays > 30) return DateFormat('d MMM yy').format(dt);
    if (diff.inDays > 0)  return '${diff.inDays}d ago';
    if (diff.inHours > 0) return '${diff.inHours}h ago';
    return 'Just now';
  }
}

// ─── Small widgets ────────────────────────────────────────────────────────────
class _Badge extends StatelessWidget {
  final String text;
  final Color color;
  const _Badge(this.text, this.color);
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 3),
    decoration: BoxDecoration(
      color: color.withOpacity(0.12),
      borderRadius: BorderRadius.circular(5),
      border: Border.all(color: color.withOpacity(0.35)),
    ),
    child: Text(text,
        style: TextStyle(fontSize: 9, fontWeight: FontWeight.w800, color: color)),
  );
}

class _CopyRow extends StatelessWidget {
  final IconData icon;
  final String label;
  final VoidCallback onCopy;
  const _CopyRow({required this.icon, required this.label, required this.onCopy});
  @override
  Widget build(BuildContext context) => Padding(
    padding: const EdgeInsets.only(bottom: 6),
    child: Row(children: [
      Icon(icon, size: 14, color: T.text3),
      const SizedBox(width: 6),
      Expanded(child: Text(label,
          style: T.body.copyWith(fontSize: 13),
          overflow: TextOverflow.ellipsis)),
      GestureDetector(
        onTap: onCopy,
        child: const Icon(Icons.copy_rounded, size: 14, color: T.text3),
      ),
    ]),
  );
}

class _InfoTile extends StatelessWidget {
  final String label, value;
  final IconData icon;
  final Color? valueColor;
  const _InfoTile(this.label, this.value, this.icon, {this.valueColor});
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(10),
    decoration: BoxDecoration(
        color: T.card, borderRadius: BorderRadius.circular(10),
        border: Border.all(color: T.border)),
    child: Row(children: [
      Icon(icon, size: 14, color: T.text3),
      const SizedBox(width: 6),
      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(label, style: T.bodySm.copyWith(fontSize: 10, color: T.text3)),
        Text(value, style: T.body.copyWith(fontSize: 12,
            fontWeight: FontWeight.w600, color: valueColor),
            overflow: TextOverflow.ellipsis),
      ])),
    ]),
  );
}

class _StatCard extends StatelessWidget {
  final String label, value;
  final IconData icon;
  final Color color;
  const _StatCard({required this.label, required this.value,
      required this.icon, required this.color});
  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.symmetric(vertical: 10, horizontal: 8),
    decoration: BoxDecoration(
        color: color.withOpacity(0.07),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withOpacity(0.2))),
    child: Column(children: [
      Icon(icon, size: 18, color: color),
      const SizedBox(height: 4),
      Text(value, style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800, color: color)),
      Text(label, style: TextStyle(fontSize: 10, color: T.text3)),
    ]),
  );
}

class _ActionBtn extends StatelessWidget {
  final IconData icon;
  final String label;
  final Color color;
  final VoidCallback onTap;
  final bool fullWidth;
  const _ActionBtn({required this.icon, required this.label,
      required this.color, required this.onTap, this.fullWidth = false});
  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: Container(
      width: fullWidth ? double.infinity : null,
      padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 8),
      decoration: BoxDecoration(
        color: color.withOpacity(0.09),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.28)),
      ),
      child: Row(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          Icon(icon, size: 18, color: color),
          const SizedBox(width: 6),
          Text(label, style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700, color: color)),
        ],
      ),
    ),
  );
}

class _StatPill extends StatelessWidget {
  final String label, value;
  final Color color;
  const _StatPill({required this.label, required this.value, required this.color});
  @override
  Widget build(BuildContext context) => Column(children: [
    Text(value, style: TextStyle(fontSize: 22, fontWeight: FontWeight.w800, color: color)),
    Text(label, style: const TextStyle(fontSize: 10, color: Colors.white54, letterSpacing: 0.3)),
  ]);
}

class _ErrorState extends StatelessWidget {
  final String error;
  final VoidCallback onRetry;
  const _ErrorState({required this.error, required this.onRetry});
  @override
  Widget build(BuildContext context) => Center(
    child: Padding(
      padding: const EdgeInsets.all(32),
      child: Column(mainAxisSize: MainAxisSize.min, children: [
        const Icon(Icons.lock_rounded, size: 48, color: T.danger),
        const SizedBox(height: 12),
        Text(error, textAlign: TextAlign.center,
            style: const TextStyle(color: T.danger, fontSize: 15)),
        const SizedBox(height: 16),
        ElevatedButton(onPressed: onRetry, child: const Text('Retry')),
      ]),
    ),
  );
}
