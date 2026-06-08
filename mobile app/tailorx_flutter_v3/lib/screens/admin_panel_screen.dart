import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import '../services/api_service.dart';
import '../utils/theme.dart';

class AdminPanelScreen extends StatefulWidget {
  final String adminSecret;
  const AdminPanelScreen({super.key, required this.adminSecret});

  @override
  State<AdminPanelScreen> createState() => _AdminPanelScreenState();
}

class _AdminPanelScreenState extends State<AdminPanelScreen> {
  final _api = Api();
  List<Map<String, dynamic>> _boutiques = [];
  bool _loading = true;
  String? _error;

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() { _loading = true; _error = null; });
    try {
      final list = await _api.adminGetBoutiques(widget.adminSecret);
      if (mounted) setState(() { _boutiques = list; _loading = false; });
    } catch (e) {
      if (mounted) setState(() { _error = e.toString().replaceFirst('Exception: ', ''); _loading = false; });
    }
  }

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
            ? 'Reactivate "$name"? They will be able to login again.'
            : 'Put "$name" on hold? They won\'t be able to login until reactivated.',
          style: T.body,
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
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
      if (mounted) {
        ScaffoldMessenger.of(context).showSnackBar(SnackBar(
          content: Text(newState ? '"$name" reactivated.' : '"$name" put on hold.'),
          backgroundColor: newState ? T.success : T.danger,
        ));
      }
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
        SnackBar(content: Text(e.toString().replaceFirst('Exception: ', ''))));
    }
  }

  @override
  Widget build(BuildContext context) {
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
          : _boutiques.isEmpty
            ? const Center(child: Text('No boutiques found.'))
            : RefreshIndicator(
                onRefresh: _load,
                child: ListView(
                  padding: const EdgeInsets.fromLTRB(16, 16, 16, 32),
                  children: [
                    // Summary bar
                    Container(
                      padding: const EdgeInsets.all(16),
                      margin: const EdgeInsets.only(bottom: 16),
                      decoration: BoxDecoration(
                        gradient: T.headerGrad,
                        borderRadius: BorderRadius.circular(16),
                      ),
                      child: Row(
                        mainAxisAlignment: MainAxisAlignment.spaceAround,
                        children: [
                          _StatBadge(
                            label: 'Total',
                            value: '${_boutiques.length}',
                            color: Colors.white,
                          ),
                          _StatBadge(
                            label: 'Active',
                            value: '${_boutiques.where((b) => b['is_active'] != false).length}',
                            color: T.success,
                          ),
                          _StatBadge(
                            label: 'On Hold',
                            value: '${_boutiques.where((b) => b['is_active'] == false).length}',
                            color: T.danger,
                          ),
                        ],
                      ),
                    ),
                    ..._boutiques.map((b) => _BoutiqueCard(
                      boutique: b,
                      onToggleHold: () => _toggleHold(b),
                    )),
                  ],
                ),
              ),
    );
  }
}

class _BoutiqueCard extends StatelessWidget {
  final Map<String, dynamic> boutique;
  final VoidCallback onToggleHold;
  const _BoutiqueCard({required this.boutique, required this.onToggleHold});

  @override
  Widget build(BuildContext context) {
    final isActive = boutique['is_active'] as bool? ?? true;
    final name = boutique['name'] ?? 'Unknown';
    final email = boutique['email'] ?? '';
    final plan = (boutique['plan'] ?? 'free').toString().toUpperCase();
    final city = boutique['city'] ?? '';
    final createdAt = boutique['created_at'] != null
        ? DateFormat('dd MMM yyyy').format(DateTime.parse(boutique['created_at']))
        : '';
    final initials = name.trim().split(' ').where((e) => e.isNotEmpty).take(2)
        .map((e) => e[0].toUpperCase()).join();

    return Container(
      margin: const EdgeInsets.only(bottom: 12),
      decoration: BoxDecoration(
        color: T.card,
        borderRadius: BorderRadius.circular(16),
        border: Border.all(
          color: isActive ? T.border : T.danger.withOpacity(0.4),
          width: isActive ? 1 : 1.5,
        ),
        boxShadow: T.shadowCard,
      ),
      child: Padding(
        padding: const EdgeInsets.all(14),
        child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
          // Avatar
          Container(
            width: 48, height: 48,
            decoration: BoxDecoration(
              gradient: isActive ? T.accentGrad : LinearGradient(
                colors: [T.danger.withOpacity(0.6), T.danger.withOpacity(0.3)]),
              borderRadius: BorderRadius.circular(12),
            ),
            child: Center(child: Text(initials,
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800,
                    color: isActive ? T.headerDark : Colors.white))),
          ),
          const SizedBox(width: 12),

          // Info
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Row(children: [
              Expanded(child: Text(name,
                  style: T.heading.copyWith(fontSize: 16),
                  overflow: TextOverflow.ellipsis)),
              // Status badge
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                decoration: BoxDecoration(
                  color: isActive ? T.success.withOpacity(0.1) : T.danger.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(6),
                  border: Border.all(
                    color: isActive ? T.success.withOpacity(0.3) : T.danger.withOpacity(0.3)),
                ),
                child: Text(isActive ? 'ACTIVE' : 'ON HOLD',
                    style: TextStyle(fontSize: 10, fontWeight: FontWeight.w700,
                        color: isActive ? T.success : T.danger)),
              ),
            ]),
            const SizedBox(height: 3),
            Text(email, style: T.bodySm.copyWith(fontSize: 12)),
            const SizedBox(height: 4),
            Row(children: [
              if (city.isNotEmpty) ...[
                Icon(Icons.location_on_rounded, size: 11, color: T.text3),
                const SizedBox(width: 2),
                Text(city, style: T.bodySm.copyWith(fontSize: 11)),
                const SizedBox(width: 8),
              ],
              Container(
                padding: const EdgeInsets.symmetric(horizontal: 6, vertical: 2),
                decoration: BoxDecoration(
                  color: T.accent.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(4)),
                child: Text(plan, style: TextStyle(fontSize: 9, fontWeight: FontWeight.w700,
                    color: T.accent)),
              ),
              if (createdAt.isNotEmpty) ...[
                const SizedBox(width: 8),
                Text('Since $createdAt', style: T.bodySm.copyWith(fontSize: 10, color: T.text3)),
              ],
            ]),
          ])),

          const SizedBox(width: 8),

          // Hold toggle button
          GestureDetector(
            onTap: onToggleHold,
            child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 7),
              decoration: BoxDecoration(
                color: isActive ? T.danger.withOpacity(0.08) : T.success.withOpacity(0.08),
                borderRadius: BorderRadius.circular(10),
                border: Border.all(
                  color: isActive ? T.danger.withOpacity(0.25) : T.success.withOpacity(0.25)),
              ),
              child: Column(children: [
                Icon(
                  isActive ? Icons.pause_circle_rounded : Icons.play_circle_rounded,
                  size: 20,
                  color: isActive ? T.danger : T.success,
                ),
                const SizedBox(height: 2),
                Text(
                  isActive ? 'HOLD' : 'LIFT',
                  style: TextStyle(
                    fontSize: 9, fontWeight: FontWeight.w800,
                    color: isActive ? T.danger : T.success,
                    letterSpacing: 0.5,
                  ),
                ),
              ]),
            ),
          ),
        ]),
      ),
    );
  }
}

class _StatBadge extends StatelessWidget {
  final String label, value;
  final Color color;
  const _StatBadge({required this.label, required this.value, required this.color});

  @override
  Widget build(BuildContext context) => Column(children: [
    Text(value, style: TextStyle(fontSize: 28, fontWeight: FontWeight.w800, color: color)),
    Text(label, style: TextStyle(fontSize: 11, color: Colors.white54, letterSpacing: 0.5)),
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
            style: TextStyle(color: T.danger, fontSize: 15)),
        const SizedBox(height: 16),
        ElevatedButton(onPressed: onRetry, child: const Text('Retry')),
      ]),
    ),
  );
}
