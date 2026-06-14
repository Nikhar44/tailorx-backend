// lib/screens/dashboard_screen.dart
//
// Combined B+C dashboard, ported from the HTML mockup the user pasted.
// Uses: AppTheme (theme.dart), AppLang (lang.dart), Api (api_service.dart),
//       common_widgets (StatusBadge etc.) — drop-in replacement for the
//       existing dashboard_screen.dart.
//
// Sections (top → bottom):
//   1. Greeting
//   2. Alert banner (pending payments / orders)
//   3. 4 stat cards (with left accent bar)
//   4. Order pipeline (5 stage chips with counts)
//   5. Quick actions (4 tinted buttons)
//   6. Monthly collection progress (dark card)
//   7. Today's tasks
//   8. Activity feed (timeline)

import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import '../models/models.dart';
import '../services/api_service.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import '../widgets/common_widgets.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen>
    with SingleTickerProviderStateMixin {
  final _api = Api();
  final _lang = AppLang();
  DashboardData? _d;
  bool _loading = true;
  String? _err;
  late AnimationController _anim;

  final _fmt = NumberFormat.currency(
      locale: 'en_IN', symbol: '\u20B9', decimalDigits: 0);
  final _fmtCompact = NumberFormat.compactCurrency(
      locale: 'en_IN', symbol: '\u20B9', decimalDigits: 1);

  // Monthly collection target (kept locally; could later be a setting)
  static const double _monthlyTarget = 500000;

  @override
  void initState() {
    super.initState();
    _anim = AnimationController(
        vsync: this, duration: const Duration(milliseconds: 900));
    _load();
  }

  @override
  void dispose() {
    _anim.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _err = null;
    });
    try {
      final d = await _api.getDashboard();
      if (mounted) {
        setState(() => _d = d);
        _anim.forward(from: 0);
      }
    } catch (e) {
      if (mounted) setState(() => _err = e.toString());
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  // Curved interval helper for staggered reveals
  Widget _stagger(int i, Widget child) {
    final start = (i * 0.08).clamp(0.0, 0.85);
    final end = (start + 0.45).clamp(0.0, 1.0);
    final curve = CurvedAnimation(
        parent: _anim, curve: Interval(start, end, curve: Curves.easeOutCubic));
    return AnimatedBuilder(
      animation: curve,
      builder: (_, __) => Opacity(
        opacity: curve.value,
        child: Transform.translate(
          offset: Offset(0, (1 - curve.value) * 14),
          child: child,
        ),
      ),
    );
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return const Center(
          child:
              CircularProgressIndicator(strokeWidth: 1.5, color: AppTheme.accent));
    }
    if (_err != null) {
      return EmptyState(
          icon: Icons.cloud_off_rounded,
          title: _lang.t('connection_error'),
          subtitle: _lang.t('server_waking'),
          buttonLabel: _lang.t('retry'),
          onPressed: _load);
    }
    final d = _d!;

    return RefreshIndicator(
      onRefresh: _load,
      color: AppTheme.accent,
      child: ListView(
        padding: const EdgeInsets.fromLTRB(18, 16, 18, 32),
        children: [
          // ── 1. Greeting ─────────────────────────────────────────
          _stagger(0, _greeting()),

          // ── 2. Alert banner ─────────────────────────────────────
          if (d.pendingOrders > 0) ...[
            const SizedBox(height: 14),
            _stagger(1, _alertBanner(d)),
          ],

          const SizedBox(height: 16),

          // ── 3. Stat cards (4 tiles) ─────────────────────────────
          _stagger(2, _stats(d)),

          const SizedBox(height: 18),

          // ── 4. Order pipeline ───────────────────────────────────
          _stagger(3, _sectionTitle('order_pipeline', fallback: 'Order Pipeline')),
          const SizedBox(height: 8),
          _stagger(4, _pipeline(d)),

          const SizedBox(height: 16),

          // ── 5. Quick actions ────────────────────────────────────
          _stagger(5, _sectionTitle('quick_actions', fallback: 'Quick Actions')),
          const SizedBox(height: 8),
          _stagger(6, _quickActions()),

          const SizedBox(height: 16),

          // ── 6. Monthly progress card ────────────────────────────
          _stagger(7, _monthlyCard(d)),

          const SizedBox(height: 16),

          // ── 7. Today's tasks ────────────────────────────────────
          _stagger(8, _sectionTitle('todays_tasks', fallback: "Today's Tasks")),
          const SizedBox(height: 8),
          _stagger(9, _tasks(d)),

          const SizedBox(height: 16),

          // ── 8. Activity feed ────────────────────────────────────
          _stagger(10,
              _sectionTitle('activity_feed', fallback: 'Activity Feed')),
          const SizedBox(height: 8),
          _stagger(11, _activityFeed(d)),
        ],
      ),
    );
  }

  // ─────────────────────────────────────────────────────────────────
  // SECTION BUILDERS
  // ─────────────────────────────────────────────────────────────────

  Widget _greeting() {
    final hour = DateTime.now().hour;
    String greet = 'Good evening';
    if (hour < 12) {
      greet = 'Good morning';
    } else if (hour < 17) greet = 'Good afternoon';
    final name = _api.boutiqueName ?? 'TailorX';
    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text('$greet, $name', style: AppTheme.displayLarge.copyWith(fontSize: 22)),
      const SizedBox(height: 2),
      Text(DateFormat('EEEE, d MMMM').format(DateTime.now()),
          style: AppTheme.bodySmall),
    ]);
  }

  Widget _alertBanner(DashboardData d) {
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: () {}, // TODO: jump to filtered orders
        borderRadius: BorderRadius.circular(12),
        child: Container(
          padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(
            gradient: LinearGradient(colors: [
              AppTheme.warning.withOpacity(0.1),
              AppTheme.warning.withOpacity(0.03),
            ]),
            border: Border.all(color: AppTheme.warning.withOpacity(0.2)),
            borderRadius: BorderRadius.circular(12),
          ),
          child: Row(children: [
            Container(
              width: 36, height: 36,
              decoration: BoxDecoration(
                color: AppTheme.warning.withOpacity(0.15),
                borderRadius: BorderRadius.circular(10),
              ),
              child: const Icon(Icons.pending_actions_rounded,
                  size: 16, color: AppTheme.warning),
            ),
            const SizedBox(width: 12),
            Expanded(
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('${d.pendingOrders} pending orders',
                    style: AppTheme.bodyMedium
                        .copyWith(fontWeight: FontWeight.w600)),
                Text('Require attention',
                    style: AppTheme.bodySmall.copyWith(fontSize: 9)),
              ]),
            ),
            const Icon(Icons.chevron_right_rounded,
                size: 14, color: AppTheme.textMuted),
          ]),
        ),
      ),
    );
  }

  Widget _stats(DashboardData d) {
    final tiles = [
      _StatTile(
          icon: Icons.people_rounded,
          color: AppTheme.info,
          value: d.totalCustomers.toString(),
          label: 'Customers'),
      _StatTile(
          icon: Icons.receipt_long_rounded,
          color: AppTheme.purple,
          value: d.totalOrders.toString(),
          label: 'Active Orders'),
      _StatTile(
          icon: Icons.trending_up_rounded,
          color: AppTheme.success,
          value: _fmtCompact.format(d.totalRevenue),
          valueColor: AppTheme.success,
          label: 'Revenue'),
      _StatTile(
          icon: Icons.schedule_rounded,
          color: AppTheme.warning,
          value: _fmtCompact.format(d.pendingPayments),
          valueColor: AppTheme.warning,
          label: 'Pending'),
    ];
    return GridView.count(
      crossAxisCount: 2,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      crossAxisSpacing: 8,
      mainAxisSpacing: 8,
      childAspectRatio: 1.5,
      children: tiles,
    );
  }

  Widget _pipeline(DashboardData d) {
    // Pull counts from recentOrders status histogram (fallback when API
    // doesn't expose a per-stage breakdown). If your DashboardData has
    // a dedicated map, swap this in.
    final stages = const [
      ['Received', AppTheme.warning],
      ['Cutting', AppTheme.info],
      ['Stitching', AppTheme.purple],
      ['Trial', AppTheme.teal],
      ['Ready', AppTheme.success],
    ];
    final counts = <String, int>{};
    for (final o in d.recentOrders) {
      final k = o.status.toLowerCase();
      counts[k] = (counts[k] ?? 0) + 1;
    }
    return SizedBox(
      height: 64,
      child: Row(
        children: stages.map((s) {
          final label = s[0] as String;
          final color = s[1] as Color;
          final count = counts[label.toLowerCase()] ?? 0;
          return Expanded(
            child: Padding(
              padding: const EdgeInsets.symmetric(horizontal: 3),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 250),
                decoration: BoxDecoration(
                  color: color.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(10),
                ),
                child: Column(
                  mainAxisAlignment: MainAxisAlignment.center,
                  children: [
                    Text('$count',
                        style: GoogleFonts.playfairDisplay(
                            fontSize: 20,
                            fontWeight: FontWeight.w700,
                            height: 1,
                            color: color)),
                    const SizedBox(height: 3),
                    Text(label.toUpperCase(),
                        style: TextStyle(
                            fontSize: 7,
                            fontWeight: FontWeight.w600,
                            letterSpacing: 1.2,
                            color: color)),
                  ],
                ),
              ),
            ),
          );
        }).toList(),
      ),
    );
  }

  Widget _quickActions() {
    final actions = [
      _QuickAction(
          icon: Icons.person_add_alt_1_rounded,
          color: AppTheme.info,
          label: 'Customer'),
      _QuickAction(
          icon: Icons.content_cut_rounded,
          color: AppTheme.success,
          label: 'Order'),
      _QuickAction(
          icon: Icons.description_rounded,
          color: AppTheme.accentDark,
          label: 'Invoice',
          tintBg: AppTheme.accent),
      _QuickAction(
          icon: Icons.send_rounded, color: AppTheme.purple, label: 'Notify'),
    ];
    return Row(
      children: actions
          .map((a) => Expanded(
                child: Padding(
                  padding: const EdgeInsets.symmetric(horizontal: 3),
                  child: a,
                ),
              ))
          .toList(),
    );
  }

  Widget _monthlyCard(DashboardData d) {
    final collected = d.totalRevenue;
    final pct = (collected / _monthlyTarget).clamp(0.0, 1.0);
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        gradient: const LinearGradient(
          begin: Alignment.topLeft,
          end: Alignment.bottomRight,
          colors: [Color(0xFF1C1C1C), Color(0xFF2A2A3A)],
        ),
        borderRadius: BorderRadius.circular(12),
      ),
      child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
          Text('MONTHLY COLLECTION',
              style: TextStyle(
                  fontSize: 9,
                  letterSpacing: 2,
                  fontWeight: FontWeight.w600,
                  color: Colors.white.withOpacity(0.4))),
          Text('${(pct * 100).round()}%',
              style: GoogleFonts.playfairDisplay(
                  fontSize: 24,
                  fontWeight: FontWeight.w600,
                  color: AppTheme.accent)),
        ]),
        const SizedBox(height: 8),
        // Animated bar
        TweenAnimationBuilder<double>(
          duration: const Duration(milliseconds: 1100),
          curve: Curves.easeOutCubic,
          tween: Tween(begin: 0, end: pct),
          builder: (_, v, __) => ClipRRect(
            borderRadius: BorderRadius.circular(3),
            child: Stack(children: [
              Container(
                  height: 5, color: Colors.white.withOpacity(0.1)),
              FractionallySizedBox(
                widthFactor: v,
                child: Container(
                  height: 5,
                  decoration: const BoxDecoration(
                    gradient: LinearGradient(
                      colors: [AppTheme.accent, Color(0xFFE8C49A)],
                    ),
                  ),
                ),
              ),
            ]),
          ),
        ),
        const SizedBox(height: 6),
        Text(
            '${_fmt.format(collected)} of ${_fmt.format(_monthlyTarget)} target',
            style: TextStyle(
                fontSize: 9, color: Colors.white.withOpacity(0.35))),
      ]),
    );
  }

  Widget _tasks(DashboardData d) {
    // Build today's task list from recentOrders that need action.
    final today = <_TaskItem>[];
    for (final o in d.recentOrders.take(6)) {
      switch (o.status.toLowerCase()) {
        case 'trial':
          today.add(_TaskItem(
              title: 'Trial — ${o.customerName ?? "Unknown"}',
              subtitle: '${o.description} fitting today',
              badgeText: 'Trial',
              badgeColor: AppTheme.teal));
          break;
        case 'ready':
          today.add(_TaskItem(
              title: 'Deliver — ${o.customerName ?? "Unknown"}',
              subtitle: '${o.description} ready for pickup',
              badgeText: 'Ready',
              badgeColor: AppTheme.success));
          break;
        default:
          if (o.balanceAmount > 0) {
            today.add(_TaskItem(
                title: 'Payment — ${o.customerName ?? "Unknown"}',
                subtitle: '${_fmt.format(o.balanceAmount)} balance pending',
                badgeText: 'Due',
                badgeColor: AppTheme.danger));
          }
      }
      if (today.length >= 3) break;
    }
    if (today.isEmpty) {
      return Container(
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
            color: AppTheme.cardBg,
            borderRadius: BorderRadius.circular(10),
            boxShadow: AppTheme.cardShadow),
        child: Center(
            child: Text('No tasks today — relax ☕',
                style: AppTheme.bodySmall)),
      );
    }
    return Column(children: today.map((t) => t).toList());
  }

  Widget _activityFeed(DashboardData d) {
    // Synthesize a feed from recent orders. In production back this
    // with a real /activity endpoint.
    final feed = <_FeedItem>[];
    for (final o in d.recentOrders.take(5)) {
      final c = AppTheme.statusColor(o.status);
      String title;
      String desc;
      String badge;
      switch (o.status.toLowerCase()) {
        case 'received':
          title = 'New Order';
          desc = '${o.customerName ?? "Unknown"} — ${o.description} '
              '(${_fmt.format(o.totalAmount)})';
          badge = 'Received';
          break;
        case 'stitching':
        case 'cutting':
        case 'trial':
          title = 'Status Changed';
          desc = "${o.customerName ?? "Unknown"}'s ${o.description} → ${o.status}";
          badge = o.status;
          break;
        case 'ready':
          title = 'Ready for Pickup';
          desc = '${o.customerName ?? "Unknown"} — ${o.description}';
          badge = 'Ready';
          break;
        case 'delivered':
          title = 'Delivered';
          desc = '${o.customerName ?? "Unknown"} — ${o.description}';
          badge = 'Delivered';
          break;
        default:
          title = 'Order Update';
          desc = '${o.customerName ?? "Unknown"} — ${o.description}';
          badge = o.status;
      }
      feed.add(_FeedItem(
          color: c,
          time: _relTime(o.createdAt),
          title: title,
          desc: desc,
          badge: badge,
          badgeColor: c));
    }
    if (feed.isEmpty) {
      return const SizedBox.shrink();
    }
    return _Timeline(items: feed);
  }

  Widget _sectionTitle(String key, {required String fallback}) {
    return Text(
        (_lang.t(key) == key ? fallback : _lang.t(key)).toUpperCase(),
        style: TextStyle(
            fontSize: 9,
            fontWeight: FontWeight.w600,
            letterSpacing: 2.5,
            color: AppTheme.textMuted));
  }

  String _relTime(DateTime? t) {
    if (t == null) return 'recently';
    final diff = DateTime.now().difference(t);
    if (diff.inMinutes < 60) return '${diff.inMinutes} min ago';
    if (diff.inHours < 24) return '${diff.inHours} hour${diff.inHours == 1 ? "" : "s"} ago';
    if (diff.inDays == 1) return 'Yesterday';
    return '${diff.inDays} days ago';
  }
}

// ════════════════════════════════════════════════════════════════════
// REUSABLE TILES
// ════════════════════════════════════════════════════════════════════

class _StatTile extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String value;
  final Color? valueColor;
  final String label;
  const _StatTile({
    required this.icon,
    required this.color,
    required this.value,
    required this.label,
    this.valueColor,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(
        color: AppTheme.cardBg,
        borderRadius: BorderRadius.circular(12),
        boxShadow: AppTheme.cardShadow,
      ),
      child: Stack(children: [
        // Left accent bar
        Positioned(
          left: -14, top: -14, bottom: -14,
          child: Container(
            width: 3,
            decoration: BoxDecoration(
              color: color,
              borderRadius: const BorderRadius.only(
                topRight: Radius.circular(2),
                bottomRight: Radius.circular(2),
              ),
            ),
          ),
        ),
        Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Container(
            width: 28, height: 28,
            decoration: BoxDecoration(
                color: color.withOpacity(0.1),
                borderRadius: BorderRadius.circular(8)),
            child: Icon(icon, size: 14, color: color),
          ),
          const SizedBox(height: 8),
          Text(value,
              style: GoogleFonts.playfairDisplay(
                  fontSize: 22,
                  fontWeight: FontWeight.w600,
                  color: valueColor ?? AppTheme.textPrimary,
                  height: 1)),
          const SizedBox(height: 3),
          Text(label.toUpperCase(),
              style: TextStyle(
                  fontSize: 8,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 1.8,
                  color: AppTheme.textMuted)),
        ]),
      ]),
    );
  }
}

class _QuickAction extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String label;
  final Color? tintBg;
  const _QuickAction({
    required this.icon,
    required this.color,
    required this.label,
    this.tintBg,
  });

  @override
  Widget build(BuildContext context) {
    final bg = (tintBg ?? color).withOpacity(0.07);
    return Material(
      color: Colors.transparent,
      child: InkWell(
        onTap: () {}, // TODO: route to corresponding screen
        borderRadius: BorderRadius.circular(10),
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 14, horizontal: 6),
          decoration: BoxDecoration(
            color: bg,
            borderRadius: BorderRadius.circular(10),
          ),
          child: Column(children: [
            Icon(icon, size: 18, color: color),
            const SizedBox(height: 4),
            Text(label.toUpperCase(),
                style: TextStyle(
                    fontSize: 8,
                    fontWeight: FontWeight.w600,
                    letterSpacing: 0.8,
                    color: color)),
          ]),
        ),
      ),
    );
  }
}

class _TaskItem extends StatelessWidget {
  final String title;
  final String subtitle;
  final String badgeText;
  final Color badgeColor;
  const _TaskItem({
    required this.title,
    required this.subtitle,
    required this.badgeText,
    required this.badgeColor,
  });

  @override
  Widget build(BuildContext context) {
    return Container(
      margin: const EdgeInsets.only(bottom: 6),
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 10),
      decoration: BoxDecoration(
        color: AppTheme.cardBg,
        borderRadius: BorderRadius.circular(10),
        boxShadow: AppTheme.cardShadow,
      ),
      child: Row(children: [
        Container(
          width: 18, height: 18,
          decoration: BoxDecoration(
            border: Border.all(color: AppTheme.accent, width: 2),
            borderRadius: BorderRadius.circular(5),
          ),
        ),
        const SizedBox(width: 10),
        Expanded(
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(title,
                style: AppTheme.bodyMedium
                    .copyWith(fontSize: 11, fontWeight: FontWeight.w600)),
            Text(subtitle,
                style: AppTheme.bodySmall.copyWith(fontSize: 9)),
          ]),
        ),
        Container(
          padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
          decoration: BoxDecoration(
            color: badgeColor.withOpacity(0.1),
            borderRadius: BorderRadius.circular(6),
          ),
          child: Text(badgeText.toUpperCase(),
              style: TextStyle(
                  fontSize: 7,
                  fontWeight: FontWeight.w600,
                  letterSpacing: 0.8,
                  color: badgeColor)),
        ),
      ]),
    );
  }
}

class _FeedItem {
  final Color color;
  final String time;
  final String title;
  final String desc;
  final String badge;
  final Color badgeColor;
  _FeedItem({
    required this.color,
    required this.time,
    required this.title,
    required this.desc,
    required this.badge,
    required this.badgeColor,
  });
}

class _Timeline extends StatelessWidget {
  final List<_FeedItem> items;
  const _Timeline({required this.items});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.only(left: 22),
      child: Stack(children: [
        // Vertical line
        Positioned(
          left: -16, top: 4, bottom: 4,
          child: Container(width: 1.5, color: const Color(0xFFEEEEEE)),
        ),
        Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: items.map((it) {
            return Padding(
              padding: const EdgeInsets.only(bottom: 14),
              child: Stack(clipBehavior: Clip.none, children: [
                // Dot
                Positioned(
                  left: -19, top: 4,
                  child: Container(
                    width: 10, height: 10,
                    decoration: BoxDecoration(
                      color: it.color,
                      shape: BoxShape.circle,
                      border: Border.all(color: Colors.white, width: 2),
                      boxShadow: [
                        BoxShadow(
                            color: Colors.black.withOpacity(0.15),
                            blurRadius: 0,
                            spreadRadius: 1)
                      ],
                    ),
                  ),
                ),
                Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(it.time,
                      style: TextStyle(
                          fontSize: 8,
                          letterSpacing: 0.5,
                          color: AppTheme.textMuted)),
                  const SizedBox(height: 3),
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 10),
                    decoration: BoxDecoration(
                      color: AppTheme.cardBg,
                      borderRadius: BorderRadius.circular(10),
                      boxShadow: AppTheme.cardShadow,
                    ),
                    child: Column(
                        crossAxisAlignment: CrossAxisAlignment.start,
                        children: [
                          Text(it.title,
                              style: AppTheme.bodyMedium.copyWith(
                                  fontSize: 11, fontWeight: FontWeight.w600)),
                          const SizedBox(height: 1),
                          Text(it.desc,
                              style: AppTheme.bodySmall.copyWith(fontSize: 9),
                              maxLines: 2,
                              overflow: TextOverflow.ellipsis),
                          const SizedBox(height: 4),
                          Container(
                            padding: const EdgeInsets.symmetric(
                                horizontal: 7, vertical: 2),
                            decoration: BoxDecoration(
                              color: it.badgeColor.withOpacity(0.1),
                              borderRadius: BorderRadius.circular(4),
                            ),
                            child: Text(it.badge.toUpperCase(),
                                style: TextStyle(
                                    fontSize: 7,
                                    fontWeight: FontWeight.w600,
                                    letterSpacing: 0.8,
                                    color: it.badgeColor)),
                          ),
                        ]),
                  ),
                ]),
              ]),
            );
          }).toList(),
        ),
      ]),
    );
  }
}
