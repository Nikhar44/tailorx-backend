import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/models.dart';
import '../services/api_service.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import '../utils/privacy_helper.dart';
import '../widgets/common_widgets.dart';

class DashboardScreen extends StatefulWidget {
  final Function(int)? onNavigate;
  const DashboardScreen({super.key, this.onNavigate});
  @override
  State<DashboardScreen> createState() => DashboardScreenState();
}

class DashboardScreenState extends State<DashboardScreen> with SingleTickerProviderStateMixin {
  final _api = Api(); final _lang = AppLang();
  DashboardData? _d; bool _loading = true; String? _err;
  final _fmt = NumberFormat.currency(locale: 'en_IN', symbol: '\u20B9', decimalDigits: 0);
  late AnimationController _anim;

  @override
  void initState() { super.initState();
    _anim = AnimationController(vsync: this, duration: const Duration(milliseconds: 1000));
    _load();
  }
  @override void dispose() { _anim.dispose(); super.dispose(); }

  Future<void> refresh() => _load();

  Future<void> _load() async {
    setState(() { _loading = true; _err = null; });
    try { final d = await _api.getDashboard();
      if (mounted) { setState(() => _d = d); _anim.forward(from: 0); }
    } catch (e) { if (mounted) setState(() => _err = e.toString()); }
    finally { if (mounted) setState(() => _loading = false); }
  }

  void _showNotifySheet() {
    final readyOrders = _d?.recentOrders.where((o) => o.stage == 'Ready').toList() ?? [];
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      isScrollControlled: true,
      builder: (ctx) => T.sheetScaffold(ctx, heightFraction: 0.7, child: Column(children: [
          const SizedBox(height: 12),
          Container(width: 36, height: 4, decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2))),
          Padding(padding: const EdgeInsets.all(20), child: Row(children: [
            Text('Ready for Pickup', style: T.displaySm),
            const Spacer(),
            Text('${readyOrders.length} orders', style: T.bodySm),
          ])),
          Expanded(
            child: readyOrders.isEmpty
                ? Center(child: Text('No orders are ready for pickup', style: T.bodySm))
                : ListView.builder(
                    padding: const EdgeInsets.symmetric(horizontal: 16),
                    itemCount: readyOrders.length,
                    itemBuilder: (ctx, i) {
                      final o = readyOrders[i];
                      return Container(
                        margin: const EdgeInsets.only(bottom: 8),
                        padding: const EdgeInsets.all(12),
                        decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(12), boxShadow: T.shadowCard),
                        child: Row(children: [
                          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            Text(o.customerName ?? 'Customer', style: T.body.copyWith(fontWeight: FontWeight.w600)),
                            Text(o.description, style: T.bodySm.copyWith(fontSize: 14)),
                          ])),
                          IconButton(
                            icon: const Icon(Icons.chat_rounded, color: Color(0xFF25D366)),
                            onPressed: () {
                              final msg = "Hi ${o.customerName}, your ${o.description} is ready for pickup at ${_api.boutiqueName}! Please visit us. Thank you!";
                              launchUrl(Uri.parse('https://wa.me/91${o.customerPhone ?? ""}?text=${Uri.encodeComponent(msg)}'),
                                  mode: LaunchMode.externalApplication);
                            },
                          ),
                        ]),
                      );
                    },
                  ),
          ),
        ]),
      ),
    );
  }

  Widget _stagger(int i, Widget child) => FadeTransition(
    opacity: CurvedAnimation(parent: _anim,
      curve: Interval(i * 0.08, (i * 0.08 + 0.4).clamp(0, 1), curve: Curves.easeOut)),
    child: SlideTransition(
      position: Tween(begin: const Offset(0, 0.06), end: Offset.zero).animate(
        CurvedAnimation(parent: _anim,
          curve: Interval(i * 0.08, (i * 0.08 + 0.4).clamp(0, 1), curve: Curves.easeOut))),
      child: child));

  @override
  Widget build(BuildContext context) {
    if (_loading) {
      return Center(child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          const CircularProgressIndicator(strokeWidth: 1.5, color: T.accent),
          const SizedBox(height: 20),
          Text('Waking up server...', style: T.bodySm),
        ],
      ));
    }
    if (_err != null) return EmptyState(icon: Icons.cloud_off_rounded, title: _lang.t('connection_error'),
      subtitle: _lang.t('server_waking'), buttonLabel: _lang.t('retry'), onPressed: _load);
    final d = _d!;

    // ── Responsive breakpoints ───────────────────────────────────────────────
    final sw = MediaQuery.of(context).size.width;
    final isTablet     = sw >= 600;   // iPad mini, small tablets
    final isLargeTablet = sw >= 900;  // iPad Pro, large tablets
    final hPad = isLargeTablet ? 32.0 : isTablet ? 24.0 : 18.0;
    final gap  = isTablet ? 12.0 : 8.0;

    // Build pipeline counts from orders
    final pipeline = <String, int>{'Received': 0, 'Cutting': 0, 'Stitching': 0, 'Trial': 0, 'Ready': 0};
    for (final o in d.recentOrders) {
      final s = o.stage;
      if (pipeline.containsKey(s)) pipeline[s] = pipeline[s]! + 1;
    }

    // Dynamic Tasks — driven by today's trial date / delivery date / pending payments
    final tasks = <_Task>[];
    for (final t in d.todayTasks) {
      switch (t.type) {
        case 'Trial':
          tasks.add(_Task(id: t.id, title: t.title, sub: t.sub, badge: 'Trial', color: T.teal, type: 'Trial'));
          break;
        case 'Delivery':
          tasks.add(_Task(id: t.id, title: t.title, sub: t.sub, badge: 'Ready', color: T.success, type: 'Ready'));
          break;
        case 'Payment':
          tasks.add(_Task(id: t.id, title: t.title, sub: t.sub, badge: 'Due', color: T.danger, type: 'Payment', balanceAmt: _fmt.format(t.balance)));
          break;
      }
    }

    // ── Shared section builders ──────────────────────────────────────────────
    Widget statGrid() => GridView.count(
      crossAxisCount: isTablet ? 4 : 2,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      crossAxisSpacing: gap, mainAxisSpacing: gap,
      childAspectRatio: isLargeTablet ? 2.0 : isTablet ? 1.7 : 1.4,
      children: [
        GestureDetector(onTap: () => widget.onNavigate?.call(1),
          child: StatCard(label: _lang.t('total_customers'), value: d.totalCustomers.toString(),
            icon: Icons.people_rounded, color: T.info, isPrivate: true)),
        GestureDetector(onTap: () => widget.onNavigate?.call(2),
          child: StatCard(label: 'Active Orders', value: d.pendingOrders.toString(),
            icon: Icons.receipt_long_rounded, color: T.purple, isPrivate: true)),
        GestureDetector(onTap: () => widget.onNavigate?.call(3),
          child: StatCard(label: _lang.t('revenue'), value: _fmt.format(d.totalRevenue),
            icon: Icons.trending_up_rounded, color: T.success, isPrivate: true)),
        GestureDetector(onTap: () => widget.onNavigate?.call(3),
          child: StatCard(label: _lang.t('pending'), value: _fmt.format(d.pendingPayments),
            icon: Icons.schedule_rounded, color: T.warning, isPrivate: true)),
      ]);

    Widget quickActions() => IntrinsicHeight(
      child: Row(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
        _QuickBtn(icon: Icons.person_add_rounded, label: _lang.t('new_customer'),
          color: T.info, bg: T.info.withOpacity(0.07), isTablet: isTablet,
          onTap: () => widget.onNavigate?.call(1)),
        SizedBox(width: gap),
        _QuickBtn(icon: Icons.content_cut_rounded, label: _lang.t('new_order'),
          color: T.success, bg: T.success.withOpacity(0.07), isTablet: isTablet,
          onTap: () => widget.onNavigate?.call(2)),
        SizedBox(width: gap),
        _QuickBtn(icon: Icons.receipt_rounded, label: 'Invoice',
          color: T.accentDark, bg: T.accent.withOpacity(0.1), isTablet: isTablet,
          onTap: () => widget.onNavigate?.call(3)),
        SizedBox(width: gap),
        _QuickBtn(icon: Icons.send_rounded, label: 'Notify',
          color: T.purple, bg: T.purple.withOpacity(0.07), isTablet: isTablet,
          onTap: _showNotifySheet),
      ]));

    Widget monthlyCard() => Container(
      margin: const EdgeInsets.only(top: 4),
      padding: EdgeInsets.all(isTablet ? 20 : 16),
      decoration: BoxDecoration(
        gradient: const LinearGradient(colors: [Color(0xFF1C1C1C), Color(0xFF2A2A3A)]),
        borderRadius: BorderRadius.circular(14)),
      child: Column(children: [
        Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
          Text('MONTHLY COLLECTION', style: TextStyle(
            fontSize: isTablet ? 13 : 12, letterSpacing: 2, fontWeight: FontWeight.w800,
            color: Colors.white.withOpacity(0.5))),
          PrivacyText('${((d.totalRevenue/500000)*100).toInt()}%', style: GoogleFonts.prata(
            fontSize: isTablet ? 48 : 40, fontWeight: FontWeight.w400, color: T.accent)),
        ]),
        const SizedBox(height: 10),
        ClipRRect(borderRadius: BorderRadius.circular(4),
          child: LinearProgressIndicator(value: (d.totalRevenue/500000).clamp(0, 1), minHeight: 6,
            backgroundColor: Colors.white.withOpacity(0.1), color: T.accent)),
        const SizedBox(height: 8),
        PrivacyText('${_fmt.format(d.totalRevenue)} of ${_fmt.format(500000)} target', style: TextStyle(
          fontSize: isTablet ? 13 : 12, fontWeight: FontWeight.w500, color: Colors.white.withOpacity(0.4))),
      ]));

    Widget todayTasks() => tasks.isEmpty
      ? Center(child: Padding(padding: const EdgeInsets.symmetric(vertical: 20),
          child: Text('No tasks for today', style: T.bodySm)))
      : Column(children: tasks.take(5).map((t) => _TaskCard(
          title: t.title, sub: t.sub, badge: t.badge, badgeColor: t.color, balanceAmt: t.balanceAmt,
          onDone: () async {
            final nextStage = t.type == 'Trial' ? 'Ready' : 'Delivered';
            try {
              await _api.updateOrderStatus(t.id, nextStage);
              _load();
              if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('Order marked as $nextStage')));
            } catch (e) {
              if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
            }
          })).toList());

    return RefreshIndicator(onRefresh: _load, color: T.accent,
      child: ListView(padding: EdgeInsets.fromLTRB(hPad, 16, hPad, 32), children: [

        // ═══ 1. STAT CARDS ═══
        _stagger(0, statGrid()),

        // ═══ 2. ORDER PIPELINE ═══
        _stagger(1, SecTitle(title: 'Order Pipeline', action: 'View All', onAction: () => widget.onNavigate?.call(2))),
        _stagger(2, PipelineBar(stages: pipeline)),

        // ═══ 3. QUICK ACTIONS ═══
        _stagger(3, const SecTitle(title: 'Quick Actions')),
        _stagger(4, quickActions()),

        // ═══ TABLET: Monthly + Tasks side by side ═══
        if (isLargeTablet) ...[
          _stagger(5, Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Expanded(flex: 5, child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              const SecTitle(title: 'Monthly Collection'),
              monthlyCard(),
            ])),
            SizedBox(width: gap * 2),
            Expanded(flex: 7, child: Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              const SecTitle(title: "Today's Tasks"),
              todayTasks(),
            ])),
          ])),
          _stagger(6, SecTitle(title: 'Activity Feed', action: 'Orders', onAction: () => widget.onNavigate?.call(2))),
          _stagger(7, _ActivityFeed(orders: d.recentOrders, fmt: _fmt, onOrderTap: () => widget.onNavigate?.call(2), isTablet: true)),
        ]

        // ═══ PHONE / SMALL TABLET: Single column ═══
        else ...[
          _stagger(5, Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            const SecTitle(title: 'Monthly Collection'),
            monthlyCard(),
          ])),
          _stagger(6, const SecTitle(title: "Today's Tasks")),
          _stagger(7, todayTasks()),
          _stagger(8, SecTitle(title: 'Activity Feed', action: 'Orders', onAction: () => widget.onNavigate?.call(2))),
          _stagger(9, _ActivityFeed(orders: d.recentOrders, fmt: _fmt, onOrderTap: () => widget.onNavigate?.call(2))),
        ],
      ]),
    );
  }
}

class _Task {
  final String id; final String title, sub, badge, type; final Color color;
  final String? balanceAmt; // non-null for payment tasks — shown with privacy mask
  _Task({required this.id, required this.title, required this.sub, required this.badge, required this.color, required this.type, this.balanceAmt});
}

class _QuickBtn extends StatelessWidget {
  final IconData icon; final String label; final Color color, bg;
  final VoidCallback? onTap; final bool isTablet;
  const _QuickBtn({required this.icon, required this.label, required this.color,
    required this.bg, this.onTap, this.isTablet = false});

  @override
  Widget build(BuildContext context) => Expanded(
    child: InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(12),
      child: Container(
        // Fixed vertical padding — IntrinsicHeight in the parent makes all equal height
        padding: EdgeInsets.symmetric(vertical: isTablet ? 20 : 14, horizontal: 4),
        decoration: BoxDecoration(color: bg, borderRadius: BorderRadius.circular(12)),
        child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
          Icon(icon, size: isTablet ? 30 : 24, color: color),
          SizedBox(height: isTablet ? 8 : 5),
          // FittedBox scales text down if it doesn't fit — prevents overflow & unequal heights
          FittedBox(
            fit: BoxFit.scaleDown,
            child: Text(
              label.toUpperCase(),
              style: TextStyle(
                fontSize: isTablet ? 13 : 11,
                fontWeight: FontWeight.w700,
                letterSpacing: 0.5,
                color: color),
              textAlign: TextAlign.center,
              maxLines: 1,
            ),
          ),
        ]),
      ),
    ),
  );
}

class _TaskCard extends StatelessWidget {
  final String title, sub, badge; final Color badgeColor; final bool done;
  final VoidCallback? onDone;
  final String? balanceAmt; // when non-null, shows privacy-masked amount
  const _TaskCard({required this.title, required this.sub, required this.badge,
    required this.badgeColor, this.done = false, this.onDone, this.balanceAmt});
  @override
  Widget build(BuildContext context) => Container(
    margin: const EdgeInsets.only(bottom: 6),
    padding: const EdgeInsets.all(10),
    decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(10), boxShadow: T.shadowCard),
    child: Row(children: [
      InkWell(
        onTap: onDone,
        child: Container(width: 18, height: 18,
          decoration: BoxDecoration(border: Border.all(color: T.accent, width: 2), borderRadius: BorderRadius.circular(5)),
          child: done ? const Icon(Icons.check, size: 12, color: T.accent) : null),
      ),
      const SizedBox(width: 12),
      Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Text(title, style: T.body.copyWith(fontWeight: FontWeight.w700, fontSize: 16)),
        if (balanceAmt != null)
          Row(children: [
            PrivacyText(balanceAmt!, style: T.bodySm.copyWith(fontSize: 14, color: T.danger, fontWeight: FontWeight.w600)),
            Text(' pending', style: T.bodySm.copyWith(fontSize: 14)),
          ])
        else
          Text(sub, style: T.bodySm.copyWith(fontSize: 14)),
      ])),
      Container(padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
        decoration: BoxDecoration(color: badgeColor.withOpacity(0.1), borderRadius: BorderRadius.circular(6)),
        child: Text(badge.toUpperCase(), style: TextStyle(
          fontSize: 12, fontWeight: FontWeight.w700, letterSpacing: 0.8, color: badgeColor))),
    ]),
  );
}

class _ActivityFeed extends StatelessWidget {
  final List<Order> orders; final NumberFormat fmt;
  final VoidCallback? onOrderTap; final bool isTablet;
  const _ActivityFeed({required this.orders, required this.fmt, this.onOrderTap, this.isTablet = false});
  String _timeAgo(String? iso) {
    if (iso == null) return '';
    final dt = DateTime.tryParse(iso);
    if (dt == null) return '';
    final diff = DateTime.now().toUtc().difference(dt.toUtc());
    if (diff.inSeconds < 60) return 'Just now';
    if (diff.inMinutes < 60) return '${diff.inMinutes} min${diff.inMinutes == 1 ? '' : 's'} ago';
    if (diff.inHours < 24) return '${diff.inHours} hour${diff.inHours == 1 ? '' : 's'} ago';
    if (diff.inDays == 1) return 'Yesterday';
    if (diff.inDays < 7) return '${diff.inDays} days ago';
    return DateFormat('dd MMM yyyy').format(dt.toLocal());
  }

  Widget _feedItem(Order o, int i) {
    final c = T.stageColor(o.stage);
    return Padding(padding: const EdgeInsets.only(bottom: 14),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Transform.translate(offset: const Offset(-25, 4),
          child: Container(width: 10, height: 10,
            decoration: BoxDecoration(color: c, shape: BoxShape.circle,
              border: Border.all(color: T.card, width: 2)))),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(_timeAgo(o.updatedAt ?? o.createdAt),
            style: T.bodySm.copyWith(fontSize: 12, color: T.text3, fontWeight: FontWeight.w600)),
          const SizedBox(height: 4),
          InkWell(onTap: onOrderTap, borderRadius: BorderRadius.circular(10),
            child: Container(padding: const EdgeInsets.all(12),
              decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(10), boxShadow: T.shadowCard),
              child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text(o.customerName ?? 'Order', style: T.body.copyWith(fontWeight: FontWeight.w700, fontSize: 16)),
                Text(o.description, style: T.bodySm.copyWith(fontSize: 14)),
                const SizedBox(height: 6),
                Container(padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 3),
                  decoration: BoxDecoration(color: c.withOpacity(0.1), borderRadius: BorderRadius.circular(6)),
                  child: Text(o.stage.toUpperCase(), style: TextStyle(
                    fontSize: 12, fontWeight: FontWeight.w700, letterSpacing: 0.8, color: c))),
              ]))),
        ])),
      ]));
  }

  @override
  Widget build(BuildContext context) {
    // On large tablets show 2 columns of feed items
    final take = isTablet ? orders.take(8).toList() : orders.take(4).toList();
    if (isTablet && take.length > 1) {
      final left  = take.asMap().entries.where((e) => e.key.isEven).toList();
      final right = take.asMap().entries.where((e) => e.key.isOdd).toList();
      return Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        Expanded(child: Container(padding: const EdgeInsets.only(left: 22),
          child: Stack(children: [
            Positioned(left: 0, top: 4, bottom: 4, child: Container(width: 1.5, color: T.border)),
            Column(children: left.map((e) => _feedItem(e.value, e.key * 2)).toList()),
          ]))),
        const SizedBox(width: 16),
        Expanded(child: Container(padding: const EdgeInsets.only(left: 22),
          child: Stack(children: [
            Positioned(left: 0, top: 4, bottom: 4, child: Container(width: 1.5, color: T.border)),
            Column(children: right.map((e) => _feedItem(e.value, e.key * 2 + 1)).toList()),
          ]))),
      ]);
    }
    return Container(
      padding: const EdgeInsets.only(left: 22),
      child: Stack(children: [
        Positioned(left: 0, top: 4, bottom: 4, child: Container(width: 1.5, color: T.border)),
        Column(children: take.asMap().entries.map((e) => _feedItem(e.value, e.key)).toList()),
      ]),
    );
  }
}
