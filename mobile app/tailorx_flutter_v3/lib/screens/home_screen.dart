import 'package:flutter/material.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/models.dart';
import '../services/api_service.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import '../utils/privacy_helper.dart';
import '../widgets/common_widgets.dart';
import 'dashboard_screen.dart';
import 'customers_screen.dart';
import 'orders_screen.dart';
import 'invoices_screen.dart';
import 'settings_screen.dart';

class HomeScreen extends StatefulWidget {
  const HomeScreen({super.key});
  @override
  State<HomeScreen> createState() => _HomeScreenState();
}

class _HomeScreenState extends State<HomeScreen> with WidgetsBindingObserver {
  int _idx = 0;
  final _api = Api();
  final _lang = AppLang();
  bool _searchMode = false;
  final _searchCtrl = TextEditingController();
  Customer? _preselectedCustomer;
  List<AppNotification> _notifs = [];

  final _dashKey = GlobalKey<DashboardScreenState>();
  final _custKey = GlobalKey<CustomersScreenState>();
  final _ordRefreshNotifier = ValueNotifier<int>(0);
  final _invKey = GlobalKey<InvoicesScreenState>();

  @override
  void initState() {
    super.initState();
    WidgetsBinding.instance.addObserver(this);
    _lang.addListener(_onLangChange);
    _loadNotifs();
  }

  @override
  void dispose() {
    WidgetsBinding.instance.removeObserver(this);
    _lang.removeListener(_onLangChange);
    _ordRefreshNotifier.dispose();
    _searchCtrl.dispose();
    super.dispose();
  }

  @override
  void didChangeAppLifecycleState(AppLifecycleState state) {
    // Lock sensitive values whenever the app leaves the foreground
    if (state == AppLifecycleState.paused ||
        state == AppLifecycleState.inactive ||
        state == AppLifecycleState.hidden) {
      PrivacyHelper.lock();
    }
  }

  void _onLangChange() { if (mounted) setState(() {}); }

  Future<void> _loadNotifs() async {
    try {
      final orders = await _api.getOrders();
      final invoices = await _api.getInvoices();
      final now = DateTime.now();
      final today = DateTime(now.year, now.month, now.day);
      
      final List<AppNotification> list = [];

      for (var o in orders) {
        if (o.dueDate != null) {
          final due = DateTime.parse(o.dueDate!);
          if (due.isAtSameMomentAs(today)) {
            list.add(AppNotification(
              id: 'due_${o.id}', title: 'Delivery Due Today',
              body: '${o.customerName}\'s ${o.description} is scheduled for today.',
              type: 'due', time: 'Today', icon: Icons.timer_rounded, color: T.warning, data: o
            ));
          }
        }
        if (o.stage == 'Ready') {
          list.add(AppNotification(
            id: 'pickup_${o.id}', title: 'Ready for Pickup',
            body: '${o.customerName}\'s order is ready since ${o.createdAt?.split('T').first ?? "few days"}.',
            type: 'pickup', time: 'Pending', icon: Icons.shopping_bag_rounded, color: T.success, data: o
          ));
        }
      }

      for (var inv in invoices) {
        if (inv.dueAmount > 0 && inv.status != 'paid') {
          list.add(AppNotification(
            id: 'pay_${inv.id}', title: 'Payment Pending',
            body: '₹${inv.dueAmount} due from ${inv.customerName}.',
            type: 'payment', time: 'Overdue', icon: Icons.payments_rounded, color: T.danger, data: inv
          ));
        }
      }

      if (mounted) setState(() => _notifs = list);
    } catch (_) {}
  }

  void _navigateToOrders({Customer? customer}) {
    setState(() {
      _idx = 2;
      _preselectedCustomer = customer;
    });
    // The OrdersScreen will handle opening the form in its didUpdateWidget/initState
  }

  String get _title {
    final k = ['dashboard', 'customers', 'orders', 'invoices', 'settings'];
    return _lang.t(k[_idx]);
  }

  void _showSearchResults(String query) {
    showModalBottomSheet(context: context, isScrollControlled: true, backgroundColor: Colors.transparent,
      builder: (ctx) => Container(
        height: MediaQuery.of(ctx).size.height * 0.85,
        decoration: BoxDecoration(color: T.bg, borderRadius: const BorderRadius.vertical(top: Radius.circular(28))),
        child: Column(children: [
          const SizedBox(height: 12),
          Container(width: 36, height: 4, decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2))),
          Padding(padding: const EdgeInsets.all(20), child: Row(children: [
            Text('Results for "$query"', style: T.displaySm),
            const Spacer(),
            IconButton(icon: const Icon(Icons.close_rounded), onPressed: () => Navigator.pop(ctx)),
          ])),
          Expanded(child: _SearchBody(query: query)),
        ]),
      ),
    );
  }

  // ─── Trial status banner ────────────────────────────────────────
  Widget _buildTrialBanner() {
    final plan     = _api.boutiquePlan;
    final daysLeft = _api.trialDaysRemaining;
    final isTrial  = plan == 'trial';
    final isExpired = isTrial && daysLeft <= 0;

    // Only show for trial users (not paid, not free accounts)
    if (!isTrial) return const SizedBox.shrink();

    final isUrgent = daysLeft <= 5;

    return GestureDetector(
      onTap: () => setState(() => _idx = 4), // go to Settings tab
      child: Container(
        width: double.infinity,
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
        decoration: BoxDecoration(
          color: isExpired
              ? T.danger
              : isUrgent
                  ? const Color(0xFFD97706)   // amber-600
                  : const Color(0xFF2D1B69),   // deep purple — calm trial
        ),
        child: Row(children: [
          Icon(
            isExpired ? Icons.lock_rounded : Icons.hourglass_top_rounded,
            size: 15, color: Colors.white),
          const SizedBox(width: 8),
          Expanded(
            child: Text(
              isExpired
                  ? 'Your free trial has ended — tap to upgrade'
                  : 'Free Trial: $daysLeft day${daysLeft == 1 ? '' : 's'} remaining',
              style: const TextStyle(
                fontSize: 13, fontWeight: FontWeight.w600, color: Colors.white),
            ),
          ),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.2),
              borderRadius: BorderRadius.circular(6)),
            child: const Text('Upgrade',
              style: TextStyle(
                fontSize: 12, fontWeight: FontWeight.w700, color: Colors.white)),
          ),
        ]),
      ),
    );
  }

  Widget _buildBody() {
    // Block entire app if trial has expired
    final plan      = _api.boutiquePlan;
    final daysLeft  = _api.trialDaysRemaining;
    final isExpired = plan == 'trial' && daysLeft <= 0;
    if (isExpired) return const _PlanExpiredScreen();

    return IndexedStack(
      index: _idx,
      children: [
        DashboardScreen(key: _dashKey, onNavigate: (i) {
          setState(() => _idx = i);
          _refreshTab(i);
        }),
        CustomersScreen(key: _custKey, onNewOrder: (c) => _navigateToOrders(customer: c)),
        OrdersScreen(
          initialCustomer: _preselectedCustomer,
          onHandled: () => setState(() => _preselectedCustomer = null),
          refreshNotifier: _ordRefreshNotifier,
          onCreateInvoice: (order) {
            // Switch to Invoices tab, then open pre-filled invoice form
            setState(() => _idx = 3);
            _invKey.currentState?.createInvoiceForOrder(order);
          },
        ),
        InvoicesScreen(key: _invKey),
        const SettingsScreen(),
      ],
    );
  }

  void _refreshTab(int i) {
    switch (i) {
      case 0: _dashKey.currentState?.refresh(); break;
      case 1: _custKey.currentState?.refresh(); break;
      case 2: _ordRefreshNotifier.value++; break;
      case 3: _invKey.currentState?.refresh(); break;
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(
        flexibleSpace: Container(decoration: const BoxDecoration(gradient: T.headerGrad)),
        title: _searchMode
            ? TextField(controller: _searchCtrl, autofocus: true,
                style: const TextStyle(color: T.headerText, fontSize: 18),
                decoration: InputDecoration(
                  hintText: '${_lang.t("search")}...',
                  hintStyle: TextStyle(color: Colors.white.withOpacity(0.4), fontSize: 18),
                  border: InputBorder.none, filled: false),
                onSubmitted: (q) {
                  if (q.trim().isEmpty) return;
                  setState(() => _searchMode = false);
                  _searchCtrl.clear();
                  _showSearchResults(q.trim());
                })
            : _idx == 0
                ? Row(children: [
                    Container(width: 40, height: 40,
                      decoration: BoxDecoration(borderRadius: BorderRadius.circular(8), gradient: T.accentGrad),
                      child: const Center(child: Text('TX', style: TextStyle(
                        fontSize: 14, fontWeight: FontWeight.w800, color: T.headerDark, letterSpacing: 1)))),
                    const SizedBox(width: 10),
                    Expanded(child: Text(_api.boutiqueName ?? 'TAILORX',
                      style: const TextStyle(fontSize: 20, fontWeight: FontWeight.w600,
                        color: T.headerText, letterSpacing: 0.5), overflow: TextOverflow.ellipsis)),
                  ])
                : Text(_title),
        actions: [
          // Eye icon — only on screens that have sensitive numbers
          if ([0, 1, 3].contains(_idx))
            ValueListenableBuilder<bool>(
              valueListenable: PrivacyHelper.isUnlocked,
              builder: (_, unlocked, __) => IconButton(
                icon: Icon(
                  unlocked ? Icons.visibility_rounded : Icons.visibility_off_rounded,
                  size: 22, color: T.headerText,
                ),
                tooltip: unlocked ? 'Hide numbers' : 'Show numbers',
                onPressed: PrivacyHelper.toggle,
              ),
            ),
          IconButton(icon: Icon(_searchMode ? Icons.close_rounded : Icons.search_rounded,
            size: 24, color: T.headerText),
            onPressed: () => setState(() { _searchMode = !_searchMode; if (!_searchMode) _searchCtrl.clear(); })),
          Stack(children: [
            IconButton(icon: const Icon(Icons.notifications_outlined, size: 24, color: T.headerText),
              onPressed: _showNotif),
            if (_notifs.isNotEmpty)
              Positioned(right: 8, top: 8, child: Container(width: 8, height: 8,
                decoration: BoxDecoration(color: T.accent, shape: BoxShape.circle,
                  border: Border.all(color: T.headerDark, width: 1.5)))),
          ]),
        ],
      ),
      body: Builder(builder: (ctx) {
        final isTablet = T.isTablet(ctx);
        return Column(
          children: [
            _buildTrialBanner(),
            Expanded(
              child: isTablet
                  ? Row(children: [
                      _buildNavRail(),
                      VerticalDivider(width: 1, thickness: 1, color: T.border),
                      Expanded(child: _buildBody()),
                    ])
                  : _buildBody(),
            ),
          ],
        );
      }),
      bottomNavigationBar: T.isTablet(context) ? null : Container(
        decoration: BoxDecoration(color: T.card,
          boxShadow: [BoxShadow(color: Colors.black.withOpacity(0.06), blurRadius: 12, offset: const Offset(0, -4))]),
        child: SafeArea(child: Padding(padding: const EdgeInsets.symmetric(vertical: 6),
          child: Row(mainAxisAlignment: MainAxisAlignment.spaceAround, children: [
            _nav(0, Icons.dashboard_outlined, Icons.dashboard_rounded, _lang.t('dashboard')),
            _nav(1, Icons.people_outline, Icons.people_rounded, _lang.t('customers')),
            _nav(2, Icons.receipt_long_outlined, Icons.receipt_long_rounded, _lang.t('orders')),
            _nav(3, Icons.payments_outlined, Icons.payments_rounded, _lang.t('invoices')),
            _nav(4, Icons.settings_outlined, Icons.settings_rounded, _lang.t('settings')),
          ]))),
      ),
    );
  }

  Widget _buildNavRail() {
    return NavigationRail(
      selectedIndex: _idx,
      onDestinationSelected: (i) {
        setState(() => _idx = i);
        _refreshTab(i);
      },
      labelType: NavigationRailLabelType.all,
      backgroundColor: T.card,
      minWidth: 80,
      selectedIconTheme: const IconThemeData(color: T.headerDark, size: 26),
      unselectedIconTheme: const IconThemeData(color: T.text3, size: 24),
      selectedLabelTextStyle: const TextStyle(
          color: T.headerDark, fontWeight: FontWeight.w700, fontSize: 11),
      unselectedLabelTextStyle: const TextStyle(color: T.text3, fontSize: 11),
      leading: Padding(
        padding: const EdgeInsets.only(top: 8, bottom: 16),
        child: Container(
          width: 40, height: 40,
          decoration: BoxDecoration(borderRadius: BorderRadius.circular(8), gradient: T.accentGrad),
          child: const Center(child: Text('TX', style: TextStyle(
              fontSize: 13, fontWeight: FontWeight.w800, color: T.headerDark, letterSpacing: 1))),
        ),
      ),
      destinations: [
        NavigationRailDestination(
            icon: const Icon(Icons.dashboard_outlined),
            selectedIcon: const Icon(Icons.dashboard_rounded),
            label: Text(_lang.t('dashboard'))),
        NavigationRailDestination(
            icon: const Icon(Icons.people_outline),
            selectedIcon: const Icon(Icons.people_rounded),
            label: Text(_lang.t('customers'))),
        NavigationRailDestination(
            icon: const Icon(Icons.receipt_long_outlined),
            selectedIcon: const Icon(Icons.receipt_long_rounded),
            label: Text(_lang.t('orders'))),
        NavigationRailDestination(
            icon: const Icon(Icons.payments_outlined),
            selectedIcon: const Icon(Icons.payments_rounded),
            label: Text(_lang.t('invoices'))),
        NavigationRailDestination(
            icon: const Icon(Icons.settings_outlined),
            selectedIcon: const Icon(Icons.settings_rounded),
            label: Text(_lang.t('settings'))),
      ],
    );
  }

  Widget _nav(int i, IconData ic, IconData aic, String l) {
    final a = _idx == i;
    return GestureDetector(onTap: () {
      setState(() => _idx = i);
      _refreshTab(i);
    }, behavior: HitTestBehavior.opaque,
      child: AnimatedContainer(duration: const Duration(milliseconds: 200),
        padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
        decoration: a ? BoxDecoration(color: T.headerDark.withOpacity(0.08), borderRadius: BorderRadius.circular(12)) : null,
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Icon(a ? aic : ic, size: 24, color: a ? T.headerDark : T.text3),
          const SizedBox(height: 2),
          Text(l, style: TextStyle(fontSize: 12, fontWeight: a ? FontWeight.w600 : FontWeight.w400,
            color: a ? T.headerDark : T.text3)),
        ])));
  }

  void _showNotif() {
    showModalBottomSheet(context: context, isScrollControlled: true, backgroundColor: Colors.transparent,
      builder: (ctx) => Container(
        height: MediaQuery.of(ctx).size.height * 0.75,
        decoration: BoxDecoration(color: T.bg, borderRadius: const BorderRadius.vertical(top: Radius.circular(T.rXl))),
        child: Column(children: [
          const SizedBox(height: 12),
          Container(width: 36, height: 4, decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2))),
          Padding(padding: const EdgeInsets.all(20), child: Row(children: [
            Text('Smart Alerts', style: T.displaySm),
            const Spacer(),
            Text('${_notifs.length} active', style: T.bodySm),
          ])),
          Expanded(
            child: _notifs.isEmpty
              ? Center(child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                  Icon(Icons.notifications_none_rounded, size: 48, color: T.text3.withOpacity(0.4)),
                  const SizedBox(height: 12),
                  Text('All caught up!', style: T.bodySm),
                ]))
              : ListView.builder(
                  padding: const EdgeInsets.symmetric(horizontal: 16),
                  itemCount: _notifs.length,
                  itemBuilder: (ctx, i) {
                    final n = _notifs[i];
                    return Container(
                      margin: const EdgeInsets.only(bottom: 10),
                      padding: const EdgeInsets.all(16),
                      decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(16), boxShadow: T.shadowCard),
                      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
                        Container(width: 40, height: 40,
                          decoration: BoxDecoration(color: n.color.withOpacity(0.1), borderRadius: BorderRadius.circular(12)),
                          child: Icon(n.icon, size: 20, color: n.color)),
                        const SizedBox(width: 14),
                        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                          Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                            Text(n.title, style: T.body.copyWith(fontWeight: FontWeight.w700, fontSize: 16)),
                            Text(n.time, style: TextStyle(fontSize: 10, color: T.text3, fontWeight: FontWeight.w600)),
                          ]),
                          const SizedBox(height: 4),
                          Text(n.body, style: T.bodySm.copyWith(fontSize: 14)),
                          const SizedBox(height: 12),
                          Row(children: [
                            if (n.type == 'pickup' || n.type == 'payment' || n.type == 'due')
                              GestureDetector(
                                onTap: () {
                                  Navigator.pop(ctx);
                                  final name = n.data is Order ? n.data.customerName : (n.data as Invoice).customerName;
                                  final phone = n.data is Order ? n.data.customerPhone : (n.data as Invoice).customerPhone;
                                  final desc = n.data is Order ? n.data.description : (n.data as Invoice).garment;
                                  final msg = n.type == 'pickup' 
                                    ? "Hi $name, your $desc is ready at ${_api.boutiqueName}! Please visit us to collect. Thank you!"
                                    : n.type == 'payment'
                                      ? "Hi $name, a balance payment of ₹${(n.data as Invoice).dueAmount} is pending for your $desc. Requesting you to clear it. Thanks!"
                                      : "Hi $name, your $desc is due for delivery today at ${_api.boutiqueName}. We'll keep it ready! Thanks!";
                                  launchUrl(Uri.parse('https://wa.me/91${phone ?? ""}?text=${Uri.encodeComponent(msg)}'),
                                      mode: LaunchMode.externalApplication);
                                },
                                child: Container(padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                                  decoration: BoxDecoration(color: const Color(0xFF25D366).withOpacity(0.1), borderRadius: BorderRadius.circular(8)),
                                  child: Row(children: [
                                    const Icon(Icons.chat_rounded, size: 14, color: Color(0xFF25D366)),
                                    const SizedBox(width: 6),
                                    const Text('WhatsApp Reminder', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF075E54))),
                                  ])),
                              ),
                          ]),
                        ])),
                      ]),
                    );
                  },
                ),
          ),
        ]),
      ),
    );
  }
}

// ─── Plan Expired — full blocking screen ────────────────────────────────────
class _PlanExpiredScreen extends StatelessWidget {
  const _PlanExpiredScreen();

  void _contactUs() {
    launchUrl(
      Uri.parse(
        'https://wa.me/918469696966?text=${Uri.encodeComponent('Hi, my TailorX 15-day free trial has ended. I would like to renew my plan. Please help me.')}'),
      mode: LaunchMode.externalApplication,
    );
  }

  @override
  Widget build(BuildContext context) {
    return Container(
      width: double.infinity,
      height: double.infinity,
      decoration: const BoxDecoration(
        gradient: LinearGradient(
          begin: Alignment.topCenter,
          end: Alignment.bottomCenter,
          colors: [Color(0xFF0D0D1A), Color(0xFF1A0A0A)],
        ),
      ),
      child: SafeArea(
        child: Padding(
          padding: const EdgeInsets.symmetric(horizontal: 32),
          child: Column(
            mainAxisAlignment: MainAxisAlignment.center,
            children: [

              // Lock icon
              Container(
                width: 90, height: 90,
                decoration: BoxDecoration(
                  color: T.danger.withOpacity(0.12),
                  shape: BoxShape.circle,
                  border: Border.all(color: T.danger.withOpacity(0.3), width: 1.5)),
                child: const Icon(Icons.lock_rounded, size: 40, color: T.danger)),
              const SizedBox(height: 28),

              // Title
              const Text(
                'Trial Plan Expired',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 24, fontWeight: FontWeight.w800,
                  color: Colors.white, letterSpacing: 0.3)),
              const SizedBox(height: 12),

              // Message
              Text(
                'Your 15-day free trial has ended.\nTo continue using TailorX, please renew your plan.',
                textAlign: TextAlign.center,
                style: TextStyle(
                  fontSize: 15, height: 1.6,
                  color: Colors.white.withOpacity(0.6))),
              const SizedBox(height: 8),

              // Plans reminder
              Container(
                margin: const EdgeInsets.symmetric(vertical: 24),
                padding: const EdgeInsets.all(20),
                decoration: BoxDecoration(
                  color: Colors.white.withOpacity(0.04),
                  borderRadius: BorderRadius.circular(T.rMd),
                  border: Border.all(color: Colors.white.withOpacity(0.08))),
                child: Row(children: [
                  Expanded(child: Column(children: [
                    const Text('Monthly', style: TextStyle(fontSize: 12, color: Colors.white54)),
                    const SizedBox(height: 4),
                    const Text('₹499', style: TextStyle(
                      fontSize: 22, fontWeight: FontWeight.w800, color: Colors.white)),
                    const Text('per month', style: TextStyle(fontSize: 11, color: Colors.white38)),
                  ])),
                  Container(width: 1, height: 50, color: Colors.white12),
                  Expanded(child: Column(children: [
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
                      decoration: BoxDecoration(
                        color: T.accent.withOpacity(0.15),
                        borderRadius: BorderRadius.circular(4)),
                      child: const Text('BEST VALUE', style: TextStyle(
                        fontSize: 8, fontWeight: FontWeight.w800,
                        color: T.accent, letterSpacing: 1))),
                    const SizedBox(height: 2),
                    const Text('Yearly', style: TextStyle(fontSize: 12, color: Colors.white54)),
                    const SizedBox(height: 2),
                    const Text('₹3,999', style: TextStyle(
                      fontSize: 22, fontWeight: FontWeight.w800, color: T.accent)),
                    const Text('per year', style: TextStyle(fontSize: 11, color: Colors.white38)),
                  ])),
                ]),
              ),

              // WhatsApp CTA button
              GestureDetector(
                onTap: _contactUs,
                child: Container(
                  width: double.infinity,
                  height: 54,
                  decoration: BoxDecoration(
                    color: const Color(0xFF25D366),
                    borderRadius: BorderRadius.circular(T.rMd),
                    boxShadow: [BoxShadow(
                      color: const Color(0xFF25D366).withOpacity(0.35),
                      blurRadius: 20, offset: const Offset(0, 8))]),
                  child: const Row(
                    mainAxisAlignment: MainAxisAlignment.center,
                    children: [
                      Icon(Icons.chat_rounded, color: Colors.white, size: 20),
                      SizedBox(width: 10),
                      Text('Contact Us to Renew',
                        style: TextStyle(
                          fontSize: 15, fontWeight: FontWeight.w800, color: Colors.white)),
                    ]),
                ),
              ),
              const SizedBox(height: 14),

              // Sub-note
              Text(
                'We will activate your plan within minutes\nafter payment confirmation.',
                textAlign: TextAlign.center,
                style: TextStyle(fontSize: 12, color: Colors.white.withOpacity(0.35), height: 1.5)),
            ],
          ),
        ),
      ),
    );
  }
}

class _SearchBody extends StatefulWidget {
  final String query;
  const _SearchBody({required this.query});
  @override
  State<_SearchBody> createState() => _SearchBodyState();
}

class _SearchBodyState extends State<_SearchBody> {
  final _api = Api();
  bool _loading = true;
  List<Customer> _c = []; List<Order> _o = []; List<Invoice> _i = [];

  @override
  void initState() { super.initState(); _search(); }

  Future<void> _search() async {
    setState(() => _loading = true);
    try {
      final c = await _api.getCustomers();
      final o = await _api.getOrders();
      final inv = await _api.getInvoices();
      final q = widget.query.toLowerCase();
      if (mounted) setState(() {
        _c = c.where((c) => c.name.toLowerCase().contains(q) || c.phone.contains(q) || (c.email ?? '').toLowerCase().contains(q)).toList();
        _o = o.where((o) => (o.customerName ?? '').toLowerCase().contains(q) || (o.garment ?? '').toLowerCase().contains(q)).toList();
        _i = inv.where((i) => (i.customerName ?? '').toLowerCase().contains(q) || (i.garment ?? '').toLowerCase().contains(q)).toList();
      });
    } catch (_) {}
    finally { if (mounted) setState(() => _loading = false); }
  }

  @override
  Widget build(BuildContext context) {
    if (_loading) return const Center(child: CircularProgressIndicator(strokeWidth: 1.5, color: T.accent));
    final total = _c.length + _o.length + _i.length;
    if (total == 0) return Center(child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
      Icon(Icons.search_off_rounded, size: 48, color: T.text3.withOpacity(0.4)),
      const SizedBox(height: 12), Text('No results found', style: T.bodySm),
    ]));

    return ListView(padding: const EdgeInsets.symmetric(horizontal: 20), children: [
      if (_c.isNotEmpty) ...[
        Text('CUSTOMERS (${_c.length})', style: T.label), const SizedBox(height: 8),
        ..._c.map((c) => Container(margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
          child: Row(children: [
            Container(width: 44, height: 44, decoration: BoxDecoration(gradient: T.accentGrad, borderRadius: BorderRadius.circular(8)),
              child: Center(child: Text(c.initials, style: const TextStyle(fontSize: 16, fontWeight: FontWeight.w700, color: T.headerDark)))),
            const SizedBox(width: 10),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(c.name, style: T.body.copyWith(fontWeight: FontWeight.w600)),
              Text(c.phone, style: T.bodySm),
            ])),
          ]))),
        const SizedBox(height: 16),
      ],
      if (_o.isNotEmpty) ...[
        Text('ORDERS (${_o.length})', style: T.label), const SizedBox(height: 8),
        ..._o.map((o) => Container(margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
          child: Row(children: [
            Container(width: 3, height: 32, color: T.stageColor(o.status), margin: const EdgeInsets.only(right: 10)),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(o.customerName ?? '', style: T.body.copyWith(fontWeight: FontWeight.w600)),
              Text(o.description, style: T.bodySm, maxLines: 1, overflow: TextOverflow.ellipsis),
            ])),
            StatusBadge(status: o.status),
          ]))),
        const SizedBox(height: 16),
      ],
      if (_i.isNotEmpty) ...[
        Text('INVOICES (${_i.length})', style: T.label), const SizedBox(height: 8),
        ..._i.map((inv) => Container(margin: const EdgeInsets.only(bottom: 6), padding: const EdgeInsets.all(12),
          decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
          child: Row(children: [
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(inv.customerName ?? '', style: T.body.copyWith(fontWeight: FontWeight.w600)),
              Text(inv.garment ?? 'Invoice #${inv.id}', style: T.bodySm),
            ])),
            StatusBadge(status: inv.status, isInvoice: true),
          ]))),
      ],
      const SizedBox(height: 20),
    ]);
  }
}
