import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/models.dart';
import '../services/api_service.dart';
import '../utils/constants.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import '../utils/pdf_helper.dart';
import '../utils/privacy_helper.dart';
import '../utils/ai_measurements.dart';
import '../widgets/common_widgets.dart';

class CustomersScreen extends StatefulWidget {
  final Function(Customer)? onNewOrder;
  const CustomersScreen({super.key, this.onNewOrder});
  @override State<CustomersScreen> createState() => CustomersScreenState();
}

class CustomersScreenState extends State<CustomersScreen> {
  final _api = Api(); final _lang = AppLang();
  List<Customer> _list = []; List<Order> _orders = []; bool _loading = true;
  String _search = ''; final _sc = TextEditingController();
  final _fmt = NumberFormat.currency(locale: 'en_IN', symbol: '₹', decimalDigits: 0);
  Map<String, Map<String, dynamic>> _stats = {};

  @override void initState() { super.initState(); _load(); }

  Future<void> refresh() => _load();

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final results = await Future.wait([
        _api.getCustomers(),
        _api.getOrders(),
      ]);
      
      final c = results[0] as List<Customer>;
      final o = results[1] as List<Order>;

      // Calculate stats per customer
      final stats = <String, Map<String, dynamic>>{};
      for (var order in o) {
        if (order.customerId == null) continue;
        final id = order.customerId!;
        if (!stats.containsKey(id)) {
          stats[id] = {'count': 0, 'total': 0.0};
        }
        stats[id]!['count'] = (stats[id]!['count'] as int) + 1;
        stats[id]!['total'] = (stats[id]!['total'] as double) + order.totalAmount;
      }

      if (mounted) {
        setState(() {
          _stats = stats;
          _orders = o;
          c.sort((a, b) => a.name.toLowerCase().compareTo(b.name.toLowerCase()));
          _list = c;
        });
      }
    } catch (e) { if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e'))); }
    finally { if (mounted) setState(() => _loading = false); }
  }

  List<Customer> get _filteredList {
    List<Customer> filtered = _list;
    if (_search.isNotEmpty) {
      final q = _search.toLowerCase();
      filtered = filtered.where((c) =>
        c.name.toLowerCase().contains(q) || c.phone.contains(q) ||
        (c.city ?? '').toLowerCase().contains(q)).toList();
    }
    return filtered;
  }

  Map<String, List<Customer>> get _groupedCustomers {
    final groups = <String, List<Customer>>{};
    for (var c in _filteredList) {
      final char = c.name.isNotEmpty ? c.name[0].toUpperCase() : '#';
      if (!groups.containsKey(char)) groups[char] = [];
      groups[char]!.add(c);
    }
    return groups;
  }

  LinearGradient _avGrad(int i) {
    final grads = [
      const [Color(0xFFE8C49A), Color(0xFFD4A574)], const [Color(0xFF7C5CBF), Color(0xFF5C3FA3)],
      const [Color(0xFF4A7FC1), Color(0xFF2D5A94)], const [Color(0xFF2BA5A5), Color(0xFF1F7878)],
      const [Color(0xFF2D8F6F), Color(0xFF1F6650)], const [Color(0xFFCF4747), Color(0xFF992F2F)],
    ];
    return LinearGradient(begin: Alignment.topLeft, end: Alignment.bottomRight, colors: grads[i % grads.length]);
  }

  void _viewCustomer(Customer c, int idx) {
    final isMale = c.gender?.toLowerCase() == 'male';
    final customerOrders = _orders
        .where((o) => o.customerId == c.id)
        .toList()
      ..sort((a, b) => (b.createdAt ?? '').compareTo(a.createdAt ?? ''));
    showModalBottomSheet(context: context, isScrollControlled: true, backgroundColor: Colors.transparent,
      builder: (ctx) => T.sheetScaffold(ctx, heightFraction: 0.92, child: Column(children: [
          Container(padding: const EdgeInsets.fromLTRB(18, 16, 18, 18),
            decoration: const BoxDecoration(gradient: T.headerGrad, borderRadius: BorderRadius.vertical(top: Radius.circular(T.rXl))),
            child: Column(children: [
              Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                GestureDetector(onTap: () => Navigator.pop(ctx), child: const Icon(Icons.arrow_back_ios_rounded, size: 18, color: T.headerText)),
                Row(children: [
                  GestureDetector(
                    onTap: () {
                      final hasMeas = (c.measurementsTop?.isNotEmpty == true) || (c.measurementsBottom?.isNotEmpty == true);
                      if (!hasMeas) {
                        ScaffoldMessenger.of(context).showSnackBar(
                          const SnackBar(content: Text('No measurements recorded yet.')));
                        return;
                      }
                      PdfHelper.generateAndShareMeasurements(c,
                        boutiqueName: _api.boutiqueName,
                        boutiqueAddress: _api.boutiqueAddress);
                    },
                    child: const Icon(Icons.print_rounded, size: 16, color: T.headerText),
                  ),
                  const SizedBox(width: 14),
                  GestureDetector(onTap: () { Navigator.pop(ctx); _showForm(c: c); }, child: const Icon(Icons.edit_rounded, size: 16, color: T.headerText)),
                  const SizedBox(width: 14),
                  GestureDetector(onTap: () { Navigator.pop(ctx); _deleteCustomer(c); }, child: const Icon(Icons.delete_rounded, size: 16, color: T.headerText)),
                ]),
              ]),
              const SizedBox(height: 16),
              Row(children: [
                Container(width: 80, height: 80,
                  decoration: BoxDecoration(gradient: isMale ? const LinearGradient(colors: [Color(0xFF4A7FC1), Color(0xFF2D5A94)]) : T.accentGrad,
                    borderRadius: BorderRadius.circular(22), boxShadow: [BoxShadow(color: T.accent.withOpacity(0.45), blurRadius: 24, offset: const Offset(0, 12))]),
                  child: Center(child: Text(c.initials, style: GoogleFonts.prata(fontSize: 40, fontWeight: FontWeight.w400, color: isMale ? Colors.white : T.headerDark)))),
                const SizedBox(width: 14),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(c.name, style: GoogleFonts.prata(fontSize: 34, fontWeight: FontWeight.w400, color: Colors.white)),
                  const SizedBox(height: 6),
                  Container(padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
                    decoration: BoxDecoration(gradient: isMale ? const LinearGradient(colors: [Color(0xFF4A7FC1), Color(0xFF2D5A94)]) : const LinearGradient(colors: [Color(0xFFD67BA0), Color(0xFFA85A82)]), borderRadius: BorderRadius.circular(4)),
                    child: Text(isMale ? '♂ MALE' : '♀ FEMALE', style: const TextStyle(fontSize: 12, fontWeight: FontWeight.w800, letterSpacing: 1.2, color: Colors.white))),
                  const SizedBox(height: 6),
                  Text('${c.phone}${c.city?.isNotEmpty == true ? " · ${c.city}" : ""}', style: TextStyle(fontSize: 16, fontWeight: FontWeight.w500, color: Colors.white.withOpacity(0.6))),
                ])),
              ]),
            ]),
          ),
          Expanded(child: ListView(padding: EdgeInsets.fromLTRB(16, 14, 16, 80 + MediaQuery.of(ctx).viewInsets.bottom), children: [
            if (c.measurementsTop?.isNotEmpty == true) ...[
              const SecTitle(title: 'Top Measurements'),
              if (isMale)
                _MeasView(measurements: c.measurementsTop!, isMale: true)
              else
                _FemaleTopView(measurements: c.measurementsTop!),
              const SizedBox(height: 12),
            ],
            if (c.measurementsBottom?.isNotEmpty == true) ...[
              const SecTitle(title: 'Bottom Measurements'),
              _MeasView(measurements: c.measurementsBottom!, isMale: isMale),
              const SizedBox(height: 12),
            ],
            if (c.notes?.isNotEmpty == true) ...[
              const SecTitle(title: 'Fitting Notes'),
              Container(padding: const EdgeInsets.all(12),
                decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(12), border: Border.all(color: T.accent.withOpacity(0.18))),
                child: Text(c.notes!, style: T.body)),
              const SizedBox(height: 12),
            ],
            // ── Order History ──────────────────────────────────────
            const SecTitle(title: 'Order History'),
            if (customerOrders.isEmpty)
              Container(
                margin: const EdgeInsets.only(bottom: 12),
                padding: const EdgeInsets.symmetric(vertical: 20),
                decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
                child: Center(child: Column(children: [
                  Icon(Icons.receipt_long_outlined, size: 32, color: T.text3),
                  const SizedBox(height: 8),
                  Text('No orders yet', style: T.bodySm.copyWith(color: T.text3)),
                ])),
              )
            else
              Container(
                margin: const EdgeInsets.only(bottom: 12),
                decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
                child: Column(
                  children: customerOrders.asMap().entries.map((e) {
                    final i = e.key; final o = e.value;
                    final isPaid = o.balance <= 0;
                    final stageColor = {
                      'received': T.info, 'cutting': T.warning,
                      'stitching': T.purple, 'trial': T.teal,
                      'ready': T.success, 'delivered': T.text3,
                    }[o.stage.toLowerCase()] ?? T.text3;
                    return Column(children: [
                      if (i > 0) Container(height: 1, margin: const EdgeInsets.symmetric(horizontal: 14), color: T.border),
                      Padding(
                        padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                        child: Row(children: [
                          // Stage dot
                          Container(width: 10, height: 10,
                            decoration: BoxDecoration(color: stageColor, shape: BoxShape.circle)),
                          const SizedBox(width: 12),
                          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                            Text(o.garment ?? 'Order', style: T.body.copyWith(fontWeight: FontWeight.w600, fontSize: 15)),
                            const SizedBox(height: 2),
                            Row(children: [
                              Container(
                                padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                                decoration: BoxDecoration(color: stageColor.withOpacity(0.12), borderRadius: BorderRadius.circular(4)),
                                child: Text(o.stage.toUpperCase(), style: TextStyle(fontSize: 9, fontWeight: FontWeight.w800, color: stageColor, letterSpacing: 0.8)),
                              ),
                              if (o.fabric?.isNotEmpty == true) ...[
                                const SizedBox(width: 6),
                                Text('· ${o.fabric}', style: T.bodySm.copyWith(fontSize: 12)),
                              ],
                            ]),
                          ])),
                          Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
                            Text(_fmt.format(o.totalAmount),
                              style: T.body.copyWith(fontWeight: FontWeight.w700, fontSize: 15)),
                            const SizedBox(height: 2),
                            Container(
                              padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                              decoration: BoxDecoration(
                                color: isPaid ? T.success.withOpacity(0.1) : T.danger.withOpacity(0.1),
                                borderRadius: BorderRadius.circular(4)),
                              child: Text(
                                isPaid ? 'PAID' : 'DUE ${_fmt.format(o.balance)}',
                                style: TextStyle(fontSize: 9, fontWeight: FontWeight.w800,
                                  color: isPaid ? T.success : T.danger, letterSpacing: 0.8))),
                          ]),
                        ]),
                      ),
                    ]);
                  }).toList(),
                ),
              ),

            // ── Contact ────────────────────────────────────────────
            const SecTitle(title: 'Contact'),
            Container(decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
              child: Column(children: [
                _ContactRow(Icons.phone_rounded, 'Phone', c.phone),
                if (c.email?.isNotEmpty == true) _ContactRow(Icons.email_rounded, 'Email', c.email!),
                if (c.dob?.isNotEmpty == true) _ContactRow(Icons.cake_rounded, 'Birthday', DateFormat('dd MMM yyyy').format(DateTime.parse(c.dob!))),
                if (c.address?.isNotEmpty == true) _ContactRow(Icons.location_on_rounded, 'Address', c.address!),
                if (c.city?.isNotEmpty == true) _ContactRow(Icons.location_city_rounded, 'City', c.city!),
                if (c.notify?.isNotEmpty == true) _ContactRow(Icons.notifications_rounded, 'Notify via', c.notify!),
              ])),
          ])),
          Container(padding: const EdgeInsets.fromLTRB(16, 10, 16, 24),
            decoration: BoxDecoration(gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter, colors: [T.bg.withOpacity(0), T.bg])),
            child: Row(children: [
              Expanded(child: GestureDetector(onTap: () { Navigator.pop(ctx); _showForm(c: c); },
                child: Container(padding: const EdgeInsets.symmetric(vertical: 13), decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(12), boxShadow: T.shadowCard),
                  child: Center(child: Text('UPDATE', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600, letterSpacing: 0.6, color: T.text)))))),
              const SizedBox(width: 8),
              // Print measurements button
              GestureDetector(
                onTap: () {
                  final hasMeas = (c.measurementsTop?.isNotEmpty == true) || (c.measurementsBottom?.isNotEmpty == true);
                  if (!hasMeas) {
                    Navigator.pop(ctx);
                    ScaffoldMessenger.of(context).showSnackBar(
                      const SnackBar(content: Text('No measurements to print yet.')));
                    return;
                  }
                  Navigator.pop(ctx);
                  PdfHelper.generateAndShareMeasurements(c,
                    boutiqueName: _api.boutiqueName,
                    boutiqueAddress: _api.boutiqueAddress);
                },
                child: Container(
                  padding: const EdgeInsets.symmetric(vertical: 13, horizontal: 16),
                  decoration: BoxDecoration(
                    color: T.accent.withOpacity(0.12),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(color: T.accent.withOpacity(0.35)),
                  ),
                  child: Row(mainAxisSize: MainAxisSize.min, children: [
                    Icon(Icons.print_rounded, size: 16, color: T.accent),
                    const SizedBox(width: 6),
                    Text('PRINT', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w700, letterSpacing: 0.6, color: T.accent)),
                  ]),
                ),
              ),
              const SizedBox(width: 8),
              Expanded(child: GestureDetector(
                onTap: () {
                  Navigator.pop(ctx);
                  widget.onNewOrder?.call(c);
                },
                child: Container(padding: const EdgeInsets.symmetric(vertical: 13),
                  decoration: BoxDecoration(gradient: T.accentGrad, borderRadius: BorderRadius.circular(12),
                    boxShadow: [BoxShadow(color: T.accent.withOpacity(0.4), blurRadius: 18, offset: const Offset(0, 6))]),
                  child: Center(child: Text('+ NEW ORDER', style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600, letterSpacing: 0.6, color: Colors.white)))))),
            ])),
        ])),
    );
  }

  void _deleteCustomer(Customer c) async {
    final ok = await showDialog<bool>(context: context, builder: (ctx) => AlertDialog(
      title: Text('Delete Customer?', style: T.heading),
      content: Text('Delete "${c.name}"? This cannot be undone.', style: T.body),
      actions: [
        TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(_lang.t('cancel'))),
        ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: T.danger), onPressed: () => Navigator.pop(ctx, true), child: const Text('DELETE'))],
    ));
    if (ok == true) {
      try { await _api.deleteCustomer(c.id!); _load();
        if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('"${c.name}" deleted')));
      } catch (e) { if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e'))); }
    }
  }

  void _showUpgradeSheet(BuildContext ctx) {
    showModalBottomSheet(
      context: ctx,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (_) => Container(
        decoration: const BoxDecoration(
          color: Colors.white,
          borderRadius: BorderRadius.vertical(top: Radius.circular(24)),
        ),
        padding: const EdgeInsets.fromLTRB(24, 16, 24, 32),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          // Handle
          Container(width: 40, height: 4,
            decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2))),
          const SizedBox(height: 24),

          // Icon badge
          Container(
            width: 72, height: 72,
            decoration: BoxDecoration(
              gradient: T.headerGrad,
              borderRadius: BorderRadius.circular(20),
              boxShadow: T.shadowElev,
            ),
            child: const Center(child: Text('✨', style: TextStyle(fontSize: 32))),
          ),
          const SizedBox(height: 16),

          Text('Pro Feature', style: T.label.copyWith(color: T.accentDark, letterSpacing: 2.5)),
          const SizedBox(height: 8),
          Text('AI Measurement Suggest', style: T.displaySm.copyWith(color: T.text)),
          const SizedBox(height: 8),
          Text(
            'Automatically fill all measurements from height & body type using our intelligent tailoring engine.',
            textAlign: TextAlign.center,
            style: T.bodySm.copyWith(color: T.text2, height: 1.5),
          ),
          const SizedBox(height: 24),

          // Feature bullets
          ...['Instant measurement suggestions', 'Male & female body proportions',
              'Slim / Average / Plus Size support', 'Apply all with one tap'].map((f) =>
            Padding(
              padding: const EdgeInsets.only(bottom: 10),
              child: Row(children: [
                Container(
                  width: 20, height: 20,
                  decoration: BoxDecoration(
                    color: T.accentDark.withOpacity(0.15),
                    shape: BoxShape.circle),
                  child: Icon(Icons.check_rounded, size: 13, color: T.accentDark)),
                const SizedBox(width: 12),
                Text(f, style: T.bodySm.copyWith(color: T.text)),
              ]),
            )),

          const SizedBox(height: 24),

          // Upgrade CTA
          GestureDetector(
            onTap: () async {
              Navigator.pop(ctx);
              final uri = Uri.parse('https://wa.me/918469696966?text=Hi%2C%20I%20want%20to%20upgrade%20to%20Pro%20plan%20for%20AI%20Measurements%20feature');
              try {
                // ignore: deprecated_member_use
                if (await canLaunchUrl(uri)) { await launchUrl(uri, mode: LaunchMode.externalApplication); }
              } catch (_) {}
            },
            child: Container(
              width: double.infinity,
              padding: const EdgeInsets.symmetric(vertical: 16),
              decoration: BoxDecoration(
                gradient: T.headerGrad,
                borderRadius: BorderRadius.circular(T.rMd),
                boxShadow: T.shadowElev,
              ),
              child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                const Icon(Icons.star_rounded, color: Color(0xFFD4A574), size: 20),
                const SizedBox(width: 8),
                Text('Upgrade to Pro', style: T.btn),
              ]),
            ),
          ),
          const SizedBox(height: 12),

          // Or dismiss
          GestureDetector(
            onTap: () => Navigator.pop(ctx),
            child: Center(child: Text('Maybe later',
              style: T.bodySm.copyWith(color: T.text3))),
          ),
        ]),
      ),
    );
  }

  void _showAISuggest(
    BuildContext ctx,
    StateSetter setSt,
    String gender,
    Map<String, String> meas,
    List<String> customTop,
    List<String> customBottom,
    List<String> customTopBlouse,
    List<String> customTopDress,
  ) async {
    // Local state for the AI input sheet
    double feet = 5, inches = 5, keyMeas = 36;
    String bodyType = AIMeasurements.average;
    bool useMetric = false;
    double heightCm = 165;
    Map<String, Map<String, double>>? suggestions;
    bool generated = false;

    // Fetch current AI measurement usage (unlimited for Pro Yearly/trial/free,
    // capped for Pro Monthly)
    Map<String, dynamic>? aiUsage;
    try {
      aiUsage = await _api.getAIMeasurementUsage();
    } catch (_) {
      // If usage check fails, fall back to allowing generation —
      // the record endpoint will still enforce the cap server-side.
    }

    showModalBottomSheet(
      context: context,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      useSafeArea: true,
      builder: (shCtx) => StatefulBuilder(builder: (shCtx, shSt) {
        final bottomPad = MediaQuery.of(shCtx).padding.bottom;
        return Container(
          decoration: BoxDecoration(
            color: T.bg,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(24))),
          padding: EdgeInsets.fromLTRB(24, 20, 24, 20 + bottomPad),
          child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch, children: [

            // Handle
            Center(child: Container(width: 36, height: 4,
              decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2)))),
            const SizedBox(height: 20),

            // Header
            Row(children: [
              Container(width: 44, height: 44,
                decoration: BoxDecoration(
                  gradient: T.headerGrad,
                  borderRadius: BorderRadius.circular(12)),
                child: const Center(child: Text('✨', style: TextStyle(fontSize: 22)))),
              const SizedBox(width: 12),
              Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('AI Measurement Suggest', style: T.displaySm),
                Text('Enter basics — we suggest everything',
                  style: T.bodySm.copyWith(fontSize: 12)),
              ]),
              const Spacer(),
              if (aiUsage != null)
                Container(
                  padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
                  decoration: BoxDecoration(
                    color: T.accentDark.withOpacity(0.1),
                    borderRadius: BorderRadius.circular(8)),
                  child: Text(
                    aiUsage!['unlimited'] == true
                        ? 'Unlimited'
                        : '${aiUsage!['remaining']}/${aiUsage!['limit']} left',
                    style: T.bodySm.copyWith(
                      fontSize: 11, fontWeight: FontWeight.w700,
                      color: T.accentDark)),
                ),
            ]),
            const SizedBox(height: 24),

            // Height unit toggle
            Row(children: [
              Text('HEIGHT', style: T.label),
              const Spacer(),
              Container(
                decoration: BoxDecoration(color: T.surface, borderRadius: BorderRadius.circular(8)),
                child: Row(mainAxisSize: MainAxisSize.min, children: [
                  _unitBtn('ft/in', !useMetric, () => shSt(() => useMetric = false)),
                  _unitBtn('cm',     useMetric,  () => shSt(() => useMetric = true)),
                ]),
              ),
            ]),
            const SizedBox(height: 8),

            if (!useMetric)
              Row(children: [
                Expanded(child: _numInput('Feet', feet.toStringAsFixed(0), (v) {
                  feet = double.tryParse(v) ?? feet;
                })),
                const SizedBox(width: 10),
                Expanded(child: _numInput('Inches', inches.toStringAsFixed(0), (v) {
                  inches = double.tryParse(v) ?? inches;
                })),
              ])
            else
              _numInput('Height (cm)', heightCm.toStringAsFixed(0), (v) {
                heightCm = double.tryParse(v) ?? heightCm;
              }),

            const SizedBox(height: 16),

            // Key measurement
            Text(
              gender == 'male' ? 'CHEST (inches)' : 'BUST / CHEST 1 (inches)',
              style: T.label),
            const SizedBox(height: 8),
            _numInput(
              gender == 'male' ? 'e.g. 38' : 'e.g. 34',
              keyMeas.toStringAsFixed(0),
              (v) { keyMeas = double.tryParse(v) ?? keyMeas; },
            ),
            const SizedBox(height: 16),

            // Body type
            Text('BODY TYPE', style: T.label),
            const SizedBox(height: 8),
            Row(children: [
              AIMeasurements.slim,
              AIMeasurements.average,
              AIMeasurements.plus,
            ].map((bt) => Expanded(child: GestureDetector(
              onTap: () => shSt(() => bodyType = bt),
              child: AnimatedContainer(
                duration: const Duration(milliseconds: 200),
                margin: const EdgeInsets.symmetric(horizontal: 3),
                padding: const EdgeInsets.symmetric(vertical: 10),
                decoration: BoxDecoration(
                  color: bodyType == bt
                      ? T.accentDark.withOpacity(0.12)
                      : T.surface,
                  borderRadius: BorderRadius.circular(10),
                  border: Border.all(
                    color: bodyType == bt
                        ? T.accentDark
                        : Colors.transparent,
                    width: 1.5),
                ),
                child: Column(children: [
                  Text(
                    bt == AIMeasurements.slim ? '🪶' :
                    bt == AIMeasurements.average ? '🧍' : '🫅',
                    style: const TextStyle(fontSize: 20)),
                  const SizedBox(height: 4),
                  Text(bt,
                    textAlign: TextAlign.center,
                    style: TextStyle(
                      fontSize: 11, fontWeight: FontWeight.w600,
                      color: bodyType == bt
                          ? T.accentDark
                          : T.text3)),
                ]),
              ),
            ))).toList()),
            const SizedBox(height: 24),

            // Generate button
            if (!generated)
              GestureDetector(
                onTap: () async {
                  // Enforce Pro Monthly cap before generating
                  if (aiUsage != null &&
                      aiUsage!['unlimited'] != true &&
                      (aiUsage!['remaining'] ?? 0) <= 0) {
                    Navigator.pop(shCtx);
                    _showUpgradeSheet(ctx);
                    return;
                  }

                  // Record usage server-side (also enforces cap as a fallback)
                  try {
                    final updated = await _api.recordAIMeasurementUsage();
                    shSt(() => aiUsage = updated);
                  } catch (e) {
                    Navigator.pop(shCtx);
                    _showUpgradeSheet(ctx);
                    return;
                  }

                  final hCm = useMetric
                      ? heightCm
                      : AIMeasurements.feetToCm(feet, inches);
                  final s = gender == 'male'
                      ? AIMeasurements.suggestMale(
                          heightCm: hCm, chest: keyMeas, bodyType: bodyType)
                      : AIMeasurements.suggestFemale(
                          heightCm: hCm, bust: keyMeas, bodyType: bodyType);
                  shSt(() { suggestions = s; generated = true; });
                },
                child: Container(
                  padding: const EdgeInsets.symmetric(vertical: 16),
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [Color(0xFF4B2FD4), Color(0xFF2D7DD2)]),
                    borderRadius: BorderRadius.circular(T.rMd),
                    boxShadow: [BoxShadow(
                      color: T.headerDark.withOpacity(0.35),
                      blurRadius: 16, offset: const Offset(0, 6))]),
                  child: const Center(child: Text('✨  Generate Measurements',
                    style: TextStyle(
                      color: Colors.white, fontWeight: FontWeight.w700,
                      fontSize: 15, letterSpacing: 0.5))),
                ),
              ),

            // Results
            if (generated && suggestions != null) ...[
              Container(
                padding: const EdgeInsets.all(14),
                decoration: BoxDecoration(
                  color: T.accentDark.withOpacity(0.06),
                  borderRadius: BorderRadius.circular(T.rMd),
                  border: Border.all(
                    color: T.accentDark.withOpacity(0.2))),
                child: Column(children: [
                  Row(children: [
                    const Text('✨', style: TextStyle(fontSize: 16)),
                    const SizedBox(width: 8),
                    Text('Suggestions ready!',
                      style: T.body.copyWith(
                        fontWeight: FontWeight.w700,
                        color: T.accentDark)),
                    const Spacer(),
                    Text('All in inches', style: T.bodySm.copyWith(fontSize: 11)),
                  ]),
                  const SizedBox(height: 12),
                  ...suggestions!.entries.map((section) => Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Text(section.key.toUpperCase(),
                        style: T.label.copyWith(fontSize: 10)),
                      const SizedBox(height: 6),
                      Wrap(spacing: 8, runSpacing: 8,
                        children: section.value.entries.map((e) =>
                          Container(
                            padding: const EdgeInsets.symmetric(
                              horizontal: 12, vertical: 8),
                            decoration: BoxDecoration(
                              color: T.card,
                              borderRadius: BorderRadius.circular(8),
                              boxShadow: T.shadowCard),
                            child: Column(children: [
                              Text(e.key,
                                style: T.bodySm.copyWith(fontSize: 10)),
                              Text('${e.value}″',
                                style: TextStyle(
                                  fontSize: 16, fontWeight: FontWeight.w800,
                                  color: T.accentDark)),
                            ]),
                          ),
                        ).toList()),
                      const SizedBox(height: 10),
                    ],
                  )),
                ]),
              ),
              const SizedBox(height: 12),

              // Apply button
              GestureDetector(
                onTap: () {
                  // Apply all suggestions into the meas map
                  suggestions!.forEach((section, fields) {
                    fields.forEach((field, value) {
                      final v = value % 1 == 0
                          ? value.toInt().toString()
                          : value.toString();
                      if (gender == 'male') {
                        meas[field] = v;
                      } else {
                        // Female: prefix with section name for top
                        if (section == 'blouse' || section == 'dress') {
                          meas['${section}_$field'] = v;
                        } else {
                          meas[field] = v;
                        }
                      }
                    });
                  });
                  Navigator.pop(shCtx);
                  setSt(() {}); // rebuild form with applied values
                  ScaffoldMessenger.of(context).showSnackBar(
                    SnackBar(
                      content: const Row(children: [
                        Text('✨ ', style: TextStyle(fontSize: 16)),
                        Text('AI measurements applied! Review and adjust as needed.'),
                      ]),
                      backgroundColor: T.accentDark,
                      duration: const Duration(seconds: 3),
                    ));
                },
                child: Container(
                  padding: const EdgeInsets.symmetric(vertical: 15),
                  decoration: BoxDecoration(
                    gradient: const LinearGradient(
                      colors: [Color(0xFF4B2FD4), Color(0xFF2D7DD2)]),
                    borderRadius: BorderRadius.circular(T.rMd)),
                  child: const Center(child: Text('Apply All Measurements',
                    style: TextStyle(
                      color: Colors.white, fontWeight: FontWeight.w700,
                      fontSize: 15))),
                ),
              ),
              const SizedBox(height: 8),
              GestureDetector(
                onTap: () => shSt(() => generated = false),
                child: Center(child: Text('← Adjust inputs',
                  style: T.bodySm.copyWith(color: T.text3))),
              ),
            ],
          ])),
        );
      }),
    );
  }

  // Helper widgets for AI suggest sheet
  Widget _unitBtn(String label, bool active, VoidCallback onTap) =>
      GestureDetector(onTap: onTap,
        child: AnimatedContainer(
          duration: const Duration(milliseconds: 150),
          padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 6),
          decoration: BoxDecoration(
            color: active ? T.card : Colors.transparent,
            borderRadius: BorderRadius.circular(6)),
          child: Text(label, style: TextStyle(
            fontSize: 12, fontWeight: FontWeight.w600,
            color: active ? T.text : T.text3))));

  Widget _numInput(String hint, String initial, Function(String) onChange) =>
      TextFormField(
        initialValue: initial,
        keyboardType: const TextInputType.numberWithOptions(decimal: true),
        style: T.body.copyWith(fontSize: 16),
        decoration: InputDecoration(
          hintText: hint,
          filled: true,
          fillColor: T.surface,
          border: OutlineInputBorder(
            borderRadius: BorderRadius.circular(T.rMd),
            borderSide: BorderSide.none),
          contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 13)),
        onChanged: onChange,
      );

  void _showForm({Customer? c}) {
    final nm = TextEditingController(text: c?.name ?? '');
    final ph = TextEditingController(text: c?.phone ?? '');
    final em = TextEditingController(text: c?.email ?? '');
    final ad = TextEditingController(text: c?.address ?? '');
    final ct = TextEditingController(text: c?.city ?? '');
    final nt = TextEditingController(text: c?.notes ?? '');
    DateTime? dob = c?.dob != null ? DateTime.tryParse(c!.dob!) : null;
    String gender = (c?.gender?.toLowerCase() == 'male') ? 'male' : 'female';
    String notif = c?.notify ?? 'WhatsApp';
    final Map<String, String> meas = {};
    final customTop = <String>[]; final customBottom = <String>[];
    final customTopBlouse = <String>[]; final customTopDress = <String>[];
    String femTopTab = 'blouse';

    if (c != null) {
      final mt = c.measurementsTop ?? {};
      final mb = c.measurementsBottom ?? {};
      final defB = gender == 'male' ? C.maleBottom : C.femaleBottom;

      if (gender == 'male') {
        mt.forEach((k, v) {
          meas[k] = v.toString();
          if (!C.maleTop.any((f) => f.toLowerCase() == k.toLowerCase())) customTop.add(k);
        });
      } else {
        mt.forEach((k, v) {
          if (k.startsWith('blouse_') || k.startsWith('dress_')) {
            meas[k] = v.toString();
            final isBlouse = k.startsWith('blouse_');
            final baseKey = k.substring(isBlouse ? 7 : 6);
            final targetFields = isBlouse ? C.femaleTopBlouse : C.femaleTopDress;
            if (!targetFields.any((f) => f.toLowerCase() == baseKey.toLowerCase())) {
              (isBlouse ? customTopBlouse : customTopDress).add(baseKey);
            }
          } else {
            // Legacy unprefixed → treat as blouse
            meas['blouse_$k'] = v.toString();
            if (!C.femaleTopBlouse.any((f) => f.toLowerCase() == k.toLowerCase())) {
              customTopBlouse.add(k);
            }
          }
        });
      }

      mb.forEach((k, v) {
        meas[k] = v.toString();
        if (!defB.any((f) => f.toLowerCase() == k.toLowerCase())) customBottom.add(k);
      });
    }

    final fk = GlobalKey<FormState>();
    showModalBottomSheet(context: context, isScrollControlled: true, backgroundColor: Colors.transparent,
      builder: (ctx) => StatefulBuilder(builder: (ctx, setSt) => T.sheetScaffold(ctx, heightFraction: 0.92, child: Column(children: [
          const SizedBox(height: 12),
          Container(width: 36, height: 4, decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2))),
          Expanded(child: Form(key: fk, child: ListView(padding: EdgeInsets.fromLTRB(20, 20, 20, 30 + MediaQuery.of(ctx).viewInsets.bottom), children: [
            Text(c == null ? _lang.t('add_customer') : _lang.t('edit_customer'), style: T.displayMd),
            const SizedBox(height: 20),
            TxField(label: _lang.t('name'), hint: 'Full name', controller: nm, validator: (v) => v == null || v.trim().isEmpty ? _lang.t('required') : null),
            const SizedBox(height: 12),
            TxField(label: _lang.t('phone'), hint: '10-digit number', controller: ph, keyboardType: TextInputType.phone, validator: (v) => v == null || v.trim().isEmpty ? _lang.t('required') : null),
            const SizedBox(height: 12),
            Row(children: [
              Expanded(child: TxField(label: _lang.t('email'), hint: 'Optional', controller: em, keyboardType: TextInputType.emailAddress)),
              const SizedBox(width: 10),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('BIRTHDAY', style: T.label),
                const SizedBox(height: 6),
                GestureDetector(onTap: () async {
                  final d = await showDatePicker(context: ctx, initialDate: dob ?? DateTime(1995), firstDate: DateTime(1920), lastDate: DateTime.now());
                  if (d != null) setSt(() => dob = d);
                }, child: Container(padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14), decoration: BoxDecoration(color: T.surface, borderRadius: BorderRadius.circular(T.rMd)), child: Row(children: [
                  Icon(Icons.cake_rounded, size: 16, color: dob != null ? T.accent : T.text3),
                  const SizedBox(width: 10),
                  Text(dob != null ? DateFormat('dd MMM yyyy').format(dob!) : 'Select Date', style: T.body.copyWith(fontSize: 14, color: dob != null ? T.text : T.text3)),
                ]))),
              ])),
            ]),
            const SizedBox(height: 12),
            Row(children: [
              Expanded(child: TxField(label: _lang.t('city'), controller: ct)),
              const SizedBox(width: 10),
              Expanded(child: Container()), // Placeholder for symmetry if needed, or just let city take full width
            ]),
            const SizedBox(height: 12),
            TxField(label: 'Address', controller: ad, maxLines: 2),
            const SizedBox(height: 16),
            Text(_lang.t('gender').toUpperCase(), style: T.label),
            const SizedBox(height: 8),
            Row(children: [
              _GenderCard(label: 'MALE', icon: Icons.male_rounded, color: T.info, isSel: gender == 'male', onTap: () => setSt(() => gender = 'male')),
              const SizedBox(width: 8),
              _GenderCard(label: 'FEMALE', icon: Icons.female_rounded, color: T.pink, isSel: gender == 'female', onTap: () => setSt(() => gender = 'female')),
            ]),
            const SizedBox(height: 20),

            // ── AI Measurement Suggest ──────────────────────────
            GestureDetector(
              onTap: () {
                if (_api.isProPlan) {
                  _showAISuggest(ctx, setSt, gender, meas,
                    customTop, customBottom, customTopBlouse, customTopDress);
                } else {
                  _showUpgradeSheet(ctx);
                }
              },
              child: Stack(children: [
                Container(
                  padding: const EdgeInsets.all(16),
                  decoration: BoxDecoration(
                    gradient: _api.isProPlan ? T.headerGrad : const LinearGradient(
                      begin: Alignment.topLeft, end: Alignment.bottomRight,
                      colors: [Color(0xFF3A3A5C), Color(0xFF2A2A4A)]),
                    borderRadius: BorderRadius.circular(T.rMd),
                    boxShadow: [BoxShadow(
                      color: T.headerDark.withOpacity(0.35),
                      blurRadius: 16, offset: const Offset(0, 6))],
                  ),
                  child: Row(children: [
                    Container(
                      width: 44, height: 44,
                      decoration: BoxDecoration(
                        color: Colors.white.withOpacity(0.15),
                        borderRadius: BorderRadius.circular(12)),
                      child: Center(child: Text(
                        _api.isProPlan ? '✨' : '🔒',
                        style: const TextStyle(fontSize: 22)))),
                    const SizedBox(width: 12),
                    Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                      Row(children: [
                        const Text('AI Measurement Suggest',
                          style: TextStyle(color: Colors.white, fontWeight: FontWeight.w700, fontSize: 15)),
                        if (!_api.isProPlan) ...[
                          const SizedBox(width: 8),
                          Container(
                            padding: const EdgeInsets.symmetric(horizontal: 7, vertical: 2),
                            decoration: BoxDecoration(
                              color: T.accent.withOpacity(0.25),
                              borderRadius: BorderRadius.circular(6),
                              border: Border.all(color: T.accent.withOpacity(0.5), width: 1)),
                            child: const Text('PRO',
                              style: TextStyle(color: Color(0xFFD4A574), fontSize: 10,
                                fontWeight: FontWeight.w800, letterSpacing: 1.2))),
                        ],
                      ]),
                      const SizedBox(height: 2),
                      Text(
                        _api.isProPlan
                          ? 'Auto-fill all measurements from height & body type'
                          : 'Upgrade to Pro to unlock AI measurements',
                        style: TextStyle(color: Colors.white.withOpacity(0.75), fontSize: 12)),
                    ])),
                    Icon(
                      _api.isProPlan ? Icons.arrow_forward_ios_rounded : Icons.lock_outline_rounded,
                      size: 14, color: Colors.white.withOpacity(0.7)),
                  ]),
                ),
              ]),
            ),
            const SizedBox(height: 16),

            // ── Top Measurements ────────────────────────────────
            if (gender == 'female') ...[
              // Blouse / Dress tab switcher
              Container(
                margin: const EdgeInsets.only(bottom: 8),
                padding: const EdgeInsets.all(4),
                decoration: BoxDecoration(color: T.surface, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
                child: Row(children: ['blouse', 'dress'].map((tab) => Expanded(child: GestureDetector(
                  onTap: () => setSt(() => femTopTab = tab),
                  child: AnimatedContainer(duration: const Duration(milliseconds: 200),
                    padding: const EdgeInsets.symmetric(vertical: 10),
                    decoration: BoxDecoration(
                      color: femTopTab == tab ? T.card : Colors.transparent,
                      borderRadius: BorderRadius.circular(10),
                      boxShadow: femTopTab == tab ? T.shadowCard : null,
                    ),
                    child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                      Icon(tab == 'blouse' ? Icons.checkroom_rounded : Icons.dry_cleaning_rounded, size: 14,
                        color: femTopTab == tab ? T.accentDark : T.text3),
                      const SizedBox(width: 6),
                      Text(tab.toUpperCase(), style: T.label.copyWith(
                        color: femTopTab == tab ? T.accentDark : T.text3, fontSize: 12)),
                      // Dot if has data
                      if (meas.keys.any((k) => k.startsWith('${tab}_') && meas[k]!.isNotEmpty)) ...[
                        const SizedBox(width: 4),
                        Container(width: 6, height: 6, decoration: BoxDecoration(color: T.success, shape: BoxShape.circle)),
                      ],
                    ]),
                  ),
                ))).toList()),
              ),
              MeasurementSection(
                key: ValueKey(femTopTab),
                title: femTopTab == 'blouse' ? 'Blouse Measurements' : 'Dress Measurements',
                section: femTopTab == 'blouse' ? 'femaleTopBlouse' : 'femaleTopDress',
                fields: femTopTab == 'blouse' ? C.femaleTopBlouse : C.femaleTopDress,
                values: Map.fromEntries(meas.entries
                  .where((e) => e.key.startsWith('${femTopTab}_'))
                  .map((e) => MapEntry(e.key.substring(femTopTab.length + 1), e.value))),
                onChanged: (f, v) => meas['${femTopTab}_$f'] = v,
                customFields: femTopTab == 'blouse' ? customTopBlouse : customTopDress,
                onAddCustom: (f) => setSt(() {
                  if (femTopTab == 'blouse') customTopBlouse.add(f); else customTopDress.add(f);
                }),
                onRemoveCustom: (f) => setSt(() {
                  if (femTopTab == 'blouse') customTopBlouse.remove(f); else customTopDress.remove(f);
                  meas.remove('${femTopTab}_$f');
                }),
              ),
            ] else
              MeasurementSection(title: 'Top', section: 'maleTop', fields: C.maleTop, values: meas, onChanged: (f, v) => meas[f] = v, customFields: customTop, onAddCustom: (f) => setSt(() => customTop.add(f)), onRemoveCustom: (f) => setSt(() { customTop.remove(f); meas.remove(f); })),
            MeasurementSection(title: 'Bottom', section: gender == 'male' ? 'maleBottom' : 'femaleBottom', fields: gender == 'male' ? C.maleBottom : C.femaleBottom, values: meas, onChanged: (f, v) => meas[f] = v, customFields: customBottom, onAddCustom: (f) => setSt(() => customBottom.add(f)), onRemoveCustom: (f) => setSt(() { customBottom.remove(f); meas.remove(f); })),
            const SizedBox(height: 12),
            TxField(label: _lang.t('notes'), hint: 'Fitting notes...', controller: nt, maxLines: 2),
            const SizedBox(height: 16),
            Text(_lang.t('notification_pref').toUpperCase(), style: T.label),
            const SizedBox(height: 8),
            Wrap(spacing: 8, children: ['WhatsApp', 'SMS', 'Email'].map((n) => GestureDetector(onTap: () => setSt(() => notif = n),
              child: AnimatedContainer(duration: const Duration(milliseconds: 200), padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
                decoration: BoxDecoration(color: notif == n ? T.accent.withOpacity(0.12) : T.surface, borderRadius: BorderRadius.circular(20), border: Border.all(color: notif == n ? T.accent : Colors.transparent, width: 1.5)),
                child: Text(n, style: T.bodySm.copyWith(color: notif == n ? T.accentDark : T.text3, fontWeight: notif == n ? FontWeight.w600 : FontWeight.w400))))).toList()),
            const SizedBox(height: 24),
            Container(height: 52, decoration: BoxDecoration(gradient: T.headerGrad, borderRadius: BorderRadius.circular(T.rMd), boxShadow: [BoxShadow(color: T.headerDark.withOpacity(0.3), blurRadius: 16, offset: const Offset(0, 6))]),
              child: Material(color: Colors.transparent, child: InkWell(onTap: () async {
                if (!fk.currentState!.validate()) return;
                final botF = gender == 'male' ? C.maleBottom : C.femaleBottom;
                final allB = [...botF, ...customBottom];
                final topM = <String, dynamic>{}; final botM = <String, dynamic>{};
                if (gender == 'male') {
                  final allT = [...C.maleTop, ...customTop];
                  meas.forEach((k, v) {
                    if (v.isNotEmpty) {
                      final val = double.tryParse(v) ?? v;
                      if (allB.any((f) => f.toLowerCase() == k.toLowerCase())) botM[k] = val;
                      else topM[k] = val;
                    }
                  });
                } else {
                  // Female: top keys are prefixed blouse_X / dress_X
                  meas.forEach((k, v) {
                    if (v.isNotEmpty) {
                      final val = double.tryParse(v) ?? v;
                      if (k.startsWith('blouse_') || k.startsWith('dress_')) {
                        topM[k] = val;
                      } else if (allB.any((f) => f.toLowerCase() == k.toLowerCase())) {
                        botM[k] = val;
                      } else {
                        topM[k] = val; // fallback
                      }
                    }
                  });
                }
                final cust = Customer(id: c?.id, name: nm.text.trim(), phone: ph.text.trim(), email: em.text.trim(), address: ad.text.trim(), city: ct.text.trim(), dob: dob?.toIso8601String().split('T').first, gender: gender, notify: notif, notes: nt.text.trim(), measurementsTop: topM, measurementsBottom: botM);
                try {
                  if (c == null) await _api.createCustomer(cust); else await _api.updateCustomer(c.id!, cust);
                  if (ctx.mounted) Navigator.pop(ctx);
                  if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(c == null ? _lang.t('customer_added') : _lang.t('customer_updated'))));
                } catch (e) {
                  if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
                } finally {
                  _load(); // always refresh list — customer may have been created even if response parsing failed
                }
              }, borderRadius: BorderRadius.circular(T.rMd), child: Center(child: Text((c == null ? _lang.t('add_customer') : _lang.t('save_changes')).toUpperCase(), style: T.btn.copyWith(color: T.accent, letterSpacing: 1.5)))))),
          ])))
        ]),
      )),
    );
  }

  @override Widget build(BuildContext context) {
    final groups = _groupedCustomers;
    final keys = groups.keys.toList()..sort();

    return Scaffold(backgroundColor: T.bg, body: Column(children: [
      const SizedBox(height: 12),
      // Search Bar
      Padding(padding: const EdgeInsets.fromLTRB(18, 0, 18, 12), child: Container(decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(16), boxShadow: T.shadowCard),
        child: TextField(controller: _sc, style: T.body.copyWith(fontSize: 18),
          decoration: InputDecoration(hintText: _lang.t('search_customers'), prefixIcon: Icon(Icons.search_rounded, size: 20, color: T.text3), suffixIcon: _search.isNotEmpty ? IconButton(icon: const Icon(Icons.close_rounded, size: 20), onPressed: () { _sc.clear(); setState(() => _search = ''); }) : null, border: InputBorder.none, filled: false, contentPadding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12)),
          onChanged: (v) { setState(() => _search = v); }))),

      Expanded(child: _loading 
        ? const Center(child: CircularProgressIndicator(strokeWidth: 1.5, color: T.accent)) 
        : _list.isEmpty 
          ? EmptyState(icon: Icons.people_outline, title: _lang.t('no_customers'), subtitle: _lang.t('add_first_customer'), buttonLabel: _lang.t('add_customer'), onPressed: () => _showForm()) 
          : RefreshIndicator(onRefresh: _load, color: T.accent,
            child: ListView.builder(
              padding: const EdgeInsets.fromLTRB(18, 4, 18, 80),
              itemCount: keys.length,
              itemBuilder: (_, ki) {
                final letter = keys[ki];
                final customers = groups[letter]!;
                return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Padding(padding: const EdgeInsets.fromLTRB(4, 16, 0, 8),
                    child: Text(letter, style: T.label.copyWith(color: T.text3, fontSize: 16))),
                  ...customers.asMap().entries.map((e) {
                    final i = e.key; final c = e.value;
                    final orderCount = _stats[c.id]?['count'] ?? 0;
                    final totalSpent = _stats[c.id]?['total'] ?? 0.0;
                    return Padding(padding: const EdgeInsets.only(bottom: 10), 
                      child: Material(color: T.card, borderRadius: BorderRadius.circular(24), 
                        child: InkWell(onTap: () => _viewCustomer(c, i), borderRadius: BorderRadius.circular(24), 
                          child: Container(padding: const EdgeInsets.all(20), decoration: BoxDecoration(borderRadius: BorderRadius.circular(24), boxShadow: T.shadowCard),
                            child: Row(children: [
                              Container(width: 60, height: 60, 
                                decoration: BoxDecoration(gradient: _avGrad(ki + i), shape: BoxShape.circle), 
                                child: Center(child: Text(c.initials, style: GoogleFonts.prata(fontSize: 22, fontWeight: FontWeight.w400, color: Colors.white)))),
                              const SizedBox(width: 16),
                              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                                Row(children: [
                                  Text(c.name, style: T.body.copyWith(fontSize: 18, fontWeight: FontWeight.w700)),
                                  if (orderCount >= 5) ...[const SizedBox(width: 6), const Icon(Icons.star_rounded, size: 16, color: T.warning)],
                                ]),
                                const SizedBox(height: 2),
                                Text('${c.phone}${c.city?.isNotEmpty == true ? " · ${c.city}" : ""}', 
                                  style: T.bodySm.copyWith(fontSize: 14, color: T.text3)),
                              ])),
                              Column(crossAxisAlignment: CrossAxisAlignment.end, children: [
                                Text('$orderCount order${orderCount == 1 ? '' : 's'}',
                                  style: T.bodySm.copyWith(fontSize: 14, fontWeight: FontWeight.w700, color: T.text)),
                                Text(_fmt.format(totalSpent),
                                  style: T.bodySm.copyWith(fontSize: 13, color: T.text3)),
                              ]),
                            ]),
                          ),
                        ),
                      ),
                    );
                  }).toList(),
                ]);
              },
            ),
          ),
        ),
    ]), floatingActionButton: FloatingActionButton(onPressed: () => _showForm(), child: const Icon(Icons.add_rounded, size: 22)));
  }
}

class _Stat extends StatelessWidget {
  final String label, val; final Color color;
  const _Stat({required this.label, required this.val, required this.color});
  @override Widget build(BuildContext context) => Expanded(child: Container(padding: const EdgeInsets.all(10), decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(10), boxShadow: T.shadowCard), child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text(val, style: T.stat.copyWith(color: color, fontSize: 24)), Text(label, style: T.statLabel)])));
}

class _GenderCard extends StatelessWidget {
  final String label; final IconData icon; final Color color; final bool isSel; final VoidCallback onTap;
  const _GenderCard({required this.label, required this.icon, required this.color, required this.isSel, required this.onTap});
  @override Widget build(BuildContext context) => Expanded(child: GestureDetector(onTap: onTap, child: AnimatedContainer(duration: const Duration(milliseconds: 200), padding: const EdgeInsets.symmetric(vertical: 14), decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(12), boxShadow: T.shadowCard, border: Border.all(color: isSel ? T.accent : Colors.transparent, width: 2)), child: Column(children: [Icon(icon, size: 28, color: color), const SizedBox(height: 5), Text(label, style: TextStyle(fontSize: 14, fontWeight: FontWeight.w600, letterSpacing: 0.6, color: T.text)), Text(isSel ? 'SELECTED' : 'Standard', style: TextStyle(fontSize: 10, color: isSel ? T.accentDark : T.text3, fontWeight: FontWeight.w600, letterSpacing: 0.5))]))));
}

class _MeasView extends StatelessWidget {
  final Map<String, dynamic> measurements; final bool isMale;
  const _MeasView({required this.measurements, required this.isMale});
  @override Widget build(BuildContext context) => GridView.count(
    crossAxisCount: 3, shrinkWrap: true, physics: const NeverScrollableScrollPhysics(),
    crossAxisSpacing: 8, mainAxisSpacing: 8, childAspectRatio: 1.1,
    children: measurements.entries.map((e) => Container(
      padding: const EdgeInsets.all(8),
      decoration: BoxDecoration(color: T.surface, borderRadius: BorderRadius.circular(10)),
      child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
        Text(e.key.replaceAll('_', ' ').toUpperCase(), style: TextStyle(fontSize: 10, fontWeight: FontWeight.w800,
          letterSpacing: 0.5, color: T.text2), textAlign: TextAlign.center, maxLines: 1, overflow: TextOverflow.ellipsis),
        const SizedBox(height: 4),
        RichText(text: TextSpan(children: [
          TextSpan(text: '${e.value}', style: GoogleFonts.prata(
            fontSize: 24, fontWeight: FontWeight.w400, color: T.text)),
          const TextSpan(text: ' in', style: TextStyle(fontSize: 12, fontWeight: FontWeight.bold, color: Color(0xFF9E9EA8))),
        ])),
      ]),
    )).toList());
}

class _FemaleTopView extends StatefulWidget {
  final Map<String, dynamic> measurements;
  const _FemaleTopView({required this.measurements});
  @override State<_FemaleTopView> createState() => _FemaleTopViewState();
}

class _FemaleTopViewState extends State<_FemaleTopView> {
  String _tab = 'blouse';

  Map<String, dynamic> get _filtered {
    final result = <String, dynamic>{};
    widget.measurements.forEach((k, v) {
      if (k.startsWith('${_tab}_')) {
        result[k.substring(_tab.length + 1)] = v;
      } else if (!k.startsWith('blouse_') && !k.startsWith('dress_')) {
        // Legacy unprefixed data — show under blouse tab only
        if (_tab == 'blouse') result[k] = v;
      }
    });
    return result;
  }

  bool _hasData(String tab) => widget.measurements.keys.any(
    (k) => k.startsWith('${tab}_') && widget.measurements[k].toString().isNotEmpty);

  @override Widget build(BuildContext context) {
    final filtered = _filtered;
    return Column(crossAxisAlignment: CrossAxisAlignment.stretch, children: [
      Container(
        margin: const EdgeInsets.only(bottom: 10),
        padding: const EdgeInsets.all(4),
        decoration: BoxDecoration(color: T.surface, borderRadius: BorderRadius.circular(T.rMd)),
        child: Row(children: ['blouse', 'dress'].map((tab) => Expanded(child: GestureDetector(
          onTap: () => setState(() => _tab = tab),
          child: AnimatedContainer(duration: const Duration(milliseconds: 200),
            padding: const EdgeInsets.symmetric(vertical: 8),
            decoration: BoxDecoration(
              color: _tab == tab ? T.card : Colors.transparent,
              borderRadius: BorderRadius.circular(10),
              boxShadow: _tab == tab ? T.shadowCard : null,
            ),
            child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
              Icon(tab == 'blouse' ? Icons.checkroom_rounded : Icons.dry_cleaning_rounded,
                size: 14, color: _tab == tab ? T.accentDark : T.text3),
              const SizedBox(width: 6),
              Text(tab.toUpperCase(), style: T.label.copyWith(
                color: _tab == tab ? T.accentDark : T.text3, fontSize: 12)),
              if (_hasData(tab)) ...[
                const SizedBox(width: 4),
                Container(width: 6, height: 6,
                  decoration: const BoxDecoration(color: T.success, shape: BoxShape.circle)),
              ],
            ]),
          ),
        ))).toList()),
      ),
      if (filtered.isNotEmpty)
        _MeasView(measurements: filtered, isMale: false)
      else
        Padding(
          padding: const EdgeInsets.symmetric(vertical: 16),
          child: Center(child: Text(
            'No ${_tab == 'blouse' ? 'blouse' : 'dress'} measurements recorded',
            style: T.bodySm.copyWith(color: T.text3))),
        ),
    ]);
  }
}

class _ContactRow extends StatelessWidget {
  final IconData icon; final String label, value;
  const _ContactRow(this.icon, this.label, this.value);
  @override Widget build(BuildContext context) => Padding(padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10), child: Row(children: [Icon(icon, size: 20, color: T.text3), const SizedBox(width: 12), Column(crossAxisAlignment: CrossAxisAlignment.start, children: [Text(label, style: T.bodySm.copyWith(fontSize: 12)), Text(value, style: T.body.copyWith(fontWeight: FontWeight.w500, fontSize: 16))])]));
}
