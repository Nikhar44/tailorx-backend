import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:image_picker/image_picker.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/api_service.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import 'auth_screen.dart';
import 'admin_panel_screen.dart';

/// Returns the correct plan badge label for the current boutique account.
String _planBadgeLabel(Api api) {
  if (api.isFree) return 'FREE';
  if (api.boutiquePlan == 'pro') return 'PRO YEARLY';
  if (api.boutiquePlan == 'pro_monthly') return 'PRO MONTHLY';
  if (api.boutiquePlan == 'basic_yearly') return 'BASIC YEARLY';
  if (api.boutiquePlan == 'basic_monthly') return 'BASIC MONTHLY';
  if (api.isTrialActive) return 'TRIAL';
  return 'TRIAL ENDED';
}

class SettingsScreen extends StatefulWidget {
  const SettingsScreen({super.key});
  @override
  State<SettingsScreen> createState() => _SettingsScreenState();
}

class _SettingsScreenState extends State<SettingsScreen> {
  final _api = Api();
  final _lang = AppLang();
  int _logoTaps = 0;

  @override
  void initState() {
    super.initState();
    // Refresh profile from server so settings always show latest data
    _api.refreshProfile().then((_) { if (mounted) setState(() {}); });
  }

  Future<void> _pickAndUploadLogo(ImageSource source) async {
    try {
      final file = await ImagePicker().pickImage(source: source, imageQuality: 75, maxWidth: 512);
      if (file == null) return;
      final bytes = await file.readAsBytes();
      final ext = file.path.split('.').last.toLowerCase();
      final mime = ext == 'png' ? 'image/png' : 'image/jpeg';
      final fileName = 'boutique_logo_${DateTime.now().millisecondsSinceEpoch}.$ext';

      final storage = Supabase.instance.client.storage.from('logos');
      await storage.uploadBinary(fileName, bytes,
          fileOptions: FileOptions(contentType: mime, upsert: true));
      final url = storage.getPublicUrl(fileName);

      await _api.updateBoutiqueProfile(logoUrl: url);
      if (mounted) {
        setState(() {});
        ScaffoldMessenger.of(context).showSnackBar(
            const SnackBar(content: Text('Logo updated!')));
      }
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Upload failed. Try entering a URL instead.')));
    }
  }

  void _showLogoOptions() {
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      useSafeArea: true,
      isScrollControlled: true,
      builder: (ctx) {
        final bottomPad = MediaQuery.of(ctx).padding.bottom;
        return Container(
          decoration: BoxDecoration(
              color: T.bg,
              borderRadius: const BorderRadius.vertical(top: Radius.circular(T.rXl))),
          padding: EdgeInsets.fromLTRB(20, 20, 20, 20 + bottomPad),
          child: SingleChildScrollView(child: Column(mainAxisSize: MainAxisSize.min, children: [
            Container(width: 36, height: 4,
                decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2))),
            const SizedBox(height: 16),
            Text('Business Logo', style: T.displaySm),
            const SizedBox(height: 8),
            Text('Choose how to set your boutique logo', style: T.bodySm),
            const SizedBox(height: 20),
            _LogoOption(
              icon: Icons.photo_library_rounded, color: T.info,
              label: 'Choose from Gallery',
              sub: 'Pick a photo from your phone',
              onTap: () { Navigator.pop(ctx); _pickAndUploadLogo(ImageSource.gallery); },
            ),
            const SizedBox(height: 10),
            _LogoOption(
              icon: Icons.camera_alt_rounded, color: T.success,
              label: 'Take a Photo',
              sub: 'Use your camera',
              onTap: () { Navigator.pop(ctx); _pickAndUploadLogo(ImageSource.camera); },
            ),
            const SizedBox(height: 10),
            _LogoOption(
              icon: Icons.link_rounded, color: T.purple,
              label: 'Enter URL',
              sub: 'Paste an image link',
              onTap: () { Navigator.pop(ctx);
                _editProfile('Logo URL', _api.boutiqueLogo,
                    (v) => _api.updateBoutiqueProfile(logoUrl: v)); },
            ),
            if (_api.boutiqueLogo != null) ...[
              const SizedBox(height: 10),
              _LogoOption(
                icon: Icons.delete_outline_rounded, color: T.danger,
                label: 'Remove Logo',
                sub: 'Clear current logo',
                onTap: () async {
                  Navigator.pop(ctx);
                  await _api.updateBoutiqueProfile(logoUrl: '');
                  if (mounted) setState(() {});
                },
              ),
            ],
          ])),
        );
      },
    );
  }

  void _editProfile(String title, String? initial, Function(String) onSave) {
    final ctrl = TextEditingController(text: initial);
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(T.rMd)),
        title: Text('Edit $title', style: T.heading),
        content: TextField(
          controller: ctrl,
          autofocus: true,
          maxLines: title.contains('Address') ? 3 : 1,
          decoration: InputDecoration(hintText: 'Enter $title'),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: Text(_lang.t('cancel'))),
          ElevatedButton(
            onPressed: () async {
              await onSave(ctrl.text.trim());
              if (mounted) setState(() {});
              if (ctx.mounted) Navigator.pop(ctx);
            },
            child: const Text('SAVE'),
          ),
        ],
      ),
    );
  }

  void _editTerms() {
    final ctrl = TextEditingController(text: _api.termsAndConditions);
    showModalBottomSheet(
      context: context,
      backgroundColor: Colors.transparent,
      useSafeArea: true,
      isScrollControlled: true,
      builder: (ctx) {
        final bottomPad = MediaQuery.of(ctx).viewInsets.bottom + MediaQuery.of(ctx).padding.bottom;
        return Container(
          decoration: BoxDecoration(
            color: T.bg,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(T.rXl))),
          padding: EdgeInsets.fromLTRB(20, 20, 20, 20 + bottomPad),
          child: Column(mainAxisSize: MainAxisSize.min, crossAxisAlignment: CrossAxisAlignment.start, children: [
            Center(child: Container(width: 36, height: 4,
              decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2)))),
            const SizedBox(height: 16),
            Row(children: [
              Container(width: 36, height: 36,
                decoration: BoxDecoration(
                  color: T.warning.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(8)),
                child: const Icon(Icons.description_rounded, size: 18, color: T.warning)),
              const SizedBox(width: 10),
              Text('Terms & Conditions', style: T.displaySm),
            ]),
            const SizedBox(height: 6),
            Text('These terms will appear at the bottom of every bill/invoice.',
              style: T.bodySm.copyWith(fontSize: 12)),
            const SizedBox(height: 14),
            TextField(
              controller: ctrl,
              maxLines: 8,
              autofocus: true,
              decoration: InputDecoration(
                hintText: 'e.g.\n1. Goods once sold will not be returned.\n2. Payment must be made before delivery.\n3. We are not responsible for any delay due to fabric shortage.',
                hintMaxLines: 6,
                border: OutlineInputBorder(borderRadius: BorderRadius.circular(T.rMd)),
                contentPadding: const EdgeInsets.all(14),
              ),
            ),
            const SizedBox(height: 14),
            Row(children: [
              Expanded(child: OutlinedButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('CANCEL'),
              )),
              const SizedBox(width: 10),
              Expanded(child: ElevatedButton(
                onPressed: () async {
                  await _api.setTermsAndConditions(ctrl.text.trim());
                  if (mounted) setState(() {});
                  if (ctx.mounted) Navigator.pop(ctx);
                  if (mounted) ScaffoldMessenger.of(context).showSnackBar(
                    const SnackBar(content: Text('Terms & Conditions saved!')));
                },
                child: const Text('SAVE'),
              )),
            ]),
          ]),
        );
      },
    );
  }

  Future<void> _showAdminEntry() async {
    final ctrl = TextEditingController();
    await showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: T.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(16)),
        title: Row(children: [
          const Icon(Icons.admin_panel_settings_rounded, color: T.accent, size: 22),
          const SizedBox(width: 8),
          Text('Admin Access', style: T.heading.copyWith(fontSize: 18)),
        ]),
        content: TextField(
          controller: ctrl,
          obscureText: true,
          autofocus: true,
          decoration: InputDecoration(
            hintText: 'Enter admin secret',
            border: OutlineInputBorder(borderRadius: BorderRadius.circular(10)),
          ),
          onSubmitted: (_) => Navigator.pop(ctx),
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('Cancel')),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: T.accent),
            onPressed: () => Navigator.pop(ctx),
            child: Text('ENTER', style: TextStyle(color: T.headerDark, fontWeight: FontWeight.w800)),
          ),
        ],
      ),
    );
    final secret = ctrl.text.trim();
    if (secret.isEmpty) return;
    if (!mounted) return;
    Navigator.of(context).push(MaterialPageRoute(
      builder: (_) => AdminPanelScreen(adminSecret: secret),
    ));
  }

  @override
  Widget build(BuildContext context) {
    return ListView(padding: const EdgeInsets.fromLTRB(18, 0, 18, 40), children: [
      // ── Profile Hero (matching .profile-hero) ──
      Container(
        margin: const EdgeInsets.only(bottom: 16, top: 12),
        padding: const EdgeInsets.all(20),
        decoration: BoxDecoration(
          gradient: T.headerGrad,
          borderRadius: BorderRadius.circular(T.rLg),
          boxShadow: [BoxShadow(color: T.headerDark.withOpacity(0.4), blurRadius: 24, offset: const Offset(0, 8))]),
        child: Row(children: [
          Container(width: 72, height: 72,
            decoration: BoxDecoration(gradient: T.accentGrad, borderRadius: BorderRadius.circular(16),
              boxShadow: [BoxShadow(color: T.accent.withOpacity(0.4), blurRadius: 16, offset: const Offset(0, 4))]),
            child: Center(child: Text(
              (_api.boutiqueName ?? 'TX').split(' ').take(2).map((e) => e.isNotEmpty ? e[0].toUpperCase() : '').join(),
              style: GoogleFonts.prata(fontSize: 28, fontWeight: FontWeight.w400, color: T.headerDark)))),
          const SizedBox(width: 14),
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(_api.boutiqueName ?? 'My Boutique',
              style: GoogleFonts.prata(fontSize: 24, fontWeight: FontWeight.w400, color: Colors.white)),
            const SizedBox(height: 3),
            Text(_api.boutiqueEmail ?? '', style: TextStyle(fontSize: 14, color: Colors.white.withOpacity(0.45))),
            const SizedBox(height: 6),
            Container(padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(color: T.accent.withOpacity(0.2), borderRadius: BorderRadius.circular(4)),
              child: Text(_planBadgeLabel(_api), style: TextStyle(fontSize: 10, fontWeight: FontWeight.w700,
                letterSpacing: 1.2, color: T.accent))),
          ])),
        ]),
      ),

      // ── Language (matching .lang-section) ──
      _Section(title: _lang.t('language'), children: [
        Padding(padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 10),
          child: Row(children: [
            Container(width: 40, height: 40,
              decoration: BoxDecoration(color: T.info.withOpacity(0.1), borderRadius: BorderRadius.circular(8)),
              child: const Icon(Icons.language_rounded, size: 20, color: T.info)),
            const SizedBox(width: 12),
            Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Text(_lang.t('select_language'), style: T.body.copyWith(fontWeight: FontWeight.w500, fontSize: 16)),
              Text(AppLang.supportedLanguages[_lang.locale] ?? 'English',
                style: T.bodySm.copyWith(fontSize: 12)),
            ])),
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 4),
              decoration: BoxDecoration(color: T.surface, borderRadius: BorderRadius.circular(8)),
              child: DropdownButton<String>(
                value: _lang.locale, underline: const SizedBox(), isDense: true,
                style: T.body.copyWith(fontSize: 14),
                items: AppLang.supportedLanguages.entries.map((e) =>
                  DropdownMenuItem(value: e.key, child: Text(e.value))).toList(),
                onChanged: (v) async {
                  if (v != null) { await _lang.setLocale(v); if (mounted) setState(() {}); }
                },
              ),
            ),
          ])),
      ]),
      const SizedBox(height: 12),

      // ── Boutique Info ──
      _Section(title: _lang.t('boutique_info'), children: [
        _Row(
          icon: Icons.store_rounded, color: T.accent,
          title: (_api.boutiqueName?.isNotEmpty == true) ? _api.boutiqueName! : 'My Boutique',
          sub: _lang.t('boutique_name'),
          onTap: () => _editProfile('Shop Name', _api.boutiqueName, (v) => _api.updateBoutiqueProfile(name: v)),
        ),
        _Divider(),
        _Row(
          icon: Icons.image_rounded, color: T.purple,
          title: _api.boutiqueLogo != null ? 'Logo set ✓' : 'Add Business Logo',
          sub: 'Upload photo or enter URL',
          trailing: _api.boutiqueLogo != null
              ? ClipRRect(borderRadius: BorderRadius.circular(6),
                  child: Image.network(_api.boutiqueLogo!, width: 36, height: 36, fit: BoxFit.cover,
                      errorBuilder: (_, __, ___) => const Icon(Icons.broken_image_rounded, size: 20)))
              : const Icon(Icons.chevron_right_rounded, size: 20, color: T.text3),
          onTap: _showLogoOptions,
        ),
        _Divider(),
        _Row(
          icon: Icons.location_on_rounded, color: T.success,
          title: (_api.boutiqueAddress?.isNotEmpty == true) ? _api.boutiqueAddress! : 'Set shop address',
          sub: 'Address',
          onTap: () => _editProfile('Shop Address', _api.boutiqueAddress, (v) => _api.updateBoutiqueProfile(address: v)),
        ),
        _Divider(),
        _Row(
          icon: Icons.phone_rounded, color: T.teal,
          title: (_api.boutiquePhone?.isNotEmpty == true) ? _api.boutiquePhone! : 'Add Phone Number',
          sub: 'Phone / WhatsApp',
          onTap: () => _editProfile('Phone Number', _api.boutiquePhone,
              (v) => _api.updateBoutiqueProfile(phone: v)),
        ),
        _Divider(),
        _Row(
          icon: Icons.receipt_long_rounded, color: T.info,
          title: (_api.boutiqueGST?.isNotEmpty == true) ? _api.boutiqueGST! : 'Add GST Number',
          sub: 'GST / Tax ID',
          onTap: () => _editProfile('GST Number', _api.boutiqueGST, (v) => _api.updateBoutiqueProfile(gst: v)),
        ),
        _Divider(),
        _Row(icon: Icons.email_rounded, color: T.purple,
          title: _api.boutiqueEmail ?? 'Not set', sub: 'Email'),
      ]),
      const SizedBox(height: 12),

      // ── Terms & Conditions ──
      _Section(title: 'TERMS & CONDITIONS', children: [
        InkWell(
          onTap: _editTerms,
          child: Padding(
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
            child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
              Container(width: 40, height: 40,
                decoration: BoxDecoration(
                  color: T.warning.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(8)),
                child: const Icon(Icons.description_rounded, size: 20, color: T.warning)),
              const SizedBox(width: 12),
              Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                Text('Bill Terms & Conditions',
                  style: T.body.copyWith(fontWeight: FontWeight.w500, fontSize: 16)),
                const SizedBox(height: 4),
                Text(
                  _api.termsAndConditions.isNotEmpty
                    ? _api.termsAndConditions
                    : 'Tap to add terms shown on every bill/invoice',
                  style: T.bodySm.copyWith(fontSize: 12),
                  maxLines: 2, overflow: TextOverflow.ellipsis),
              ])),
              const SizedBox(width: 8),
              const Icon(Icons.edit_rounded, size: 16, color: T.text3),
            ]),
          ),
        ),
      ]),
      const SizedBox(height: 12),

      // ── Plan & Billing ──
      _PlanBillingSection(api: _api),

      // ── App Settings ──
      _Section(title: 'APP SETTINGS', children: [
        _Row(icon: Icons.palette_rounded, color: T.teal,
          title: 'Theme', sub: 'Dark header + Light content',
          trailing: Container(padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 5),
            decoration: BoxDecoration(color: T.surface, borderRadius: BorderRadius.circular(6)),
            child: Text('DEFAULT', style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600,
              letterSpacing: 0.8, color: T.text3)))),
        _Divider(),
        _Row(icon: Icons.notifications_rounded, color: T.warning,
          title: 'Notifications', sub: 'Push, SMS, WhatsApp',
          trailing: Container(width: 36, height: 20,
            decoration: BoxDecoration(color: T.success, borderRadius: BorderRadius.circular(10)),
            child: Align(alignment: Alignment.centerRight,
              child: Container(width: 16, height: 16, margin: const EdgeInsets.only(right: 2),
                decoration: BoxDecoration(color: Colors.white, shape: BoxShape.circle))))),
        _Divider(),
        _Row(icon: Icons.backup_rounded, color: T.info,
          title: 'Data Backup', sub: 'Auto-sync enabled',
          trailing: const Icon(Icons.check_circle_rounded, size: 16, color: T.success)),
      ]),
      const SizedBox(height: 12),

      // ── Contact & Support ──
      _Section(title: _lang.t('contact_support'), children: [
        _Row(icon: Icons.chat_rounded, color: const Color(0xFF25D366),
          title: _lang.t('whatsapp_support'), sub: 'Fastest response — chat with us',
          trailing: const Icon(Icons.open_in_new_rounded, size: 14, color: T.text3),
          onTap: () => launchUrl(
            Uri.parse('https://wa.me/918469696966?text=${Uri.encodeComponent('Hi, I need help with my TailorX account.')}'),
            mode: LaunchMode.externalApplication)),
        _Divider(),
        _Row(icon: Icons.email_rounded, color: T.info,
          title: _lang.t('email_us'), sub: 'support@tailorx.in',
          trailing: const Icon(Icons.open_in_new_rounded, size: 14, color: T.text3),
          onTap: () => launchUrl(Uri.parse(
            'mailto:support@tailorx.in?subject=TailorX Support&body=Hi, I need help with my account.'))),
        _Divider(),
        _Row(icon: Icons.bug_report_rounded, color: T.danger,
          title: _lang.t('report_bug'), sub: 'Found a bug? Help us fix it',
          trailing: const Icon(Icons.open_in_new_rounded, size: 14, color: T.text3),
          onTap: () => launchUrl(Uri.parse(
            'mailto:support@tailorx.in?subject=Bug Report - TailorX&body=Describe the bug:\n\nSteps to reproduce:\n\n'))),
      ]),
      const SizedBox(height: 12),

      // ── About ──
      _Section(title: _lang.t('about'), children: [
        _Row(icon: Icons.info_rounded, color: T.text3,
          title: 'TailorX', sub: '${_lang.t("version")} 3.0.0'),
        _Divider(),
        _Row(icon: Icons.code_rounded, color: T.text3,
          title: 'Built for Boutique Owners', sub: 'Surat, Gujarat, India'),
      ]),
      const SizedBox(height: 20),

      // ── Sign Out (matching .sign-out) ──
      GestureDetector(
        onTap: () async {
          final ok = await showDialog<bool>(context: context, builder: (ctx) => AlertDialog(
            shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(T.rMd)),
            title: Text(_lang.t('sign_out'), style: T.heading.copyWith(fontSize: 22)),
            content: Text(_lang.t('sign_out_confirm'), style: T.body.copyWith(fontSize: 18)),
            actions: [
              TextButton(onPressed: () => Navigator.pop(ctx, false), child: Text(_lang.t('cancel'), style: const TextStyle(fontSize: 16))),
              ElevatedButton(style: ElevatedButton.styleFrom(backgroundColor: T.danger),
                onPressed: () => Navigator.pop(ctx, true), child: Text(_lang.t('sign_out').toUpperCase(), style: const TextStyle(fontSize: 16))),
            ],
          ));
          if (ok == true) {
            await _api.logout();
            if (mounted) Navigator.of(context).pushReplacement(
              MaterialPageRoute(builder: (_) => const AuthScreen()));
          }
        },
        child: Container(
          padding: const EdgeInsets.symmetric(vertical: 14),
          decoration: BoxDecoration(
            border: Border.all(color: T.danger.withOpacity(0.3)),
            borderRadius: BorderRadius.circular(T.rMd)),
          child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
            const Icon(Icons.logout_rounded, size: 20, color: T.danger),
            const SizedBox(width: 8),
            Text(_lang.t('sign_out').toUpperCase(), style: TextStyle(
              fontSize: 14, fontWeight: FontWeight.w600, letterSpacing: 1, color: T.danger)),
          ]),
        ),
      ),
      const SizedBox(height: 28),

      // ── Branding footer (tap TX logo 5× to open admin) ──
      Center(child: Column(children: [
        GestureDetector(
          onTap: () {
            setState(() => _logoTaps++);
            if (_logoTaps >= 5) {
              setState(() => _logoTaps = 0);
              _showAdminEntry();
            }
          },
          child: Container(width: 44, height: 44,
            decoration: BoxDecoration(gradient: T.accentGrad, borderRadius: BorderRadius.circular(10)),
            child: Center(child: Text('TX', style: TextStyle(
              fontSize: 16, fontWeight: FontWeight.w800, color: T.headerDark, letterSpacing: 1))))),
        const SizedBox(height: 8),
        Text('TAILORX', style: T.label.copyWith(fontSize: 18, letterSpacing: 4, color: T.text3)),
        const SizedBox(height: 3),
        Text(_lang.t('crafted'), style: T.bodySm.copyWith(fontStyle: FontStyle.italic, fontSize: 12)),
      ])),
    ]);
  }
}

class _Section extends StatelessWidget {
  final String title; final List<Widget> children;
  const _Section({required this.title, required this.children});
  @override
  Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text(title.toUpperCase(), style: T.label),
    const SizedBox(height: 8),
    Container(
      decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
      child: Column(children: children)),
  ]);
}

class _Row extends StatelessWidget {
  final IconData icon; final Color color; final String title, sub;
  final Widget? trailing; final VoidCallback? onTap;
  const _Row({required this.icon, required this.color, required this.title,
    required this.sub, this.trailing, this.onTap});
  @override
  Widget build(BuildContext context) => InkWell(onTap: onTap,
    child: Padding(padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 11),
      child: Row(children: [
        Container(width: 40, height: 40,
          decoration: BoxDecoration(color: color.withOpacity(0.1), borderRadius: BorderRadius.circular(8)),
          child: Icon(icon, size: 20, color: color)),
        const SizedBox(width: 12),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(title, style: T.body.copyWith(fontWeight: FontWeight.w500, fontSize: 16)),
          Text(sub, style: T.bodySm.copyWith(fontSize: 12)),
        ])),
        if (trailing != null) trailing!,
      ])));
}

class _Divider extends StatelessWidget {
  @override
  Widget build(BuildContext context) => Container(
    margin: const EdgeInsets.symmetric(horizontal: 14),
    height: 1, color: T.border);
}

class _PlanBillingSection extends StatelessWidget {
  final Api api;
  const _PlanBillingSection({required this.api});

  void _contactToUpgrade(BuildContext context) {
    launchUrl(
      Uri.parse('https://wa.me/918469696966?text=${Uri.encodeComponent('Hi, I want to upgrade my TailorX plan.')}'),
      mode: LaunchMode.externalApplication,
    );
  }

  @override
  Widget build(BuildContext context) {
    final isFree   = api.isFree;
    final isPaid   = const ['monthly', 'yearly', 'pro', 'pro_monthly']
        .contains(api.boutiquePlan);
    final daysLeft = api.trialDaysRemaining;
    final isExpired = !isFree && !isPaid && daysLeft <= 0;

    const planNames = {
      'monthly': 'Monthly Plan',
      'yearly': 'Yearly Plan',
      'pro': 'Pro Yearly',
      'pro_monthly': 'Pro Monthly',
    };

    return Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text('PLAN & BILLING', style: T.label),
      const SizedBox(height: 8),

      // ── Current status banner ──
      Container(
        width: double.infinity,
        padding: const EdgeInsets.all(16),
        decoration: BoxDecoration(
          gradient: isFree || isPaid ? T.headerGrad : LinearGradient(
            colors: isExpired
              ? [T.danger.withOpacity(0.8), T.danger]
              : [const Color(0xFF1a1a2e), const Color(0xFF16213e)],
          ),
          borderRadius: BorderRadius.circular(T.rMd),
          boxShadow: T.shadowCard,
        ),
        child: Row(children: [
          Container(width: 44, height: 44,
            decoration: BoxDecoration(
              color: Colors.white.withOpacity(0.1),
              borderRadius: BorderRadius.circular(10)),
            child: Icon(
              isFree ? Icons.card_giftcard_rounded
                : isPaid ? Icons.verified_rounded
                : isExpired ? Icons.lock_rounded
                : Icons.hourglass_top_rounded,
              size: 22, color: T.accent)),
          const SizedBox(width: 12),
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(
              isFree ? 'Free Account'
                : isPaid ? (planNames[api.boutiquePlan] ?? 'Paid Plan')
                : isExpired ? 'Trial Expired'
                : 'Free Trial',
              style: const TextStyle(
                fontSize: 16, fontWeight: FontWeight.w700,
                color: Colors.white, letterSpacing: 0.3)),
            const SizedBox(height: 2),
            Text(
              isFree ? 'Complimentary access — no payment needed'
                : isPaid ? 'Active — thank you for subscribing!'
                : isExpired ? 'Contact us to activate your plan'
                : '$daysLeft day${daysLeft == 1 ? '' : 's'} remaining',
              style: TextStyle(fontSize: 12, color: Colors.white.withOpacity(0.7))),
          ])),
          if (!isFree && !isPaid)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 4),
              decoration: BoxDecoration(
                color: isExpired ? Colors.white.withOpacity(0.2) : T.accent.withOpacity(0.2),
                borderRadius: BorderRadius.circular(6)),
              child: Text(
                isExpired ? 'EXPIRED' : '$daysLeft days',
                style: TextStyle(
                  fontSize: 10, fontWeight: FontWeight.w800,
                  color: isExpired ? Colors.white : T.accent,
                  letterSpacing: 1))),
        ]),
      ),

      const SizedBox(height: 12),

      // ── AI Measurement usage (Pro plans) ──
      if (api.boutiquePlan == 'pro' || api.boutiquePlan == 'pro_monthly')
        FutureBuilder<Map<String, dynamic>>(
          future: api.getAIMeasurementUsage(),
          builder: (context, snap) {
            if (!snap.hasData) return const SizedBox.shrink();
            final u = snap.data!;
            final unlimited = u['unlimited'] == true;
            return Container(
              margin: const EdgeInsets.only(bottom: 12),
              padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
              decoration: BoxDecoration(
                color: T.card,
                borderRadius: BorderRadius.circular(T.rMd),
                boxShadow: T.shadowCard),
              child: Row(children: [
                const Text('✨', style: TextStyle(fontSize: 16)),
                const SizedBox(width: 10),
                Expanded(child: Text(
                  unlimited
                      ? 'AI Measurement Suggestions: Unlimited'
                      : 'AI Measurement Suggestions: ${u['remaining']}/${u['limit']} left this month',
                  style: T.bodySm.copyWith(fontWeight: FontWeight.w600))),
              ]),
            );
          },
        ),

      // ── Plan cards ──
      if (!isFree && !isPaid) ...[
        Row(children: [
          // Monthly card
          Expanded(child: _PlanCard(
            label: 'MONTHLY',
            price: '₹499',
            period: 'per month',
            features: ['All features', 'Cancel anytime', 'WhatsApp support'],
            isPopular: false,
            onTap: () => _contactToUpgrade(context),
          )),
          const SizedBox(width: 10),
          // Yearly card
          Expanded(child: _PlanCard(
            label: 'YEARLY',
            price: '₹3,999',
            period: 'per year',
            features: ['All features', 'Save ₹2,000', '2 months free'],
            isPopular: true,
            onTap: () => _contactToUpgrade(context),
          )),
        ]),
        const SizedBox(height: 10),
        // Contact CTA
        GestureDetector(
          onTap: () => _contactToUpgrade(context),
          child: Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 13),
            decoration: BoxDecoration(
              color: const Color(0xFF25D366).withOpacity(0.1),
              borderRadius: BorderRadius.circular(T.rMd),
              border: Border.all(color: const Color(0xFF25D366).withOpacity(0.4)),
            ),
            child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
              const Icon(Icons.chat_rounded, size: 18, color: Color(0xFF25D366)),
              const SizedBox(width: 8),
              Text('Contact us on WhatsApp to activate',
                style: T.body.copyWith(
                  fontSize: 13, color: const Color(0xFF25D366),
                  fontWeight: FontWeight.w600)),
            ]),
          ),
        ),
      ],
    ]);
  }
}

class _PlanCard extends StatelessWidget {
  final String label, price, period;
  final List<String> features;
  final bool isPopular;
  final VoidCallback onTap;
  const _PlanCard({required this.label, required this.price, required this.period,
    required this.features, required this.isPopular, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        padding: const EdgeInsets.all(14),
        decoration: BoxDecoration(
          color: isPopular ? T.headerDark : T.card,
          borderRadius: BorderRadius.circular(T.rMd),
          border: Border.all(
            color: isPopular ? T.accent.withOpacity(0.5) : T.border,
            width: isPopular ? 1.5 : 1),
          boxShadow: T.shadowCard,
        ),
        child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          // Popular badge
          if (isPopular)
            Container(
              padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
              decoration: BoxDecoration(
                color: T.accent.withOpacity(0.2),
                borderRadius: BorderRadius.circular(4)),
              child: Text('BEST VALUE', style: TextStyle(
                fontSize: 9, fontWeight: FontWeight.w800,
                color: T.accent, letterSpacing: 1))),
          if (isPopular) const SizedBox(height: 8),

          Text(label, style: TextStyle(
            fontSize: 11, fontWeight: FontWeight.w700,
            color: isPopular ? T.accent : T.text3, letterSpacing: 1.2)),
          const SizedBox(height: 4),
          Text(price, style: TextStyle(
            fontSize: 22, fontWeight: FontWeight.w800,
            color: isPopular ? Colors.white : T.text)),
          Text(period, style: TextStyle(
            fontSize: 11, color: isPopular ? Colors.white38 : T.text3)),
          const SizedBox(height: 10),
          ...features.map((f) => Padding(
            padding: const EdgeInsets.only(bottom: 4),
            child: Row(children: [
              Icon(Icons.check_circle_rounded, size: 13,
                color: isPopular ? T.accent : T.success),
              const SizedBox(width: 5),
              Expanded(child: Text(f, style: TextStyle(
                fontSize: 11,
                color: isPopular ? Colors.white70 : T.text2))),
            ]),
          )),
          const SizedBox(height: 10),
          Container(
            width: double.infinity,
            padding: const EdgeInsets.symmetric(vertical: 8),
            decoration: BoxDecoration(
              color: isPopular ? T.accent.withOpacity(0.2) : T.surface,
              borderRadius: BorderRadius.circular(8)),
            child: Text('Choose Plan',
              textAlign: TextAlign.center,
              style: TextStyle(
                fontSize: 12, fontWeight: FontWeight.w700,
                color: isPopular ? T.accent : T.text2,
                letterSpacing: 0.5))),
        ]),
      ),
    );
  }
}

class _LogoOption extends StatelessWidget {
  final IconData icon; final Color color;
  final String label, sub; final VoidCallback onTap;
  const _LogoOption({required this.icon, required this.color,
    required this.label, required this.sub, required this.onTap});
  @override
  Widget build(BuildContext context) => InkWell(onTap: onTap,
    borderRadius: BorderRadius.circular(T.rMd),
    child: Container(padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd),
        boxShadow: T.shadowCard),
      child: Row(children: [
        Container(width: 44, height: 44,
          decoration: BoxDecoration(color: color.withOpacity(0.1), borderRadius: BorderRadius.circular(10)),
          child: Icon(icon, size: 22, color: color)),
        const SizedBox(width: 14),
        Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
          Text(label, style: T.body.copyWith(fontWeight: FontWeight.w600, fontSize: 16)),
          Text(sub, style: T.bodySm.copyWith(fontSize: 12)),
        ])),
        Icon(Icons.chevron_right_rounded, size: 18, color: T.text3),
      ])));
}
