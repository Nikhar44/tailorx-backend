import 'package:flutter/material.dart';
import 'package:flutter_facebook_auth/flutter_facebook_auth.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:google_sign_in/google_sign_in.dart';
import 'package:url_launcher/url_launcher.dart';
import '../services/api_service.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import '../widgets/common_widgets.dart';
import 'home_screen.dart';

class AuthScreen extends StatefulWidget {
  const AuthScreen({super.key});
  @override
  State<AuthScreen> createState() => _AuthState();
}

class _AuthState extends State<AuthScreen> with SingleTickerProviderStateMixin {
  // Mode & step
  bool _login = true;
  int _step = 1; // 1 or 2 (only for register)

  // Shared state
  bool _loading = false, _obscure = true;

  // Form keys — one per step
  final _fk1 = GlobalKey<FormState>();
  final _fk2 = GlobalKey<FormState>();

  // Step 1 controllers
  final _name      = TextEditingController();
  final _ownerName = TextEditingController();
  final _email     = TextEditingController();
  final _pass      = TextEditingController();

  // Step 2 controllers
  final _phone   = TextEditingController();
  final _city    = TextEditingController();
  final _address = TextEditingController();

  final _api  = Api();
  final _lang = AppLang();

  late AnimationController _anim;
  late Animation<double> _fade, _slide;

  @override
  void initState() {
    super.initState();
    _anim  = AnimationController(vsync: this, duration: const Duration(milliseconds: 700));
    _fade  = CurvedAnimation(parent: _anim, curve: Curves.easeOut);
    _slide = Tween(begin: 40.0, end: 0.0)
        .animate(CurvedAnimation(parent: _anim, curve: Curves.easeOut));
    _anim.forward();
  }

  @override
  void dispose() {
    _anim.dispose();
    _name.dispose(); _ownerName.dispose(); _email.dispose(); _pass.dispose();
    _phone.dispose(); _city.dispose(); _address.dispose();
    super.dispose();
  }

  // ─── Switch between login / register ───────────────────────────
  void _switchMode() {
    setState(() {
      _login = !_login;
      _step  = 1;
      _fk1.currentState?.reset();
      _fk2.currentState?.reset();
    });
  }

  // ─── Forgot password dialog ─────────────────────────────────────
  void _forgotPassword() {
    showDialog(
      context: context,
      builder: (ctx) => AlertDialog(
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(T.rMd)),
        title: const Text('Forgot Password?'),
        content: const Text(
          'To reset your password, please contact TailorX support.\n\n'
          'We will reset it for you within a few minutes.',
        ),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx), child: const Text('OK')),
        ],
      ),
    );
  }

  // ─── Contact Us bottom sheet ────────────────────────────────────
  void _showContactSheet(BuildContext context) {
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
            borderRadius: const BorderRadius.vertical(top: Radius.circular(24)),
          ),
          padding: EdgeInsets.fromLTRB(24, 20, 24, 20 + bottomPad),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            // Handle bar
            Container(width: 36, height: 4,
              decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2))),
            const SizedBox(height: 20),

            // Icon + Title
            Container(width: 56, height: 56,
              decoration: BoxDecoration(
                color: T.accentDark.withOpacity(0.1),
                borderRadius: BorderRadius.circular(16)),
              child: const Icon(Icons.support_agent_rounded, size: 28, color: T.accentDark)),
            const SizedBox(height: 12),
            Text('Contact Us', style: T.displaySm),
            const SizedBox(height: 6),
            Text(
              'Account on hold or need support?\nWe\'re here to help.',
              style: T.bodySm.copyWith(fontSize: 13),
              textAlign: TextAlign.center,
            ),
            const SizedBox(height: 24),

            // WhatsApp button
            _ContactOption(
              icon: Icons.chat_rounded,
              color: const Color(0xFF25D366),
              label: 'Chat on WhatsApp',
              sub: 'Fastest response — usually within minutes',
              onTap: () {
                Navigator.pop(ctx);
                launchUrl(
                  Uri.parse('https://wa.me/14373664452?text=Hi, I need help with my TailorX account.'),
                  mode: LaunchMode.externalApplication,
                );
              },
            ),
            const SizedBox(height: 12),

            // Email button
            _ContactOption(
              icon: Icons.email_rounded,
              color: T.info,
              label: 'Email Support',
              sub: 'support@tailorx.in',
              onTap: () {
                Navigator.pop(ctx);
                launchUrl(Uri.parse(
                  'mailto:support@tailorx.in?subject=TailorX Account Help&body=Hi, I need help with my account.'));
              },
            ),
            const SizedBox(height: 20),
          ]),
        );
      },
    );
  }

  // ─── Social sign-in: Google ─────────────────────────────────────
  Future<void> _signInWithGoogle() async {
    setState(() => _loading = true);
    try {
      final googleUser = await GoogleSignIn().signIn();
      if (googleUser == null) { setState(() => _loading = false); return; }
      final googleAuth = await googleUser.authentication;
      final idToken = googleAuth.idToken;
      if (idToken == null) throw Exception('Google sign-in failed — no token');

      final r = await _api.socialLogin(
        provider: 'google',
        idToken:  idToken,
        name:     googleUser.displayName,
        email:    googleUser.email,
      );
      if (!mounted) return;
      if (r['success'] == true) {
        if (r['isNewUser'] == true) {
          _showProfileCompletion();
        } else {
          Navigator.of(context).pushReplacement(
              MaterialPageRoute(builder: (_) => const HomeScreen()));
        }
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(r['message'] ?? 'Google sign-in failed'),
                backgroundColor: T.danger));
      }
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$e'), backgroundColor: T.danger));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  // ─── Social sign-in: Facebook ───────────────────────────────────
  Future<void> _signInWithFacebook() async {
    setState(() => _loading = true);
    try {
      final result = await FacebookAuth.instance.login(
        permissions: ['email', 'public_profile'],
      );
      if (result.status != LoginStatus.success) {
        setState(() => _loading = false);
        return;
      }
      final accessToken = result.accessToken?.tokenString;
      if (accessToken == null) throw Exception('Facebook sign-in failed — no token');
      final userData = await FacebookAuth.instance.getUserData(fields: 'name,email');

      final r = await _api.socialLogin(
        provider: 'facebook',
        idToken:  accessToken,
        name:     userData['name']?.toString(),
        email:    userData['email']?.toString(),
      );
      if (!mounted) return;
      if (r['success'] == true) {
        if (r['isNewUser'] == true) {
          _showProfileCompletion();
        } else {
          Navigator.of(context).pushReplacement(
              MaterialPageRoute(builder: (_) => const HomeScreen()));
        }
      } else {
        ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(r['message'] ?? 'Facebook sign-in failed'),
                backgroundColor: T.danger));
      }
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('$e'), backgroundColor: T.danger));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  // ─── Profile completion for new social users ─────────────────────
  void _showProfileCompletion() {
    final nameCtrl  = TextEditingController(text: _api.boutiqueName);
    final phoneCtrl = TextEditingController();
    final cityCtrl  = TextEditingController();
    final fk        = GlobalKey<FormState>();
    bool saving     = false;

    showModalBottomSheet(
      context: context,
      isDismissible: false,
      enableDrag: false,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setSt) => Container(
          padding: EdgeInsets.only(
            bottom: MediaQuery.of(ctx).viewInsets.bottom + 24,
            left: 24, right: 24, top: 24),
          decoration: BoxDecoration(
            color: T.bg,
            borderRadius: const BorderRadius.vertical(top: Radius.circular(T.rXl))),
          child: Form(key: fk, child: Column(mainAxisSize: MainAxisSize.min,
            crossAxisAlignment: CrossAxisAlignment.stretch, children: [
            Center(child: Container(width: 36, height: 4,
              decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2)))),
            const SizedBox(height: 20),
            Container(width: 48, height: 48,
              decoration: BoxDecoration(gradient: T.accentGrad, borderRadius: BorderRadius.circular(12)),
              child: const Center(child: Text('TX',
                style: TextStyle(fontSize: 18, fontWeight: FontWeight.w800,
                  color: T.headerDark, letterSpacing: 1)))),
            const SizedBox(height: 14),
            Text('Complete Your Profile', style: T.displaySm),
            const SizedBox(height: 4),
            Text('Just a few details to set up your boutique account.',
              style: T.bodySm.copyWith(fontSize: 13)),
            const SizedBox(height: 20),
            TxField(
              label: 'Boutique Name',
              hint: 'e.g. Elegance Boutique',
              controller: nameCtrl,
              validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null,
            ),
            const SizedBox(height: 12),
            TxField(
              label: 'Phone Number',
              hint: 'e.g. 9876543210',
              controller: phoneCtrl,
              keyboardType: TextInputType.phone,
              validator: (v) => (v == null || v.trim().length < 7) ? 'Enter a valid phone' : null,
            ),
            const SizedBox(height: 12),
            TxField(
              label: 'City',
              hint: 'e.g. Surat',
              controller: cityCtrl,
              validator: (v) => (v == null || v.trim().isEmpty) ? 'Required' : null,
            ),
            const SizedBox(height: 24),
            Container(
              height: 52,
              decoration: BoxDecoration(
                gradient: T.headerGrad,
                borderRadius: BorderRadius.circular(T.rMd)),
              child: Material(color: Colors.transparent,
                child: InkWell(
                  borderRadius: BorderRadius.circular(T.rMd),
                  onTap: saving ? null : () async {
                    if (!fk.currentState!.validate()) return;
                    setSt(() => saving = true);
                    await _api.updateBoutiqueProfile(
                      name:  nameCtrl.text.trim(),
                      phone: phoneCtrl.text.trim(),
                      city:  cityCtrl.text.trim(),
                    );
                    if (ctx.mounted) Navigator.pop(ctx);
                    if (mounted) Navigator.of(context).pushReplacement(
                        MaterialPageRoute(builder: (_) => const HomeScreen()));
                  },
                  child: Center(child: saving
                    ? const SizedBox(width: 20, height: 20,
                        child: CircularProgressIndicator(strokeWidth: 2, color: T.accent))
                    : Text('GET STARTED', style: T.btn.copyWith(color: T.accent, letterSpacing: 2))),
                ),
              ),
            ),
            const SizedBox(height: 4),
          ])),
        ),
      ),
    );
  }

  // ─── Step 1 → Step 2 ───────────────────────────────────────────
  void _nextStep() {
    if (!_fk1.currentState!.validate()) return;
    setState(() => _step = 2);
  }

  // ─── Final submit ───────────────────────────────────────────────
  Future<void> _submit() async {
    if (_login) {
      if (!_fk1.currentState!.validate()) return;
    } else {
      if (!_fk2.currentState!.validate()) return;
    }

    setState(() => _loading = true);

    // Warn if server is slow to wake
    Future.delayed(const Duration(seconds: 4), () {
      if (_loading && mounted) {
        ScaffoldMessenger.of(context).showSnackBar(
          const SnackBar(
            content: Text('Server is waking up… please wait a few seconds.'),
            duration: Duration(seconds: 5),
          ),
        );
      }
    });

    try {
      if (_login) {
        // ── Login flow (unchanged) ──
        final r = await _api.login(_email.text.trim(), _pass.text);
        if (!mounted) return;
        if (r['success'] == true) {
          Navigator.of(context).pushReplacement(
              MaterialPageRoute(builder: (_) => const HomeScreen()));
        } else {
          String msg = r['message'] ?? 'Authentication failed';
          if (msg.contains('Invalid login credentials')) msg = 'Invalid email or password.';
          if (msg.contains('Password should be')) msg = 'Password is too short (min 6 chars).';
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(msg), backgroundColor: T.danger,
                duration: const Duration(seconds: 4)));
        }
      } else {
        // ── Register flow — send OTP first ──
        final r = await _api.sendOtp(
          _name.text.trim(), _email.text.trim(), _pass.text,
          ownerName: _ownerName.text.trim(),
          phone:     _phone.text.trim(),
          city:      _city.text.trim(),
          address:   _address.text.trim(),
        );
        if (!mounted) return;
        if (r['success'] == true) {
          // Show OTP verification screen
          _showOtpScreen(_email.text.trim());
        } else {
          String msg = r['message'] ?? 'Registration failed';
          if (msg.contains('already registered')) msg = 'This email is already registered. Please login instead.';
          ScaffoldMessenger.of(context).showSnackBar(
            SnackBar(content: Text(msg), backgroundColor: T.danger,
                duration: const Duration(seconds: 4)));
        }
      }
    } catch (e) {
      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Error: $e'), backgroundColor: T.danger));
    } finally {
      if (mounted) setState(() => _loading = false);
    }
  }

  // ─── OTP Verification Screen ────────────────────────────────────
  void _showOtpScreen(String email) {
    final List<TextEditingController> controllers =
        List.generate(6, (_) => TextEditingController());
    final List<FocusNode> focusNodes =
        List.generate(6, (_) => FocusNode());
    bool verifying = false;
    int resendTimer = 60;

    showModalBottomSheet(
      context: context,
      isDismissible: false,
      enableDrag: false,
      isScrollControlled: true,
      backgroundColor: Colors.transparent,
      builder: (ctx) => StatefulBuilder(
        builder: (ctx, setSt) {
          // Start countdown timer
          Future.doWhile(() async {
            await Future.delayed(const Duration(seconds: 1));
            if (!ctx.mounted) return false;
            if (resendTimer > 0) { setSt(() => resendTimer--); return true; }
            return false;
          });

          String getOtp() => controllers.map((c) => c.text).join();

          Future<void> verify() async {
            final otp = getOtp();
            if (otp.length < 6) return;
            setSt(() => verifying = true);
            final r = await _api.verifyOtp(email, otp);
            if (!ctx.mounted) return;
            setSt(() => verifying = false);
            if (r['success'] == true) {
              Navigator.pop(ctx);
              if (mounted) Navigator.of(context).pushReplacement(
                  MaterialPageRoute(builder: (_) => const HomeScreen()));
            } else {
              ScaffoldMessenger.of(ctx).showSnackBar(SnackBar(
                content: Text(r['message'] ?? 'Invalid OTP'),
                backgroundColor: T.danger));
              // Clear all fields
              for (var c in controllers) c.clear();
              focusNodes[0].requestFocus();
            }
          }

          return Container(
            padding: EdgeInsets.only(
              bottom: MediaQuery.of(ctx).viewInsets.bottom + 24,
              left: 24, right: 24, top: 24),
            decoration: BoxDecoration(
              color: T.bg,
              borderRadius: const BorderRadius.vertical(top: Radius.circular(T.rXl))),
            child: Column(mainAxisSize: MainAxisSize.min,
              crossAxisAlignment: CrossAxisAlignment.stretch, children: [
              Center(child: Container(width: 36, height: 4,
                decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2)))),
              const SizedBox(height: 20),

              // Icon
              Center(child: Container(width: 56, height: 56,
                decoration: BoxDecoration(
                  color: T.info.withOpacity(0.1),
                  borderRadius: BorderRadius.circular(16)),
                child: const Icon(Icons.mark_email_read_rounded, size: 28, color: T.info))),
              const SizedBox(height: 14),

              Center(child: Text('Verify Your Email', style: T.displaySm)),
              const SizedBox(height: 6),
              Center(child: Text('Enter the 6-digit code sent to',
                style: T.bodySm.copyWith(fontSize: 13))),
              Center(child: Text(email,
                style: T.body.copyWith(fontWeight: FontWeight.w700, fontSize: 14, color: T.accentDark))),
              const SizedBox(height: 24),

              // OTP boxes
              Row(mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: List.generate(6, (i) => SizedBox(
                  width: 44, height: 52,
                  child: TextField(
                    controller: controllers[i],
                    focusNode: focusNodes[i],
                    textAlign: TextAlign.center,
                    keyboardType: TextInputType.number,
                    maxLength: 1,
                    style: T.heading.copyWith(fontSize: 22),
                    decoration: InputDecoration(
                      counterText: '',
                      contentPadding: EdgeInsets.zero,
                      border: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10),
                        borderSide: BorderSide(color: T.border)),
                      focusedBorder: OutlineInputBorder(
                        borderRadius: BorderRadius.circular(10),
                        borderSide: const BorderSide(color: T.accentDark, width: 2)),
                    ),
                    onChanged: (v) {
                      if (v.isNotEmpty && i < 5) {
                        focusNodes[i + 1].requestFocus();
                      } else if (v.isEmpty && i > 0) {
                        focusNodes[i - 1].requestFocus();
                      }
                      if (getOtp().length == 6) verify();
                    },
                  ),
                ))),
              const SizedBox(height: 24),

              // Verify button
              Container(
                height: 52,
                decoration: BoxDecoration(
                  gradient: T.headerGrad,
                  borderRadius: BorderRadius.circular(T.rMd)),
                child: Material(color: Colors.transparent,
                  child: InkWell(
                    borderRadius: BorderRadius.circular(T.rMd),
                    onTap: verifying ? null : verify,
                    child: Center(child: verifying
                      ? const SizedBox(width: 20, height: 20,
                          child: CircularProgressIndicator(strokeWidth: 2, color: T.accent))
                      : Text('VERIFY & CREATE ACCOUNT',
                          style: T.btn.copyWith(color: T.accent, letterSpacing: 1.5))),
                  )),
              ),
              const SizedBox(height: 16),

              // Resend timer
              Center(child: resendTimer > 0
                ? Text('Resend OTP in ${resendTimer}s',
                    style: T.bodySm.copyWith(fontSize: 13, color: T.text3))
                : GestureDetector(
                    onTap: () async {
                      setSt(() => resendTimer = 60);
                      await _api.sendOtp(
                        _name.text.trim(), email, _pass.text,
                        ownerName: _ownerName.text.trim(),
                        phone: _phone.text.trim(),
                        city: _city.text.trim(),
                      );
                      if (ctx.mounted) ScaffoldMessenger.of(ctx).showSnackBar(
                        const SnackBar(content: Text('New OTP sent!')));
                    },
                    child: Text('Resend OTP',
                      style: T.body.copyWith(
                        color: T.accentDark, fontWeight: FontWeight.w700, fontSize: 14)),
                  )),
              const SizedBox(height: 4),
            ]),
          );
        },
      ),
    );
  }

  // ─── BUILD ──────────────────────────────────────────────────────
  @override
  Widget build(BuildContext context) {
    final h = MediaQuery.of(context).size.height;
    return Scaffold(
      body: SingleChildScrollView(
        child: Column(children: [
          // ── Dark header ──────────────────────────────────────
          Container(
            width: double.infinity,
            height: h * 0.36,
            decoration: const BoxDecoration(
              gradient: T.headerGrad,
              borderRadius: BorderRadius.vertical(bottom: Radius.circular(32)),
            ),
            child: SafeArea(
              child: AnimatedBuilder(
                animation: _anim,
                builder: (_, __) => Opacity(
                  opacity: _fade.value,
                  child: Transform.translate(
                    offset: Offset(0, _slide.value),
                    child: Column(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: [
                        Container(
                          width: 64, height: 64,
                          decoration: BoxDecoration(
                            borderRadius: BorderRadius.circular(18),
                            gradient: T.accentGrad,
                            boxShadow: [BoxShadow(
                              color: T.accent.withOpacity(0.3),
                              blurRadius: 20, offset: const Offset(0, 8))],
                          ),
                          child: const Center(child: Text('TX',
                            style: TextStyle(fontSize: 22,
                              fontWeight: FontWeight.w800,
                              color: T.headerDark, letterSpacing: 2)))),
                        const SizedBox(height: 16),
                        Text('TAILORX', style: GoogleFonts.playfairDisplay(
                          fontSize: 24, fontWeight: FontWeight.w700,
                          color: T.accent, letterSpacing: 3)),
                        const SizedBox(height: 4),
                        Text('BOUTIQUE MANAGEMENT', style: TextStyle(
                          fontSize: 9, letterSpacing: 3,
                          color: Colors.white.withOpacity(0.35))),
                      ],
                    ),
                  ),
                ),
              ),
            ),
          ),

          // ── Form area ────────────────────────────────────────
          Padding(
            padding: const EdgeInsets.fromLTRB(28, 32, 28, 40),
            child: AnimatedBuilder(
              animation: _anim,
              builder: (_, __) => Opacity(
                opacity: _fade.value,
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.stretch,
                  children: [
                    // Title + subtitle
                    Text(
                      _login
                          ? _lang.t('welcome_back')
                          : (_step == 1
                              ? _lang.t('create_account')
                              : _lang.t('shop_details')),
                      style: T.displayMd,
                    ),
                    const SizedBox(height: 4),
                    Text(
                      _login
                          ? _lang.t('sign_in_subtitle')
                          : (_step == 1
                              ? _lang.t('register_subtitle')
                              : _lang.t('register_step2_subtitle')),
                      style: T.bodySm,
                    ),

                    // Step indicator (register only)
                    if (!_login) ...[
                      const SizedBox(height: 20),
                      _StepIndicator(step: _step),
                    ],

                    const SizedBox(height: 24),

                    // ── LOGIN FORM ──────────────────────────
                    if (_login)
                      Form(
                        key: _fk1,
                        child: Column(children: [
                          TxField(
                            label: _lang.t('email'),
                            hint: 'you@example.com',
                            controller: _email,
                            keyboardType: TextInputType.emailAddress,
                            validator: (v) {
                              if (v == null || v.trim().isEmpty) return _lang.t('required');
                              if (!v.contains('@')) return _lang.t('invalid_email');
                              return null;
                            },
                          ),
                          const SizedBox(height: 14),
                          TxField(
                            label: _lang.t('password'),
                            controller: _pass,
                            obscureText: _obscure,
                            suffix: IconButton(
                              icon: Icon(
                                _obscure ? Icons.visibility_off_rounded : Icons.visibility_rounded,
                                size: 18, color: T.text3),
                              onPressed: () => setState(() => _obscure = !_obscure)),
                            validator: (v) {
                              if (v == null || v.isEmpty) return _lang.t('required');
                              if (v.length < 6) return _lang.t('min_chars');
                              return null;
                            },
                          ),
                          Align(
                            alignment: Alignment.centerRight,
                            child: TextButton(
                              onPressed: _forgotPassword,
                              child: Text('Forgot Password?',
                                style: T.bodySm.copyWith(
                                  color: T.accentDark, fontWeight: FontWeight.w600)),
                            ),
                          ),
                        ]),
                      ),

                    // ── REGISTER STEP 1 ─────────────────────
                    if (!_login && _step == 1)
                      Form(
                        key: _fk1,
                        child: Column(children: [
                          TxField(
                            label: _lang.t('boutique_name'),
                            hint: 'e.g. Elegance Boutique',
                            controller: _name,
                            validator: (v) => (v == null || v.trim().isEmpty)
                                ? _lang.t('required') : null,
                          ),
                          const SizedBox(height: 14),
                          TxField(
                            label: _lang.t('owner_name'),
                            hint: 'e.g. Priya Shah',
                            controller: _ownerName,
                            validator: (v) => (v == null || v.trim().isEmpty)
                                ? _lang.t('required') : null,
                          ),
                          const SizedBox(height: 14),
                          TxField(
                            label: _lang.t('email'),
                            hint: 'you@example.com',
                            controller: _email,
                            keyboardType: TextInputType.emailAddress,
                            validator: (v) {
                              if (v == null || v.trim().isEmpty) return _lang.t('required');
                              if (!v.contains('@')) return _lang.t('invalid_email');
                              return null;
                            },
                          ),
                          const SizedBox(height: 14),
                          TxField(
                            label: _lang.t('password'),
                            controller: _pass,
                            obscureText: _obscure,
                            suffix: IconButton(
                              icon: Icon(
                                _obscure ? Icons.visibility_off_rounded : Icons.visibility_rounded,
                                size: 18, color: T.text3),
                              onPressed: () => setState(() => _obscure = !_obscure)),
                            validator: (v) {
                              if (v == null || v.isEmpty) return _lang.t('required');
                              if (v.length < 6) return _lang.t('min_chars');
                              return null;
                            },
                          ),
                        ]),
                      ),

                    // ── REGISTER STEP 2 ─────────────────────
                    if (!_login && _step == 2)
                      Form(
                        key: _fk2,
                        child: Column(children: [
                          TxField(
                            label: _lang.t('phone'),
                            hint: 'e.g. 9876543210',
                            controller: _phone,
                            keyboardType: TextInputType.phone,
                            validator: (v) {
                              if (v == null || v.trim().isEmpty) return _lang.t('required');
                              if (v.trim().length < 7) return _lang.t('invalid_phone');
                              return null;
                            },
                          ),
                          const SizedBox(height: 14),
                          TxField(
                            label: _lang.t('city'),
                            hint: 'e.g. Surat',
                            controller: _city,
                            validator: (v) => (v == null || v.trim().isEmpty)
                                ? _lang.t('required') : null,
                          ),
                          const SizedBox(height: 14),
                          TxField(
                            label: '${_lang.t('shop_address')} (${_lang.t('optional')})',
                            hint: 'e.g. Shop 12, Ring Road, Surat',
                            controller: _address,
                            maxLines: 2,
                          ),
                        ]),
                      ),

                    const SizedBox(height: 24),

                    // ── ACTION BUTTONS ───────────────────────
                    if (!_login && _step == 2) ...[
                      // BACK button
                      OutlinedButton(
                        onPressed: _loading ? null : () => setState(() => _step = 1),
                        style: OutlinedButton.styleFrom(
                          side: const BorderSide(color: T.accentDark),
                          shape: RoundedRectangleBorder(
                              borderRadius: BorderRadius.circular(T.rMd)),
                          minimumSize: const Size.fromHeight(52),
                        ),
                        child: Text(_lang.t('back').toUpperCase(),
                          style: T.btn.copyWith(color: T.accentDark, letterSpacing: 2)),
                      ),
                      const SizedBox(height: 12),
                    ],

                    // PRIMARY button: Next (step 1 register) or Sign In / Register
                    AnimatedContainer(
                      duration: const Duration(milliseconds: 300),
                      height: 54,
                      decoration: BoxDecoration(
                        gradient: T.headerGrad,
                        borderRadius: BorderRadius.circular(T.rMd),
                        boxShadow: _loading ? [] : [BoxShadow(
                          color: T.headerDark.withOpacity(0.3),
                          blurRadius: 16, offset: const Offset(0, 6))],
                      ),
                      child: Material(
                        color: Colors.transparent,
                        child: InkWell(
                          onTap: _loading
                              ? null
                              : (!_login && _step == 1 ? _nextStep : _submit),
                          borderRadius: BorderRadius.circular(T.rMd),
                          child: Center(
                            child: _loading
                                ? SizedBox(width: 20, height: 20,
                                    child: CircularProgressIndicator(
                                        strokeWidth: 2, color: T.accent))
                                : Text(
                                    _login
                                        ? _lang.t('sign_in').toUpperCase()
                                        : (_step == 1
                                            ? _lang.t('next').toUpperCase()
                                            : _lang.t('register').toUpperCase()),
                                    style: T.btn.copyWith(
                                        color: T.accent, letterSpacing: 2)),
                          ),
                        ),
                      ),
                    ),

                    // ── OR CONTINUE WITH ────────────────────
                    if (_login) ...[
                      const SizedBox(height: 20),
                      Row(children: [
                        Expanded(child: Container(height: 1, color: T.border)),
                        Padding(
                          padding: const EdgeInsets.symmetric(horizontal: 12),
                          child: Text('OR CONTINUE WITH',
                            style: T.label.copyWith(fontSize: 10, color: T.text3)),
                        ),
                        Expanded(child: Container(height: 1, color: T.border)),
                      ]),
                      const SizedBox(height: 16),
                      // Google button
                      _SocialButton(
                        label: 'Continue with Google',
                        isGoogle: true,
                        onTap: _loading ? null : _signInWithGoogle,
                      ),
                      const SizedBox(height: 10),
                      // Facebook button
                      _SocialButton(
                        label: 'Continue with Facebook',
                        isGoogle: false,
                        onTap: _loading ? null : _signInWithFacebook,
                      ),
                    ],

                    const SizedBox(height: 20),

                    // Toggle login / register
                    Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                      Text(_login ? _lang.t('no_account') : _lang.t('have_account'),
                          style: T.bodySm),
                      TextButton(
                        onPressed: _loading ? null : _switchMode,
                        child: Text(
                          _login ? _lang.t('register') : _lang.t('sign_in'),
                          style: T.body.copyWith(
                              fontWeight: FontWeight.w700, color: T.accent)),
                      ),
                    ]),

                    const SizedBox(height: 8),

                    // Contact Us — visible for account-on-hold users
                    GestureDetector(
                      onTap: () => _showContactSheet(context),
                      child: Container(
                        padding: const EdgeInsets.symmetric(vertical: 12, horizontal: 16),
                        decoration: BoxDecoration(
                          color: T.surface,
                          borderRadius: BorderRadius.circular(T.rMd),
                          border: Border.all(color: T.border),
                        ),
                        child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                          Icon(Icons.headset_mic_rounded, size: 16, color: T.text3),
                          const SizedBox(width: 8),
                          Text(
                            'Need help? ',
                            style: T.bodySm.copyWith(fontSize: 13),
                          ),
                          Text(
                            'Contact Us',
                            style: T.bodySm.copyWith(
                              fontSize: 13,
                              color: T.accentDark,
                              fontWeight: FontWeight.w700,
                            ),
                          ),
                        ]),
                      ),
                    ),
                  ],
                ),
              ),
            ),
          ),
        ]),
      ),
    );
  }
}

// ─── Social sign-in button ──────────────────────────────────────────
class _SocialButton extends StatelessWidget {
  final String label;
  final bool isGoogle; // true = Google, false = Facebook
  final VoidCallback? onTap;

  const _SocialButton({
    required this.label,
    required this.isGoogle,
    this.onTap,
  });

  @override
  Widget build(BuildContext context) {
    return GestureDetector(
      onTap: onTap,
      child: Container(
        height: 52,
        decoration: BoxDecoration(
          color: isGoogle ? Colors.white : const Color(0xFF1877F2),
          borderRadius: BorderRadius.circular(T.rMd),
          border: Border.all(
            color: isGoogle ? const Color(0xFFDDDDDD) : const Color(0xFF1877F2)),
          boxShadow: [BoxShadow(
            color: Colors.black.withOpacity(0.08),
            blurRadius: 8, offset: const Offset(0, 2))],
        ),
        child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
          // Logo
          if (isGoogle)
            const _GoogleGIcon()
          else
            // Facebook white f logo
            Container(
              width: 24, height: 24,
              decoration: BoxDecoration(
                color: Colors.white,
                borderRadius: BorderRadius.circular(4)),
              child: const Center(
                child: Text('f', style: TextStyle(
                  fontSize: 16, fontWeight: FontWeight.w900,
                  color: Color(0xFF1877F2), height: 1.2)))),
          const SizedBox(width: 12),
          Text(label, style: TextStyle(
            fontSize: 15, fontWeight: FontWeight.w600,
            color: isGoogle ? const Color(0xFF3C4043) : Colors.white,
            letterSpacing: 0.2)),
        ]),
      ),
    );
  }
}

// ─── Google G icon — coloured segments ──────────────────────────────
class _GoogleGIcon extends StatelessWidget {
  const _GoogleGIcon();

  @override
  Widget build(BuildContext context) {
    return SizedBox(width: 22, height: 22,
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Text('G', style: TextStyle(
          fontSize: 20,
          fontWeight: FontWeight.w700,
          height: 1,
          foreground: Paint()..shader = const LinearGradient(
            colors: [Color(0xFF4285F4), Color(0xFFEA4335)],
            begin: Alignment.topLeft,
            end: Alignment.bottomRight,
          ).createShader(const Rect.fromLTWH(0, 0, 22, 22)),
        )),
      ]),
    );
  }
}

// ─── Google G logo using RichText ───────────────────────────────────
class _GoogleLogo extends StatelessWidget {
  const _GoogleLogo();

  @override
  Widget build(BuildContext context) {
    return SizedBox(
      width: 24, height: 24,
      child: Stack(alignment: Alignment.center, children: [
        // Outer circle segments using custom painter
        CustomPaint(size: const Size(24, 24), painter: _GoogleArcPainter()),
      ]),
    );
  }
}

class _GoogleArcPainter extends CustomPainter {
  @override
  void paint(Canvas canvas, Size size) {
    const double strokeW = 5.0;
    final double radius = (size.width - strokeW) / 2;
    final Offset center = Offset(size.width / 2, size.height / 2);
    final rect = Rect.fromCircle(center: center, radius: radius);

    // Red — top left arc
    canvas.drawArc(rect, 3.5, 1.3, false,
      Paint()..color = const Color(0xFFEA4335)..style = PaintingStyle.stroke..strokeWidth = strokeW..strokeCap = StrokeCap.butt);
    // Yellow — bottom left arc
    canvas.drawArc(rect, 2.3, 1.2, false,
      Paint()..color = const Color(0xFFFBBC05)..style = PaintingStyle.stroke..strokeWidth = strokeW..strokeCap = StrokeCap.butt);
    // Green — bottom right arc
    canvas.drawArc(rect, 1.1, 1.2, false,
      Paint()..color = const Color(0xFF34A853)..style = PaintingStyle.stroke..strokeWidth = strokeW..strokeCap = StrokeCap.butt);
    // Blue — right + top arc
    canvas.drawArc(rect, -0.5, 1.6, false,
      Paint()..color = const Color(0xFF4285F4)..style = PaintingStyle.stroke..strokeWidth = strokeW..strokeCap = StrokeCap.butt);

    // Blue horizontal crossbar (the middle bar of G)
    final barPaint = Paint()
      ..color = const Color(0xFF4285F4)
      ..strokeWidth = strokeW
      ..strokeCap = StrokeCap.square;
    canvas.drawLine(
      Offset(center.dx, center.dy),
      Offset(center.dx + radius, center.dy),
      barPaint,
    );

    // White cover to make inner circle white (hollow look)
    canvas.drawCircle(center, radius - strokeW / 2,
      Paint()..color = Colors.white..style = PaintingStyle.fill);

    // Redraw crossbar on top of white fill
    canvas.drawLine(
      Offset(center.dx - 0.5, center.dy),
      Offset(center.dx + radius + 0.5, center.dy),
      barPaint,
    );
  }

  @override
  bool shouldRepaint(covariant CustomPainter oldDelegate) => false;
}

// ─── Contact option tile ────────────────────────────────────────────
class _ContactOption extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String label, sub;
  final VoidCallback onTap;
  const _ContactOption({required this.icon, required this.color,
    required this.label, required this.sub, required this.onTap});

  @override
  Widget build(BuildContext context) {
    return InkWell(
      onTap: onTap,
      borderRadius: BorderRadius.circular(T.rMd),
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
        decoration: BoxDecoration(
          color: T.card,
          borderRadius: BorderRadius.circular(T.rMd),
          boxShadow: T.shadowCard,
        ),
        child: Row(children: [
          Container(width: 44, height: 44,
            decoration: BoxDecoration(
              color: color.withOpacity(0.1),
              borderRadius: BorderRadius.circular(10)),
            child: Icon(icon, size: 22, color: color)),
          const SizedBox(width: 14),
          Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(label, style: T.body.copyWith(fontWeight: FontWeight.w600, fontSize: 15)),
            Text(sub, style: T.bodySm.copyWith(fontSize: 12)),
          ])),
          Icon(Icons.arrow_forward_ios_rounded, size: 14, color: T.text3),
        ]),
      ),
    );
  }
}

// ─── Step indicator widget ──────────────────────────────────────────
class _StepIndicator extends StatelessWidget {
  final int step;
  const _StepIndicator({required this.step});

  @override
  Widget build(BuildContext context) {
    return Row(
      children: [
        _dot(1, step >= 1),
        Expanded(
          child: Container(
            height: 2,
            color: step >= 2 ? T.accentDark : T.border,
          ),
        ),
        _dot(2, step >= 2),
        const Spacer(),
        Text(
          'Step $step of 2',
          style: TextStyle(
            fontSize: 12,
            color: T.text3,
            fontWeight: FontWeight.w500,
          ),
        ),
      ],
    );
  }

  Widget _dot(int n, bool active) {
    return Container(
      width: 28, height: 28,
      decoration: BoxDecoration(
        shape: BoxShape.circle,
        color: active ? T.accentDark : T.border,
      ),
      child: Center(
        child: Text(
          '$n',
          style: TextStyle(
            fontSize: 13,
            fontWeight: FontWeight.w700,
            color: active ? Colors.white : T.text3,
          ),
        ),
      ),
    );
  }
}
