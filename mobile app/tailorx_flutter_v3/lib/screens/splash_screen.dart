import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import '../services/api_service.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import 'auth_screen.dart';
import 'home_screen.dart';

class SplashScreen extends StatefulWidget {
  const SplashScreen({super.key});
  @override
  State<SplashScreen> createState() => _SplashState();
}

class _SplashState extends State<SplashScreen> with TickerProviderStateMixin {
  late AnimationController _lc, _tc, _pc;
  late Animation<double> _ls, _lf, _tf, _ts;
  String _status = '';

  @override
  void initState() {
    super.initState();
    _lc = AnimationController(vsync: this, duration: const Duration(milliseconds: 800));
    _tc = AnimationController(vsync: this, duration: const Duration(milliseconds: 600));
    _pc = AnimationController(vsync: this, duration: const Duration(milliseconds: 400));
    _ls = Tween(begin: 0.5, end: 1.0).animate(CurvedAnimation(parent: _lc, curve: Curves.elasticOut));
    _lf = CurvedAnimation(parent: _lc, curve: Curves.easeOut);
    _tf = CurvedAnimation(parent: _tc, curve: Curves.easeOut);
    _ts = Tween(begin: 20.0, end: 0.0).animate(CurvedAnimation(parent: _tc, curve: Curves.easeOut));
    _start();
  }

  void _start() async {
    await Future.delayed(const Duration(milliseconds: 200));
    _lc.forward();
    await Future.delayed(const Duration(milliseconds: 500));
    _tc.forward();
    await Future.delayed(const Duration(milliseconds: 300));
    _pc.forward();
    await Future.delayed(const Duration(milliseconds: 800));
    await AppLang().init();
    final ok = await Api().init();
    if (ok) {
      // Wake up Render (free tier sleeps after inactivity)
      if (mounted) setState(() => _status = 'Connecting to server...');
      await Api().warmUp();
      if (mounted) setState(() => _status = '');
    }
    if (!mounted) return;
    Navigator.of(context).pushReplacement(PageRouteBuilder(
      pageBuilder: (_, __, ___) => ok ? const HomeScreen() : const AuthScreen(),
      transitionsBuilder: (_, a, __, c) => FadeTransition(opacity: a, child: c),
      transitionDuration: const Duration(milliseconds: 600)));
  }

  @override
  void dispose() { _lc.dispose(); _tc.dispose(); _pc.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    return Scaffold(body: Container(
      decoration: const BoxDecoration(gradient: T.headerGrad),
      child: Center(child: Column(mainAxisSize: MainAxisSize.min, children: [
        AnimatedBuilder(animation: _lc, builder: (_, __) => Opacity(opacity: _lf.value,
          child: Transform.scale(scale: _ls.value, child: Container(
            width: 80, height: 80,
            decoration: BoxDecoration(borderRadius: BorderRadius.circular(T.rLg), gradient: T.accentGrad,
              boxShadow: [BoxShadow(color: T.accent.withOpacity(0.4), blurRadius: 30, offset: const Offset(0, 10))]),
            child: Center(child: Text('TX', style: TextStyle(
              fontSize: 34, fontWeight: FontWeight.w800, color: T.headerDark, letterSpacing: 3))))))),
        const SizedBox(height: 28),
        AnimatedBuilder(animation: _tc, builder: (_, __) => Opacity(opacity: _tf.value,
          child: Transform.translate(offset: Offset(0, _ts.value), child: Column(children: [
            Text('TAILORX', style: GoogleFonts.prata(
              fontSize: 40, fontWeight: FontWeight.w400, color: T.accent, letterSpacing: 3)),
            const SizedBox(height: 6),
            Text('BOUTIQUE MANAGEMENT', style: TextStyle(
              fontSize: 12, letterSpacing: 4, fontWeight: FontWeight.w400, color: Colors.white.withOpacity(0.4))),
          ])))),
        const SizedBox(height: 48),
        FadeTransition(opacity: CurvedAnimation(parent: _pc, curve: Curves.easeOut),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            SizedBox(width: 20, height: 20,
              child: CircularProgressIndicator(strokeWidth: 1.5, color: T.accent.withOpacity(0.6))),
            if (_status.isNotEmpty) ...[
              const SizedBox(height: 16),
              Text(_status, style: TextStyle(
                fontSize: 12, letterSpacing: 1.5,
                color: Colors.white.withOpacity(0.5),
                fontWeight: FontWeight.w400)),
            ],
          ])),
      ]))));
  }
}
