import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../utils/theme.dart';
import 'home_screen.dart';

class OnboardingScreen extends StatefulWidget {
  const OnboardingScreen({super.key});
  @override
  State<OnboardingScreen> createState() => _OnboardingScreenState();
}

class _OnboardingScreenState extends State<OnboardingScreen> {
  final PageController _ctrl = PageController();
  int _page = 0;

  static const _slides = [
    _Slide(
      icon: Icons.storefront_rounded,
      iconColor: Color(0xFFD4A574),
      bg: Color(0xFF1A1A2E),
      title: 'Welcome to TailorX',
      subtitle: 'Your complete boutique management solution',
      body: 'Manage your entire tailoring business from one place — customers, orders, measurements, and invoices.',
    ),
    _Slide(
      icon: Icons.people_rounded,
      iconColor: Color(0xFF4A7FC1),
      bg: Color(0xFF1A2744),
      title: 'Manage Customers',
      subtitle: 'Every client, perfectly organised',
      body: 'Add customers with their contact details, city, and gender. Search instantly and view their full order history.',
    ),
    _Slide(
      icon: Icons.straighten_rounded,
      iconColor: Color(0xFF2BA5A5),
      bg: Color(0xFF0F2E2E),
      title: 'Save Measurements',
      subtitle: 'Never lose a size again',
      body: 'Store detailed top and bottom measurements for each customer. Access them instantly when creating a new order.',
    ),
    _Slide(
      icon: Icons.receipt_long_rounded,
      iconColor: Color(0xFF7C5CBF),
      bg: Color(0xFF1E1440),
      title: 'Track Orders',
      subtitle: 'From fabric to delivery',
      body: 'Create orders and track every stage — Received → Cutting → Stitching → Trial → Ready → Delivered.',
    ),
    _Slide(
      icon: Icons.payments_rounded,
      iconColor: Color(0xFF2D8F6F),
      bg: Color(0xFF0D2820),
      title: 'Invoices & Payments',
      subtitle: 'Professional billing in seconds',
      body: 'Generate itemised invoices, apply discounts, track advance payments and balances — all in one tap.',
    ),
    _Slide(
      icon: Icons.notifications_active_rounded,
      iconColor: Color(0xFFE09F3E),
      bg: Color(0xFF2A1E00),
      title: 'WhatsApp Alerts',
      subtitle: 'Keep customers informed',
      body: 'Send automatic order-ready notifications to customers via WhatsApp. Set your boutique name and branding in Settings.',
    ),
  ];

  void _next() {
    if (_page < _slides.length - 1) {
      _ctrl.nextPage(duration: const Duration(milliseconds: 400), curve: Curves.easeInOut);
    } else {
      _finish();
    }
  }

  void _finish() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setBool('onboarding_done', true);
    if (!mounted) return;
    Navigator.of(context).pushReplacement(PageRouteBuilder(
      pageBuilder: (_, __, ___) => const HomeScreen(),
      transitionsBuilder: (_, a, __, c) => FadeTransition(opacity: a, child: c),
      transitionDuration: const Duration(milliseconds: 500),
    ));
  }

  @override
  void dispose() { _ctrl.dispose(); super.dispose(); }

  @override
  Widget build(BuildContext context) {
    final slide = _slides[_page];
    final isLast = _page == _slides.length - 1;

    return Scaffold(
      backgroundColor: slide.bg,
      body: AnimatedContainer(
        duration: const Duration(milliseconds: 400),
        color: slide.bg,
        child: SafeArea(
          child: Column(
            children: [
              // Top bar — Skip
              Padding(
                padding: const EdgeInsets.symmetric(horizontal: 20, vertical: 12),
                child: Row(
                  mainAxisAlignment: MainAxisAlignment.spaceBetween,
                  children: [
                    // Page counter
                    Text(
                      '${_page + 1} / ${_slides.length}',
                      style: GoogleFonts.montserrat(
                        fontSize: 13, fontWeight: FontWeight.w600,
                        color: Colors.white.withOpacity(0.4), letterSpacing: 1),
                    ),
                    // Skip button
                    if (!isLast)
                      GestureDetector(
                        onTap: _finish,
                        child: Container(
                          padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
                          decoration: BoxDecoration(
                            color: Colors.white.withOpacity(0.08),
                            borderRadius: BorderRadius.circular(20),
                          ),
                          child: Text('Skip', style: GoogleFonts.montserrat(
                            fontSize: 13, fontWeight: FontWeight.w600,
                            color: Colors.white.withOpacity(0.6))),
                        ),
                      ),
                  ],
                ),
              ),

              // Page view — slides
              Expanded(
                child: PageView.builder(
                  controller: _ctrl,
                  onPageChanged: (i) => setState(() => _page = i),
                  itemCount: _slides.length,
                  itemBuilder: (_, i) => _SlideView(slide: _slides[i]),
                ),
              ),

              // Bottom — dots + button
              Padding(
                padding: const EdgeInsets.fromLTRB(24, 8, 24, 32),
                child: Column(
                  children: [
                    // Dot indicators
                    Row(
                      mainAxisAlignment: MainAxisAlignment.center,
                      children: List.generate(_slides.length, (i) {
                        final active = i == _page;
                        return AnimatedContainer(
                          duration: const Duration(milliseconds: 300),
                          margin: const EdgeInsets.symmetric(horizontal: 3),
                          width: active ? 24 : 7,
                          height: 7,
                          decoration: BoxDecoration(
                            color: active
                                ? T.accent
                                : Colors.white.withOpacity(0.25),
                            borderRadius: BorderRadius.circular(4),
                          ),
                        );
                      }),
                    ),
                    const SizedBox(height: 28),
                    // Next / Get Started button
                    SizedBox(
                      width: double.infinity,
                      height: 56,
                      child: ElevatedButton(
                        onPressed: _next,
                        style: ElevatedButton.styleFrom(
                          backgroundColor: T.accent,
                          foregroundColor: T.headerDark,
                          elevation: 0,
                          shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(T.rMd)),
                        ),
                        child: Row(
                          mainAxisAlignment: MainAxisAlignment.center,
                          children: [
                            Text(
                              isLast ? 'Get Started' : 'Next',
                              style: GoogleFonts.montserrat(
                                fontSize: 16, fontWeight: FontWeight.w700,
                                letterSpacing: 0.5, color: T.headerDark),
                            ),
                            const SizedBox(width: 8),
                            Icon(
                              isLast ? Icons.check_rounded : Icons.arrow_forward_rounded,
                              size: 20, color: T.headerDark),
                          ],
                        ),
                      ),
                    ),
                  ],
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

// ─── Slide data model ─────────────────────────────────────────────────────────
class _Slide {
  final IconData icon;
  final Color iconColor;
  final Color bg;
  final String title;
  final String subtitle;
  final String body;
  const _Slide({
    required this.icon, required this.iconColor, required this.bg,
    required this.title, required this.subtitle, required this.body,
  });
}

// ─── Single slide view ────────────────────────────────────────────────────────
class _SlideView extends StatelessWidget {
  final _Slide slide;
  const _SlideView({required this.slide});

  @override
  Widget build(BuildContext context) {
    return Padding(
      padding: const EdgeInsets.symmetric(horizontal: 32),
      child: Column(
        mainAxisAlignment: MainAxisAlignment.center,
        children: [
          // Icon circle
          Container(
            width: 140, height: 140,
            decoration: BoxDecoration(
              shape: BoxShape.circle,
              color: slide.iconColor.withOpacity(0.12),
              border: Border.all(color: slide.iconColor.withOpacity(0.25), width: 1.5),
            ),
            child: Icon(slide.icon, size: 68, color: slide.iconColor),
          ),
          const SizedBox(height: 48),
          // Title
          Text(
            slide.title,
            textAlign: TextAlign.center,
            style: GoogleFonts.prata(
              fontSize: 28, fontWeight: FontWeight.w400,
              color: Colors.white, height: 1.2),
          ),
          const SizedBox(height: 12),
          // Subtitle
          Text(
            slide.subtitle,
            textAlign: TextAlign.center,
            style: GoogleFonts.montserrat(
              fontSize: 14, fontWeight: FontWeight.w600,
              color: slide.iconColor, letterSpacing: 0.3),
          ),
          const SizedBox(height: 20),
          // Body
          Text(
            slide.body,
            textAlign: TextAlign.center,
            style: GoogleFonts.montserrat(
              fontSize: 15, fontWeight: FontWeight.w400,
              color: Colors.white.withOpacity(0.6), height: 1.6),
          ),
        ],
      ),
    );
  }
}
