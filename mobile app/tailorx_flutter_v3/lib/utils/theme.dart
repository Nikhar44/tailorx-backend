import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';

class T {
  // ─── Colors from styles.css :root ─────────────────────────────
  static const Color headerDark = Color(0xFF1A1A2E);
  static const Color headerMid = Color(0xFF16213E);
  static const Color headerDeep = Color(0xFF0F3460);
  static const Color accent = Color(0xFFD4A574);
  static const Color accentSoft = Color(0xFFE8C49A);
  static const Color accentDark = Color(0xFFB8895A);
  static const Color headerText = Color(0xFFE8E8E8);
  static const Color bg = Color(0xFFF8F7F4);
  static const Color card = Color(0xFFFFFFFF);
  static const Color surface = Color(0xFFF1F0ED);
  static const Color border = Color(0xFFE8E5DF);
  static const Color text = Color(0xFF1A1A2E);
  static const Color text2 = Color(0xFF6B6B7B);
  static const Color text3 = Color(0xFF9E9EA8);
  static const Color success = Color(0xFF2D8F6F);
  static const Color warning = Color(0xFFE09F3E);
  static const Color danger = Color(0xFFCF4747);
  static const Color info = Color(0xFF4A7FC1);
  static const Color purple = Color(0xFF7C5CBF);
  static const Color teal = Color(0xFF2BA5A5);
  static const Color pink = Color(0xFFD67BA0);

  // ─── Radii ────────────────────────────────────────────────────
  static const double rSm = 8;
  static const double rMd = 14;
  static const double rLg = 20;
  static const double rXl = 28;

  // ─── Shadows ──────────────────────────────────────────────────
  static List<BoxShadow> get shadowCard => [
    BoxShadow(color: Colors.black.withOpacity(0.04), blurRadius: 12, offset: const Offset(0, 4)),
    BoxShadow(color: Colors.black.withOpacity(0.02), blurRadius: 4, offset: const Offset(0, 1)),
  ];
  static List<BoxShadow> get shadowElev => [
    BoxShadow(color: Colors.black.withOpacity(0.08), blurRadius: 24, offset: const Offset(0, 8)),
    BoxShadow(color: Colors.black.withOpacity(0.04), blurRadius: 8, offset: const Offset(0, 2)),
  ];

  // ─── Gradients ────────────────────────────────────────────────
  static const LinearGradient headerGrad = LinearGradient(
    begin: Alignment.topLeft, end: Alignment.bottomRight,
    colors: [Color(0xFF1A1A2E), Color(0xFF16213E), Color(0xFF0F3460)]);
  static LinearGradient accentGrad = const LinearGradient(
    begin: Alignment.topLeft, end: Alignment.bottomRight,
    colors: [Color(0xFFD4A574), Color(0xFFE8C49A)]);

  // ─── Status Colors ────────────────────────────────────────────
  static Color stageColor(String s) {
    switch (s.toLowerCase()) {
      case 'received': case 'pending': return warning;
      case 'cutting': return info;
      case 'stitching': return purple;
      case 'trial': return teal;
      case 'ready': case 'completed': return success;
      case 'delivered': return headerDark;
      case 'cancelled': return danger;
      default: return text3;
    }
  }
  static Color invColor(String s) {
    switch (s.toLowerCase()) {
      case 'paid': return success;
      case 'partial': case 'pending': return warning;
      case 'unpaid': case 'overdue': return danger;
      default: return text3;
    }
  }

  // ─── Text Styles ──────────────────────────────────────────────
  static TextStyle get display => GoogleFonts.prata(fontSize: 36, fontWeight: FontWeight.w400, color: text);
  static TextStyle get displayMd => GoogleFonts.prata(fontSize: 30, fontWeight: FontWeight.w400, color: text);
  static TextStyle get displaySm => GoogleFonts.prata(fontSize: 24, fontWeight: FontWeight.w400, color: text);
  static TextStyle get heading => GoogleFonts.montserrat(fontSize: 22, fontWeight: FontWeight.w700, color: text);
  static TextStyle get body => GoogleFonts.montserrat(fontSize: 18, fontWeight: FontWeight.w500, color: text);
  static TextStyle get bodySm => GoogleFonts.montserrat(fontSize: 16, fontWeight: FontWeight.w500, color: text2);
  static TextStyle get label => GoogleFonts.montserrat(fontSize: 14, fontWeight: FontWeight.w800, color: text2, letterSpacing: 2.0);
  static TextStyle get btn => GoogleFonts.montserrat(fontSize: 18, fontWeight: FontWeight.w700, color: card, letterSpacing: 0.8);
  static TextStyle get stat => GoogleFonts.prata(fontSize: 32, fontWeight: FontWeight.w400, color: text);
  static TextStyle get statLabel => GoogleFonts.montserrat(fontSize: 12, fontWeight: FontWeight.w700, color: text3, letterSpacing: 1.8);

  // ─── Responsive Helpers ───────────────────────────────────────
  static bool isTablet(BuildContext ctx) =>
      MediaQuery.of(ctx).size.width >= 600;
  static bool isLargeTablet(BuildContext ctx) =>
      MediaQuery.of(ctx).size.width >= 900;

  /// Horizontal page padding — larger on tablets
  static double hPad(BuildContext ctx) =>
      isLargeTablet(ctx) ? 40.0 : isTablet(ctx) ? 28.0 : 18.0;

  /// Max content width — centres content on large tablets
  static double maxW(BuildContext ctx) =>
      isLargeTablet(ctx) ? 900.0 : double.infinity;

  /// Bottom sheet max width — looks good on iPad
  static double sheetMaxW(BuildContext ctx) =>
      isTablet(ctx) ? 600.0 : double.infinity;

  /// Wraps a bottom sheet body so it is centred + max-width on tablets
  static Widget sheetWrap(BuildContext ctx, Widget child) {
    if (!isTablet(ctx)) return child;
    return Center(
      child: ConstrainedBox(
        constraints: BoxConstraints(maxWidth: sheetMaxW(ctx)),
        child: child,
      ),
    );
  }

  // ─── ThemeData ────────────────────────────────────────────────
  static ThemeData get theme => ThemeData(
    brightness: Brightness.light, scaffoldBackgroundColor: bg, primaryColor: headerDark,
    colorScheme: const ColorScheme.light(primary: headerDark, secondary: accent, surface: card, error: danger),
    appBarTheme: AppBarTheme(
      backgroundColor: headerDark, elevation: 0, scrolledUnderElevation: 0, centerTitle: false,
      titleTextStyle: GoogleFonts.prata(fontSize: 24, fontWeight: FontWeight.w400, color: headerText, letterSpacing: 0.4),
      iconTheme: const IconThemeData(color: headerText, size: 24)),
    inputDecorationTheme: InputDecorationTheme(
      filled: true, fillColor: surface,
      contentPadding: const EdgeInsets.symmetric(horizontal: 18, vertical: 16),
      border: OutlineInputBorder(borderRadius: BorderRadius.circular(rMd), borderSide: BorderSide.none),
      enabledBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(rMd), borderSide: BorderSide.none),
      focusedBorder: OutlineInputBorder(borderRadius: BorderRadius.circular(rMd), borderSide: const BorderSide(color: accent, width: 2.0)),
      hintStyle: GoogleFonts.montserrat(fontSize: 18, color: text3)),
    elevatedButtonTheme: ElevatedButtonThemeData(style: ElevatedButton.styleFrom(
      backgroundColor: headerDark, foregroundColor: card, elevation: 0,
      padding: const EdgeInsets.symmetric(horizontal: 28, vertical: 16),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(rMd)))),
    snackBarTheme: SnackBarThemeData(
      backgroundColor: headerDark, behavior: SnackBarBehavior.floating,
      contentTextStyle: GoogleFonts.montserrat(fontSize: 16, color: card),
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(rMd))),
    dividerTheme: const DividerThemeData(color: border, thickness: 1, space: 1),
    floatingActionButtonTheme: FloatingActionButtonThemeData(
      backgroundColor: accent, foregroundColor: card, elevation: 8,
      shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(rMd))),
  );
}
