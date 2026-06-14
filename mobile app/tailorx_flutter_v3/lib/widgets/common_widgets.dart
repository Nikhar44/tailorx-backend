import 'package:flutter/material.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import '../utils/privacy_helper.dart';
import '../utils/constants.dart';

// ─── Status Badge ───────────────────────────────────────────────────
class StatusBadge extends StatelessWidget {
  final String status; final bool isInvoice;
  const StatusBadge({super.key, required this.status, this.isInvoice = false});
  @override Widget build(BuildContext context) {
    final c = isInvoice ? T.invColor(status) : T.stageColor(status);
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(color: c.withOpacity(0.12), borderRadius: BorderRadius.circular(6)),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Container(width: 5, height: 5, decoration: BoxDecoration(color: c, shape: BoxShape.circle)),
        const SizedBox(width: 5),
        Text(status.toUpperCase(), style: TextStyle(fontSize: 12, fontWeight: FontWeight.w700, letterSpacing: 0.6, color: c)),
      ]));
  }
}

// ─── Privacy Text ────────────────────────────────────────────────────
/// Displays [text] when the eye icon has been toggled on (privacy unlocked).
/// Shows soft masked dots when locked. Not tappable — the eye icon in the
/// app bar controls visibility for the whole session.
class PrivacyText extends StatelessWidget {
  final String text;
  final TextStyle? style;
  final TextAlign? textAlign;
  final bool fitted; // wrap in FittedBox for stat cards

  const PrivacyText(this.text, {super.key, this.style, this.textAlign, this.fitted = false});

  @override Widget build(BuildContext context) {
    return ValueListenableBuilder<bool>(
      valueListenable: PrivacyHelper.isUnlocked,
      builder: (_, unlocked, __) {
        if (unlocked) {
          final t = Text(text, style: style, textAlign: textAlign);
          return fitted ? FittedBox(fit: BoxFit.scaleDown, child: t) : t;
        }
        // Masked state — soft dots, same approximate size as the real value
        final maskedStyle = (style ?? const TextStyle()).copyWith(
          fontSize: (style?.fontSize ?? 14) * 0.8,
          letterSpacing: 3,
          color: (style?.color ?? T.text2).withOpacity(0.35),
          fontFamily: null,
        );
        final masked = Text('••••••', style: maskedStyle, textAlign: textAlign);
        return fitted ? FittedBox(fit: BoxFit.scaleDown, child: masked) : masked;
      },
    );
  }
}

// ─── Stat Card ──────────────────────────────────────────────────────
class StatCard extends StatelessWidget {
  final String label, value; final IconData icon; final Color color;
  final bool isPrivate;
  const StatCard({super.key, required this.label, required this.value, required this.icon, required this.color, this.isPrivate = false});
  @override Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(12),
    decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(12), boxShadow: T.shadowCard),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, mainAxisAlignment: MainAxisAlignment.center, children: [
      Container(width: 40, height: 40,
        decoration: BoxDecoration(color: color.withOpacity(0.1), borderRadius: BorderRadius.circular(8)),
        child: Icon(icon, size: 20, color: color)),
      const SizedBox(height: 8),
      isPrivate
        ? PrivacyText(value, style: T.stat.copyWith(fontSize: 24), fitted: true)
        : FittedBox(fit: BoxFit.scaleDown, child: Text(value, style: T.stat.copyWith(fontSize: 24))),
      Text(label.toUpperCase(), style: T.statLabel, maxLines: 1, overflow: TextOverflow.ellipsis),
    ]));
}

// ─── Empty State ────────────────────────────────────────────────────
class EmptyState extends StatelessWidget {
  final IconData icon; final String title, subtitle; final String? buttonLabel; final VoidCallback? onPressed;
  const EmptyState({super.key, required this.icon, required this.title, required this.subtitle, this.buttonLabel, this.onPressed});
  @override Widget build(BuildContext context) => Center(child: Padding(padding: const EdgeInsets.all(40),
    child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
      Icon(icon, size: 60, color: T.text3.withOpacity(0.4)),
      const SizedBox(height: 16),
      Text(title, style: T.displaySm, textAlign: TextAlign.center),
      const SizedBox(height: 6),
      Text(subtitle, style: T.bodySm, textAlign: TextAlign.center),
      if(buttonLabel != null) ...[
        const SizedBox(height: 20),
        ElevatedButton(onPressed: onPressed, child: Text(buttonLabel!.toUpperCase(), style: const TextStyle(letterSpacing: 1))),
      ],
    ])));
}

// ─── Form Field ─────────────────────────────────────────────────────
class TxField extends StatelessWidget {
  final String label; final String? hint; final TextEditingController? controller;
  final TextInputType? keyboardType; final int maxLines; final bool obscureText, readOnly;
  final String? Function(String?)? validator; final Widget? suffix; final void Function(String)? onChanged;
  /// External error shown below the field (e.g. "Incorrect email or password"),
  /// separate from the form `validator`. Highlights the field border in red too.
  final String? errorText;
  const TxField({super.key, required this.label, this.hint, this.controller, this.keyboardType, this.maxLines=1, this.obscureText=false, this.readOnly=false, this.validator, this.suffix, this.onChanged, this.errorText});
  @override Widget build(BuildContext context) => Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
    Text(label.toUpperCase(), style: T.label),
    const SizedBox(height: 6),
    TextFormField(controller: controller, keyboardType: keyboardType, maxLines: maxLines, obscureText: obscureText, readOnly: readOnly,
      validator: validator, onChanged: onChanged, style: T.body,
      decoration: InputDecoration(hintText: hint, suffixIcon: suffix,
        enabledBorder: errorText != null ? OutlineInputBorder(borderRadius: BorderRadius.circular(T.rSm), borderSide: const BorderSide(color: T.danger)) : null,
        errorBorder: errorText != null ? OutlineInputBorder(borderRadius: BorderRadius.circular(T.rSm), borderSide: const BorderSide(color: T.danger)) : null,
        focusedBorder: errorText != null ? OutlineInputBorder(borderRadius: BorderRadius.circular(T.rSm), borderSide: const BorderSide(color: T.danger, width: 1.5)) : null,
      )),
    if (errorText != null) Padding(padding: const EdgeInsets.only(top: 5, left: 2),
      child: Row(children: [
        const Icon(Icons.error_outline_rounded, size: 13, color: T.danger),
        const SizedBox(width: 5),
        Expanded(child: Text(errorText!, style: const TextStyle(fontSize: 12, color: T.danger, fontWeight: FontWeight.w500))),
      ])),
  ]);
}

// ─── Section Header ─────────────────────────────────────────────────
class SecTitle extends StatelessWidget {
  final String title; final String? action; final VoidCallback? onAction;
  const SecTitle({super.key, required this.title, this.action, this.onAction});
  @override Widget build(BuildContext context) => Padding(padding: const EdgeInsets.symmetric(vertical: 8),
    child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
      Text(title.toUpperCase(), style: T.label),
      if(action != null) GestureDetector(onTap: onAction, child: Text(action!, style: T.bodySm.copyWith(color: T.accent, fontWeight: FontWeight.w600))),
    ]));
}

// ─── Measurement Section (Collapsible) ──────────────────────────────
class MeasurementSection extends StatefulWidget {
  final String title; final List<String> fields; final Map<String, String> values;
  final void Function(String, String) onChanged;
  final void Function(String)? onAddCustom, onRemoveCustom;
  final List<String> customFields;
  /// Identifies which measurement guide map to use for the (i) info icon,
  /// e.g. 'maleTop', 'maleBottom', 'femaleTopBlouse', 'femaleTopDress', 'femaleBottom'.
  final String section;
  const MeasurementSection({super.key, required this.title, required this.fields, required this.values, required this.onChanged, this.onAddCustom, this.onRemoveCustom, this.customFields = const [], this.section = ''});
  @override State<MeasurementSection> createState() => _MeasSecState();
}

class _MeasSecState extends State<MeasurementSection> {
  bool _open = true;

  void _showMeasureGuide(BuildContext context, String field, String guideKey) {
    showDialog(context: context, builder: (ctx) => Dialog(
      backgroundColor: Colors.transparent,
      insetPadding: const EdgeInsets.symmetric(horizontal: 24, vertical: 40),
      child: Container(
        decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd)),
        padding: const EdgeInsets.all(12),
        child: Column(mainAxisSize: MainAxisSize.min, children: [
          Row(children: [
            Expanded(child: Text('How to measure: $field', style: T.heading.copyWith(fontSize: 16))),
            GestureDetector(onTap: () => Navigator.pop(ctx),
              child: const Icon(Icons.close_rounded, size: 20, color: T.text3)),
          ]),
          const SizedBox(height: 10),
          ClipRRect(borderRadius: BorderRadius.circular(8),
            child: Image.asset('assets/measurement_guides/$guideKey.png',
              fit: BoxFit.contain,
              errorBuilder: (c, e, s) => Padding(padding: const EdgeInsets.all(24),
                child: Text('Illustration not available', style: T.bodySm.copyWith(color: T.text3))))),
        ]),
      ),
    ));
  }

  @override Widget build(BuildContext context) {
    final lang = AppLang();
    final all = [...widget.fields, ...widget.customFields];
    return Container(margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
      child: Column(children: [
        GestureDetector(onTap: () => setState(() => _open = !_open),
          child: Container(padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
            decoration: BoxDecoration(gradient: LinearGradient(colors: [T.accent.withOpacity(0.08), T.accent.withOpacity(0.02)]),
              borderRadius: BorderRadius.vertical(top: const Radius.circular(T.rMd), bottom: _open ? Radius.zero : const Radius.circular(T.rMd))),
            child: Row(children: [
              Container(width: 3, height: 14, decoration: BoxDecoration(color: T.accent, borderRadius: BorderRadius.circular(2))),
              const SizedBox(width: 10),
              Expanded(child: Text(widget.title.toUpperCase(), style: T.label.copyWith(color: T.accentDark))),
              Icon(_open ? Icons.expand_less_rounded : Icons.expand_more_rounded, size: 18, color: T.accentDark),
            ]))),
        if(_open) Padding(padding: const EdgeInsets.all(14),
          child: Column(children: [
            Wrap(spacing: 8, runSpacing: 10, children: all.map((f) {
              final isCust = widget.customFields.contains(f);
              final guideKey = isCust ? null : C.guideAsset(widget.section, f);
              return SizedBox(width: (MediaQuery.of(context).size.width - 64) / 2,
                child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Row(children: [
                    Expanded(child: Text(f, style: T.bodySm.copyWith(fontSize: 14, fontWeight: FontWeight.w500))),
                    if(guideKey != null) GestureDetector(onTap: () => _showMeasureGuide(context, f, guideKey),
                      child: Padding(padding: const EdgeInsets.only(left: 4),
                        child: Icon(Icons.info_outline_rounded, size: 16, color: T.accentDark.withOpacity(0.7)))),
                    if(isCust) GestureDetector(onTap: () => widget.onRemoveCustom?.call(f),
                      child: const Icon(Icons.close_rounded, size: 14, color: T.danger)),
                  ]),
                  const SizedBox(height: 4),
                  SizedBox(height: 44, child: TextFormField(
                    initialValue: widget.values[f] ?? '',
                    keyboardType: TextInputType.number, style: T.body.copyWith(fontSize: 18),
                    decoration: InputDecoration(contentPadding: const EdgeInsets.symmetric(horizontal: 10),
                      suffixText: 'in', suffixStyle: T.bodySm.copyWith(fontSize: 12)),
                    onChanged: (v) => widget.onChanged(f, v))),
                ]));
            }).toList()),
            if(widget.onAddCustom != null) Padding(padding: const EdgeInsets.only(top: 12),
              child: GestureDetector(onTap: () {
                final c = TextEditingController();
                showDialog(context: context, builder: (ctx) => AlertDialog(
                  title: Text(lang.t('add_custom_field'), style: T.heading),
                  content: TextField(controller: c, autofocus: true, decoration: InputDecoration(hintText: lang.t('custom_field_name'))),
                  actions: [
                    TextButton(onPressed: () => Navigator.pop(ctx), child: Text(lang.t('cancel'))),
                    ElevatedButton(onPressed: () { if(c.text.trim().isNotEmpty){ widget.onAddCustom!(c.text.trim()); Navigator.pop(ctx); } },
                      child: const Text('ADD')),
                  ]));
              }, child: Container(padding: const EdgeInsets.symmetric(vertical: 10),
                decoration: BoxDecoration(border: Border.all(color: T.accent.withOpacity(0.2)), borderRadius: BorderRadius.circular(8), color: T.accent.withOpacity(0.04)),
                child: Center(child: Text('+ CUSTOM FIELD', style: T.bodySm.copyWith(color: T.accentDark, fontWeight: FontWeight.w600)))))),
          ])),
      ]));
  }
}

// ─── Status Pipeline ────────────────────────────────────────────────
class StatusPipeline extends StatelessWidget {
  final String current; final List<String> stages; final void Function(String)? onTap;
  const StatusPipeline({super.key, required this.current, required this.stages, this.onTap});
  @override Widget build(BuildContext context) {
    final ci = stages.indexWhere((s) => s.toLowerCase() == current.toLowerCase());
    return SingleChildScrollView(scrollDirection: Axis.horizontal, child: Row(children: List.generate(stages.length, (i) {
      final done = i < ci; final active = i == ci;
      final c = active ? T.stageColor(stages[i]) : done ? T.success : T.text3;
      return Row(children: [
        GestureDetector(onTap: () => onTap?.call(stages[i]),
          child: AnimatedContainer(duration: const Duration(milliseconds: 300), padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 5),
            decoration: BoxDecoration(color: active ? c.withOpacity(0.15) : done ? c.withOpacity(0.08) : T.surface, borderRadius: BorderRadius.circular(8),
              border: active ? Border.all(color: c, width: 1.5) : null),
            child: Row(children: [
              if(done) Icon(Icons.check_circle_rounded, size: 14, color: c),
              if(done) const SizedBox(width: 3),
              Text(stages[i], style: TextStyle(fontSize: 14, fontWeight: active ? FontWeight.w700 : FontWeight.w400, color: active || done ? c : T.text3)),
            ]))),
        if(i < stages.length - 1) Padding(padding: const EdgeInsets.symmetric(horizontal: 1),
          child: Icon(Icons.chevron_right_rounded, size: 16, color: done ? T.success.withOpacity(0.5) : T.border)),
      ]);
    })));
  }
}

// ─── Pipeline Bar (Dashboard) ───────────────────────────────────────
class PipelineBar extends StatelessWidget {
  final Map<String, int> stages;
  const PipelineBar({super.key, required this.stages});
  @override Widget build(BuildContext context) {
    final total = stages.values.fold(0, (s, v) => s + v);
    return Container(padding: const EdgeInsets.all(14),
      decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(12), boxShadow: T.shadowCard),
      child: Column(children: [
        Row(children: stages.entries.map((e) {
          final c = T.stageColor(e.key);
          final w = total > 0 ? (e.value / total) : 0.0;
          return Expanded(flex: (w * 100).toInt().clamp(1, 100),
            child: Container(height: 6, margin: const EdgeInsets.symmetric(horizontal: 1),
              decoration: BoxDecoration(color: e.value > 0 ? c : T.surface, borderRadius: BorderRadius.circular(3))));
        }).toList()),
        const SizedBox(height: 12),
        Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: stages.entries.map((e) => Column(children: [
          Text('${e.value}', style: T.body.copyWith(fontWeight: FontWeight.w700, fontSize: 16, color: e.value > 0 ? T.stageColor(e.key) : T.text3)),
          Text(e.key.toUpperCase(), style: TextStyle(fontSize: 10, fontWeight: FontWeight.w600, letterSpacing: 0.5, color: T.text3)),
        ])).toList()),
      ]));
  }
}
