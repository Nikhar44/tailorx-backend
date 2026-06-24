import 'package:intl/intl.dart';
import 'package:pdf/pdf.dart';
import 'package:pdf/widgets.dart' as pw;
import 'package:printing/printing.dart';
import '../models/models.dart'; // Invoice, Customer

// ─── Measurement colours (matching app palette) ─────────────────────────────
const _headerDark = PdfColor.fromInt(0xFF1a1a2e);
const _accent     = PdfColor.fromInt(0xFFD4A574);
const _surface    = PdfColor.fromInt(0xFFF4F3EF);
const _text2      = PdfColor.fromInt(0xFF6B6B7B);

class PdfHelper {
  static final _fmt = NumberFormat.currency(locale: 'en_IN', symbol: 'Rs. ', decimalDigits: 2);

  static Future<void> generateAndShareInvoice(Invoice inv, {String? boutiqueName, String? boutiqueAddress, String? boutiquePhone, String? boutiqueGST, String? boutiqueLogo, String? termsAndConditions}) async {
    final pdf = await _buildPdf(inv, boutiqueName ?? 'TailorX Boutique', boutiqueAddress, boutiquePhone, boutiqueGST, boutiqueLogo, termsAndConditions);
    await Printing.sharePdf(bytes: await pdf.save(), filename: 'invoice_${inv.id ?? "new"}.pdf');
  }

  static Future<void> generateAndPrintInvoice(Invoice inv, {String? boutiqueName, String? boutiqueAddress, String? boutiquePhone, String? boutiqueGST, String? boutiqueLogo, String? termsAndConditions}) async {
    final pdf = await _buildPdf(inv, boutiqueName ?? 'TailorX Boutique', boutiqueAddress, boutiquePhone, boutiqueGST, boutiqueLogo, termsAndConditions);
    await Printing.layoutPdf(onLayout: (PdfPageFormat format) async => pdf.save());
  }

  // ─── Job Card / Work Order PDF (internal — for tailors/employees) ──────────

  static Future<void> generateAndShareJobCard(Order o, Customer? customer, {String? boutiqueName, String? boutiqueAddress, String? boutiquePhone}) async {
    final pdf = await _buildJobCardPdf(o, customer, boutiqueName ?? 'TailorX Boutique', boutiqueAddress, boutiquePhone);
    await Printing.sharePdf(bytes: await pdf.save(), filename: 'job_card_${o.id ?? "new"}.pdf');
  }

  static Future<void> generateAndPrintJobCard(Order o, Customer? customer, {String? boutiqueName, String? boutiqueAddress, String? boutiquePhone}) async {
    final pdf = await _buildJobCardPdf(o, customer, boutiqueName ?? 'TailorX Boutique', boutiqueAddress, boutiquePhone);
    await Printing.layoutPdf(onLayout: (PdfPageFormat format) async => pdf.save());
  }

  static Future<pw.Document> _buildJobCardPdf(Order o, Customer? customer, String boutiqueName, String? boutiqueAddress, String? boutiquePhone) async {
    final pdf = pw.Document();
    final orderNo = o.id != null ? 'ORD-${o.id!.padLeft(4, "0")}' : 'ORDER';
    final dueDate = o.dueDate?.isNotEmpty == true ? _fmtDate(o.dueDate) : null;
    final trialDate = o.trialDate?.isNotEmpty == true ? _fmtDate(o.trialDate) : null;
    final createdDate = _fmtDate(o.createdAt ?? DateTime.now().toIso8601String());

    // Build per-item blocks (garment/fabric + optional photos), falling back
    // to the legacy single garment/fabric/photo fields when o.items is empty.
    final itemBlocks = <Map<String, dynamic>>[];
    if (o.items.isNotEmpty) {
      for (final it in o.items) {
        pw.ImageProvider? cImg;
        pw.ImageProvider? dImg;
        if (it.clothPhotoUrl?.isNotEmpty == true) {
          try { cImg = await networkImage(it.clothPhotoUrl!); } catch (_) {}
        }
        if (it.designPhotoUrl?.isNotEmpty == true) {
          try { dImg = await networkImage(it.designPhotoUrl!); } catch (_) {}
        }
        itemBlocks.add({
          'garment': it.garment,
          'fabric': it.fabric,
          'clothImg': cImg,
          'designImg': dImg,
        });
      }
    } else {
      pw.ImageProvider? cImg;
      pw.ImageProvider? dImg;
      if (o.clothPhotoUrl?.isNotEmpty == true) {
        try { cImg = await networkImage(o.clothPhotoUrl!); } catch (_) {}
      }
      if (o.designPhotoUrl?.isNotEmpty == true) {
        try { dImg = await networkImage(o.designPhotoUrl!); } catch (_) {}
      }
      itemBlocks.add({
        'garment': o.garment,
        'fabric': o.fabric,
        'clothImg': cImg,
        'designImg': dImg,
      });
    }

    final isMale = customer?.gender?.toLowerCase() == 'male';
    final measurementSections = customer != null ? _buildMeasurementSections(customer, isMale) : <pw.Widget>[];

    pdf.addPage(pw.MultiPage(
      pageFormat: PdfPageFormat.a4,
      margin: const pw.EdgeInsets.all(36),
      build: (context) => [
        // ── Header ──
        pw.Container(
          padding: const pw.EdgeInsets.all(20),
          decoration: pw.BoxDecoration(
            color: _headerDark,
            borderRadius: const pw.BorderRadius.all(pw.Radius.circular(8)),
          ),
          child: pw.Row(
            mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
            children: [
              pw.Column(crossAxisAlignment: pw.CrossAxisAlignment.start, children: [
                pw.Text(boutiqueName.toUpperCase(),
                  style: pw.TextStyle(fontSize: 20, fontWeight: pw.FontWeight.bold, color: _accent, letterSpacing: 2)),
                if (boutiqueAddress != null && boutiqueAddress.isNotEmpty)
                  pw.Padding(padding: const pw.EdgeInsets.only(top: 4),
                    child: pw.Text(boutiqueAddress,
                      style: pw.TextStyle(fontSize: 11, color: const PdfColor(1, 1, 1, 0.6), letterSpacing: 0.5))),
                if (boutiquePhone != null && boutiquePhone.isNotEmpty)
                  pw.Text(boutiquePhone,
                    style: pw.TextStyle(fontSize: 11, color: const PdfColor(1, 1, 1, 0.6))),
              ]),
              pw.Column(crossAxisAlignment: pw.CrossAxisAlignment.end, children: [
                pw.Text('JOB CARD',
                  style: pw.TextStyle(fontSize: 15, color: _accent, fontWeight: pw.FontWeight.bold, letterSpacing: 3)),
                pw.SizedBox(height: 4),
                pw.Text(orderNo,
                  style: pw.TextStyle(fontSize: 13, color: const PdfColor(1, 1, 1, 0.6), letterSpacing: 1)),
                pw.Text(createdDate,
                  style: pw.TextStyle(fontSize: 12, color: const PdfColor(1, 1, 1, 0.6))),
              ]),
            ],
          ),
        ),
        pw.SizedBox(height: 16),
        // ── Customer + Delivery ──
        pw.Row(
          crossAxisAlignment: pw.CrossAxisAlignment.start,
          children: [
            pw.Expanded(child: pw.Column(crossAxisAlignment: pw.CrossAxisAlignment.start, children: [
              pw.Text('CUSTOMER',
                style: pw.TextStyle(fontSize: 11, letterSpacing: 2, color: _text2, fontWeight: pw.FontWeight.bold)),
              pw.SizedBox(height: 6),
              pw.Text(o.customerName ?? '-',
                style: pw.TextStyle(fontSize: 16, fontWeight: pw.FontWeight.bold)),
              if (o.customerPhone?.isNotEmpty == true)
                pw.Text(o.customerPhone!,
                  style: pw.TextStyle(fontSize: 13, color: _text2)),
            ])),
            pw.Column(crossAxisAlignment: pw.CrossAxisAlignment.end, children: [
              if (trialDate != null) ...[
                pw.Text('TRIAL DATE',
                  style: pw.TextStyle(fontSize: 11, letterSpacing: 2, color: _text2, fontWeight: pw.FontWeight.bold)),
                pw.SizedBox(height: 6),
                pw.Text(trialDate,
                  style: pw.TextStyle(fontSize: 16, fontWeight: pw.FontWeight.bold)),
                pw.SizedBox(height: 8),
              ],
              if (dueDate != null) ...[
                pw.Text('DELIVERY DATE',
                  style: pw.TextStyle(fontSize: 11, letterSpacing: 2, color: _text2, fontWeight: pw.FontWeight.bold)),
                pw.SizedBox(height: 6),
                pw.Text(dueDate,
                  style: pw.TextStyle(fontSize: 16, fontWeight: pw.FontWeight.bold, color: const PdfColor(0.81, 0.28, 0.28))),
              ],
            ]),
          ],
        ),
        pw.SizedBox(height: 16),
        pw.Divider(color: const PdfColor(0.91, 0.9, 0.87)),
        pw.SizedBox(height: 16),
        // ── Garment / Fabric (per item) ──
        for (var idx = 0; idx < itemBlocks.length; idx++) ...[
          if (idx > 0) pw.SizedBox(height: 16),
          pw.Container(
            width: double.infinity,
            decoration: pw.BoxDecoration(
              color: _surface,
              borderRadius: const pw.BorderRadius.all(pw.Radius.circular(6)),
            ),
            padding: const pw.EdgeInsets.all(16),
            child: pw.Column(crossAxisAlignment: pw.CrossAxisAlignment.start, children: [
              pw.Text(itemBlocks.length > 1 ? 'ITEM ${idx + 1} DETAILS' : 'GARMENT DETAILS',
                style: pw.TextStyle(fontSize: 11, letterSpacing: 2, color: _text2, fontWeight: pw.FontWeight.bold)),
              pw.SizedBox(height: 12),
              if ((itemBlocks[idx]['garment'] as String?)?.isNotEmpty == true)
                _odRow('Garment', itemBlocks[idx]['garment'] as String),
              if ((itemBlocks[idx]['fabric'] as String?)?.isNotEmpty == true)
                _odRow('Fabric', itemBlocks[idx]['fabric'] as String),
              if (((itemBlocks[idx]['garment'] as String?)?.isEmpty ?? true) &&
                  ((itemBlocks[idx]['fabric'] as String?)?.isEmpty ?? true))
                pw.Text('-', style: pw.TextStyle(fontSize: 13, color: _text2)),
            ]),
          ),
          // ── Reference Photos ──
          if (itemBlocks[idx]['clothImg'] != null || itemBlocks[idx]['designImg'] != null) ...[
            pw.SizedBox(height: 16),
            pw.Text('REFERENCE PHOTOS',
              style: pw.TextStyle(fontSize: 11, letterSpacing: 2, color: _text2, fontWeight: pw.FontWeight.bold)),
            pw.SizedBox(height: 8),
            pw.Row(children: [
              if (itemBlocks[idx]['clothImg'] != null)
                pw.Expanded(child: pw.Column(children: [
                  pw.Container(
                    height: 180,
                    width: double.infinity,
                    decoration: pw.BoxDecoration(
                      border: pw.Border.all(color: const PdfColor(0.91, 0.9, 0.87)),
                      borderRadius: pw.BorderRadius.circular(6),
                    ),
                    child: pw.ClipRRect(horizontalRadius: 6, verticalRadius: 6,
                      child: pw.Image(itemBlocks[idx]['clothImg'] as pw.ImageProvider, fit: pw.BoxFit.cover)),
                  ),
                  pw.SizedBox(height: 4),
                  pw.Text('Cloth / Material', style: pw.TextStyle(fontSize: 11, color: _text2)),
                ])),
              if (itemBlocks[idx]['clothImg'] != null && itemBlocks[idx]['designImg'] != null) pw.SizedBox(width: 12),
              if (itemBlocks[idx]['designImg'] != null)
                pw.Expanded(child: pw.Column(children: [
                  pw.Container(
                    height: 180,
                    width: double.infinity,
                    decoration: pw.BoxDecoration(
                      border: pw.Border.all(color: const PdfColor(0.91, 0.9, 0.87)),
                      borderRadius: pw.BorderRadius.circular(6),
                    ),
                    child: pw.ClipRRect(horizontalRadius: 6, verticalRadius: 6,
                      child: pw.Image(itemBlocks[idx]['designImg'] as pw.ImageProvider, fit: pw.BoxFit.cover)),
                  ),
                  pw.SizedBox(height: 4),
                  pw.Text('Design', style: pw.TextStyle(fontSize: 11, color: _text2)),
                ])),
            ]),
          ],
        ],
        // ── Measurements ──
        if (measurementSections.isNotEmpty) ...[
          pw.SizedBox(height: 16),
          pw.Text('CUSTOMER MEASUREMENTS',
            style: pw.TextStyle(fontSize: 11, letterSpacing: 2, color: _text2, fontWeight: pw.FontWeight.bold)),
          pw.SizedBox(height: 8),
          ...measurementSections,
        ] else ...[
          pw.SizedBox(height: 16),
          pw.Container(
            width: double.infinity,
            padding: const pw.EdgeInsets.all(12),
            decoration: pw.BoxDecoration(
              color: _surface,
              borderRadius: pw.BorderRadius.circular(6),
            ),
            child: pw.Text('No saved measurements for this customer.',
              style: pw.TextStyle(fontSize: 12, color: _text2, fontStyle: pw.FontStyle.italic)),
          ),
        ],
        // ── Notes / Special Instructions ──
        if (o.notes?.isNotEmpty == true) ...[
          pw.SizedBox(height: 16),
          pw.Container(
            width: double.infinity,
            decoration: pw.BoxDecoration(
              color: _surface,
              borderRadius: pw.BorderRadius.circular(6),
              border: pw.Border.all(color: _accent, width: 0.5),
            ),
            padding: const pw.EdgeInsets.all(12),
            child: pw.Column(crossAxisAlignment: pw.CrossAxisAlignment.start, children: [
              pw.Text('SPECIAL INSTRUCTIONS / NOTES',
                style: pw.TextStyle(fontSize: 11, fontWeight: pw.FontWeight.bold, color: _text2)),
              pw.SizedBox(height: 6),
              pw.Text(o.notes!, style: pw.TextStyle(fontSize: 12)),
            ]),
          ),
        ],
        pw.SizedBox(height: 20),
        pw.Divider(color: const PdfColor(0.91, 0.9, 0.87)),
        pw.SizedBox(height: 8),
        pw.Center(
          child: pw.Text('Internal Use Only — Not a billing document',
            style: pw.TextStyle(fontSize: 11, color: _text2, fontStyle: pw.FontStyle.italic)),
        ),
      ],
    ));
    return pdf;
  }

  static pw.Widget _odRow(String label, String value) => pw.Padding(
    padding: const pw.EdgeInsets.only(bottom: 8),
    child: pw.Row(crossAxisAlignment: pw.CrossAxisAlignment.start, children: [
      pw.SizedBox(width: 80,
        child: pw.Text(label, style: pw.TextStyle(fontSize: 13, color: _text2))),
      pw.Expanded(
        child: pw.Text(value, style: pw.TextStyle(fontSize: 13, fontWeight: pw.FontWeight.bold))),
    ]),
  );


  /// Parses any date string (ISO timestamp or plain date) → "dd MMM yyyy"
  static String _fmtDate(String? raw) {
    if (raw == null || raw.isEmpty) return '-';
    try {
      final dt = DateTime.parse(raw).toLocal();
      return DateFormat('dd MMM yyyy').format(dt);
    } catch (_) {
      // Already a plain string like "06/05/2026" — return as-is
      return raw;
    }
  }

  static Future<pw.Document> _buildPdf(Invoice inv, String boutiqueName, String? boutiqueAddress, String? boutiquePhone, String? boutiqueGST, String? boutiqueLogo, String? termsAndConditions) async {
    final pdf = pw.Document();
    final billDate  = _fmtDate(inv.billDate ?? DateTime.now().toIso8601String());
    final invNo     = inv.id != null  ? 'INV-${inv.id!.padLeft(4, "0")}' : 'DRAFT';

    pw.ImageProvider? logoImage;
    if (boutiqueLogo != null && boutiqueLogo.isNotEmpty) {
      try { logoImage = await networkImage(boutiqueLogo); } catch (_) {}
    }

    pdf.addPage(
      pw.Page(
        pageFormat: PdfPageFormat.a4,
        margin: const pw.EdgeInsets.fromLTRB(32, 32, 32, 28),
        build: (pw.Context context) => pw.Column(
          crossAxisAlignment: pw.CrossAxisAlignment.start,
          children: [

            // ── HEADER: Logo + Boutique Info + INVOICE label ──────────────
            pw.Container(
              padding: const pw.EdgeInsets.all(14),
              decoration: pw.BoxDecoration(
                color: PdfColors.blueGrey800,
                borderRadius: pw.BorderRadius.circular(8),
              ),
              child: pw.Row(
                crossAxisAlignment: pw.CrossAxisAlignment.start,
                children: [
                  // Logo
                  if (logoImage != null)
                    pw.Container(
                      width: 60, height: 60,
                      margin: const pw.EdgeInsets.only(right: 14),
                      child: pw.ClipRRect(
                        horizontalRadius: 6, verticalRadius: 6,
                        child: pw.Image(logoImage, fit: pw.BoxFit.cover),
                      ),
                    ),
                  // Boutique details
                  pw.Expanded(
                    child: pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        pw.Text(boutiqueName.toUpperCase(),
                            style: pw.TextStyle(fontSize: 18, fontWeight: pw.FontWeight.bold, color: PdfColors.amber300)),
                        if (boutiqueAddress?.isNotEmpty == true)
                          pw.Text(boutiqueAddress!, style: const pw.TextStyle(fontSize: 10, color: PdfColors.white)),
                        if (boutiquePhone?.isNotEmpty == true)
                          pw.Text('Ph: $boutiquePhone', style: const pw.TextStyle(fontSize: 10, color: PdfColors.white)),
                        if (inv.gstEnabled && boutiqueGST?.isNotEmpty == true)
                          pw.Text('GSTIN: $boutiqueGST', style: pw.TextStyle(fontSize: 10, color: PdfColors.amber100)),
                      ],
                    ),
                  ),
                  // Invoice label + number
                  pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.end,
                    children: [
                      pw.Text('INVOICE', style: pw.TextStyle(fontSize: 20, fontWeight: pw.FontWeight.bold, color: PdfColors.amber300)),
                      pw.Text(invNo, style: const pw.TextStyle(fontSize: 11, color: PdfColors.white)),
                    ],
                  ),
                ],
              ),
            ),
            pw.SizedBox(height: 12),

            // ── BILL TO + DATES ROW ───────────────────────────────────────
            pw.Row(
              crossAxisAlignment: pw.CrossAxisAlignment.start,
              children: [
                // Customer info
                pw.Expanded(
                  child: pw.Container(
                    padding: const pw.EdgeInsets.all(10),
                    decoration: pw.BoxDecoration(
                      border: pw.Border.all(color: PdfColors.blueGrey200, width: 0.5),
                      borderRadius: pw.BorderRadius.circular(6),
                    ),
                    child: pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        pw.Text('BILL TO', style: pw.TextStyle(fontSize: 9, fontWeight: pw.FontWeight.bold, color: PdfColors.blueGrey500)),
                        pw.SizedBox(height: 4),
                        pw.Text(inv.customerName ?? 'Walk-in Customer',
                            style: pw.TextStyle(fontSize: 15, fontWeight: pw.FontWeight.bold)),
                        if (inv.customerPhone?.isNotEmpty == true)
                          pw.Text('Ph: ${inv.customerPhone}', style: const pw.TextStyle(fontSize: 11, color: PdfColors.grey700)),
                        if (inv.customerCity?.isNotEmpty == true)
                          pw.Text(inv.customerCity!, style: const pw.TextStyle(fontSize: 11, color: PdfColors.grey700)),
                        if (inv.customerAddress?.isNotEmpty == true)
                          pw.Text(inv.customerAddress!, style: const pw.TextStyle(fontSize: 11, color: PdfColors.grey600)),
                      ],
                    ),
                  ),
                ),
                pw.SizedBox(width: 10),
                // Dates
                pw.Container(
                  width: 160,
                  padding: const pw.EdgeInsets.all(10),
                  decoration: pw.BoxDecoration(
                    border: pw.Border.all(color: PdfColors.blueGrey200, width: 0.5),
                    borderRadius: pw.BorderRadius.circular(6),
                  ),
                  child: pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [
                      if (inv.orderId?.isNotEmpty == true)
                        _dateRow('Order No', 'ORD-${inv.orderId!.padLeft(4, "0")}'),
                      _dateRow('Bill Date',     billDate),
                      _dateRow('Trial Date',    _fmtDate(inv.trialDate)),
                      _dateRow('Delivery Date', _fmtDate(inv.deliveryDate)),
                    ],
                  ),
                ),
              ],
            ),
            pw.SizedBox(height: 12),

            // ── ITEMS TABLE ───────────────────────────────────────────────
            pw.Table(
              border: pw.TableBorder.all(color: PdfColors.blueGrey200, width: 0.5),
              columnWidths: {
                0: const pw.FlexColumnWidth(4),
                1: const pw.FixedColumnWidth(36),
                2: const pw.FixedColumnWidth(72),
                3: const pw.FixedColumnWidth(72),
              },
              children: [
                // Header row
                pw.TableRow(
                  decoration: const pw.BoxDecoration(color: PdfColors.blueGrey800),
                  children: [
                    _th('PARTICULARS'),
                    _th('QTY', align: pw.TextAlign.center),
                    _th('RATE',  align: pw.TextAlign.right),
                    _th('AMOUNT', align: pw.TextAlign.right),
                  ],
                ),
                // Item row
                pw.TableRow(
                  children: [
                    _td(inv.garment ?? 'Custom Order'),
                    _td('1', align: pw.TextAlign.center),
                    _td(_fmt.format(inv.subtotal), align: pw.TextAlign.right),
                    _td(_fmt.format(inv.subtotal), align: pw.TextAlign.right),
                  ],
                ),
                // Empty filler rows for clean look
                for (int i = 0; i < 3; i++)
                  pw.TableRow(children: [_td(''), _td(''), _td(''), _td('')]),
              ],
            ),
            pw.SizedBox(height: 10),

            // ── SUMMARY ───────────────────────────────────────────────────
            pw.Row(
              mainAxisAlignment: pw.MainAxisAlignment.end,
              children: [
                pw.Container(
                  width: 200,
                  child: pw.Column(
                    children: [
                      _summaryRow('Subtotal:', _fmt.format(inv.subtotal)),
                      if (inv.discountAmt > 0)
                        _summaryRow('Discount (${inv.discountPct.toStringAsFixed(0)}%):', '- ${_fmt.format(inv.discountAmt)}'),
                      if (inv.gstEnabled && inv.gstAmt > 0)
                        _summaryRow('GST (${inv.gstPct.toStringAsFixed(inv.gstPct % 1 == 0 ? 0 : 1)}%):', _fmt.format(inv.gstAmt)),
                      pw.Divider(color: PdfColors.blueGrey300, thickness: 0.5),
                      _summaryRow('Advance Paid:', _fmt.format(inv.advance), color: PdfColors.green800),
                      _summaryRow('Due Amount:', _fmt.format(inv.dueAmount), color: PdfColors.red800),
                      pw.Divider(color: PdfColors.blueGrey800, thickness: 1),
                      _summaryRow('Total Amount:', _fmt.format(inv.totalAmount), isBold: true),
                    ],
                  ),
                ),
              ],
            ),

            pw.Spacer(),

            // ── TERMS & CONDITIONS ────────────────────────────────────────
            if (termsAndConditions != null && termsAndConditions.isNotEmpty) ...[
              pw.Divider(color: PdfColors.blueGrey300, thickness: 0.5),
              pw.SizedBox(height: 4),
              pw.Text('Terms & Conditions:', style: pw.TextStyle(fontSize: 10, fontWeight: pw.FontWeight.bold)),
              pw.SizedBox(height: 2),
              pw.Text(termsAndConditions, style: const pw.TextStyle(fontSize: 10, color: PdfColors.grey700)),
              pw.SizedBox(height: 8),
            ] else ...[
              pw.Divider(color: PdfColors.blueGrey300, thickness: 0.5),
              pw.SizedBox(height: 4),
            ],

            // ── FOOTER ────────────────────────────────────────────────────
            pw.Row(
              mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
              children: [
                pw.Text('Thank you for your business!',
                    style: pw.TextStyle(fontSize: 11, fontStyle: pw.FontStyle.italic, color: PdfColors.grey600)),
                pw.Column(
                  crossAxisAlignment: pw.CrossAxisAlignment.end,
                  children: [
                    pw.Text('Authorized Signatory', style: const pw.TextStyle(fontSize: 11)),
                    pw.SizedBox(height: 16),
                    pw.Text('____________________', style: const pw.TextStyle(fontSize: 11)),
                    pw.Text(boutiqueName, style: const pw.TextStyle(fontSize: 10, color: PdfColors.grey600)),
                  ],
                ),
              ],
            ),
          ],
        ),
      ),
    );
    return pdf;
  }

  static pw.Widget _dateRow(String label, String value) => pw.Padding(
    padding: const pw.EdgeInsets.only(bottom: 4),
    child: pw.Row(
      mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
      children: [
        pw.Text(label, style: const pw.TextStyle(fontSize: 10, color: PdfColors.grey600)),
        pw.Text(value, style: pw.TextStyle(fontSize: 10, fontWeight: pw.FontWeight.bold)),
      ],
    ),
  );

  static pw.Widget _th(String text, {pw.TextAlign align = pw.TextAlign.left}) =>
    pw.Padding(
      padding: const pw.EdgeInsets.symmetric(horizontal: 6, vertical: 6),
      child: pw.Text(text,
        textAlign: align,
        style: pw.TextStyle(fontSize: 10, fontWeight: pw.FontWeight.bold, color: PdfColors.white)),
    );

  static pw.Widget _td(String text, {pw.TextAlign align = pw.TextAlign.left}) =>
    pw.Padding(
      padding: const pw.EdgeInsets.symmetric(horizontal: 6, vertical: 6),
      child: pw.Text(text, textAlign: align, style: const pw.TextStyle(fontSize: 11)),
    );

  // ─── Measurement Card PDF ────────────────────────────────────────────────────

  static Future<void> generateAndShareMeasurements(
    Customer c, {
    String? boutiqueName,
    String? boutiqueAddress,
  }) async {
    final pdf = await _buildMeasurementPdf(c, boutiqueName ?? 'TailorX Boutique', boutiqueAddress);
    await Printing.sharePdf(
      bytes: await pdf.save(),
      filename: 'measurements_${c.name.replaceAll(' ', '_')}.pdf',
    );
  }

  static Future<void> printMeasurements(
    Customer c, {
    String? boutiqueName,
    String? boutiqueAddress,
  }) async {
    final pdf = await _buildMeasurementPdf(c, boutiqueName ?? 'TailorX Boutique', boutiqueAddress);
    await Printing.layoutPdf(onLayout: (PdfPageFormat format) async => pdf.save());
  }

  static Future<pw.Document> _buildMeasurementPdf(
    Customer c,
    String boutiqueName,
    String? boutiqueAddress,
  ) async {
    final pdf = pw.Document();
    final isMale = c.gender?.toLowerCase() == 'male';
    final dateStr = DateFormat('dd MMM yyyy').format(DateTime.now());
    final hasTop = c.measurementsTop?.isNotEmpty == true;
    final hasBottom = c.measurementsBottom?.isNotEmpty == true;

    pdf.addPage(
      pw.Page(
        pageFormat: PdfPageFormat.a4,
        margin: const pw.EdgeInsets.all(36),
        build: (pw.Context context) {
          return pw.Column(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              // ── Header ──────────────────────────────────────────────
              pw.Container(
                padding: const pw.EdgeInsets.all(16),
                decoration: pw.BoxDecoration(
                  color: _headerDark,
                  borderRadius: pw.BorderRadius.circular(10),
                ),
                child: pw.Row(
                  mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                  children: [
                    pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        pw.Text(boutiqueName.toUpperCase(),
                            style: pw.TextStyle(
                                fontSize: 20, fontWeight: pw.FontWeight.bold, color: _accent)),
                        if (boutiqueAddress != null && boutiqueAddress.isNotEmpty)
                          pw.SizedBox(height: 4),
                        if (boutiqueAddress != null && boutiqueAddress.isNotEmpty)
                          pw.Text(boutiqueAddress,
                              style: pw.TextStyle(fontSize: 10, color: PdfColor.fromInt(0xB3FFFFFF))),
                      ],
                    ),
                    pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.end,
                      children: [
                        pw.Text('MEASUREMENT CARD',
                            style: pw.TextStyle(
                                fontSize: 12, fontWeight: pw.FontWeight.bold, color: _accent)),
                        pw.SizedBox(height: 4),
                        pw.Text('Printed: $dateStr',
                            style: pw.TextStyle(fontSize: 10, color: PdfColor.fromInt(0xB3FFFFFF))),
                      ],
                    ),
                  ],
                ),
              ),
              pw.SizedBox(height: 16),

              // ── Customer Info Bar ────────────────────────────────────
              pw.Container(
                padding: const pw.EdgeInsets.symmetric(horizontal: 16, vertical: 12),
                decoration: pw.BoxDecoration(
                  color: _surface,
                  borderRadius: pw.BorderRadius.circular(8),
                  border: pw.Border.all(color: _accent, width: 0.5),
                ),
                child: pw.Row(
                  mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
                  children: [
                    pw.Column(
                      crossAxisAlignment: pw.CrossAxisAlignment.start,
                      children: [
                        pw.Text(c.name,
                            style: pw.TextStyle(fontSize: 22, fontWeight: pw.FontWeight.bold)),
                        pw.SizedBox(height: 2),
                        pw.Text(isMale ? 'Male' : 'Female',
                            style: pw.TextStyle(fontSize: 12, color: _text2)),
                        if (c.city?.isNotEmpty == true)
                          pw.Text(c.city!,
                              style: pw.TextStyle(fontSize: 11, color: _text2)),
                      ],
                    ),
                    if (c.dob?.isNotEmpty == true)
                      pw.Column(
                        crossAxisAlignment: pw.CrossAxisAlignment.end,
                        children: [
                          pw.Text('Birthday', style: pw.TextStyle(fontSize: 10, color: _text2)),
                          pw.Text(
                            DateFormat('dd MMM yyyy').format(DateTime.parse(c.dob!)),
                            style: pw.TextStyle(fontSize: 12, fontWeight: pw.FontWeight.bold),
                          ),
                        ],
                      ),
                  ],
                ),
              ),
              pw.SizedBox(height: 20),

              // ── Measurements ─────────────────────────────────────────
              ..._buildMeasurementSections(c, isMale),

              // ── Notes ────────────────────────────────────────────────
              if (c.notes?.isNotEmpty == true) ...[
                pw.SizedBox(height: 16),
                pw.Container(
                  width: double.infinity,
                  padding: const pw.EdgeInsets.all(12),
                  decoration: pw.BoxDecoration(
                    color: _surface,
                    borderRadius: pw.BorderRadius.circular(8),
                    border: pw.Border.all(color: _accent, width: 0.5),
                  ),
                  child: pw.Column(
                    crossAxisAlignment: pw.CrossAxisAlignment.start,
                    children: [
                      pw.Text('FITTING NOTES',
                          style: pw.TextStyle(fontSize: 11, fontWeight: pw.FontWeight.bold, color: _text2)),
                      pw.SizedBox(height: 6),
                      pw.Text(c.notes!,
                          style: pw.TextStyle(fontSize: 12)),
                    ],
                  ),
                ),
              ],

              pw.Spacer(),

              // ── Footer ───────────────────────────────────────────────
              pw.Divider(color: PdfColors.grey300),
              pw.Center(
                child: pw.Text(
                  'Measurements recorded by $boutiqueName · $dateStr',
                  style: pw.TextStyle(fontSize: 10, color: _text2, fontStyle: pw.FontStyle.italic),
                ),
              ),
            ],
          );
        },
      ),
    );

    return pdf;
  }

  /// Builds the measurement section widgets, handling male (top|bottom side-by-side)
  /// and female (blouse section | dress section, then bottom below).
  static List<pw.Widget> _buildMeasurementSections(Customer c, bool isMale) {
    final hasTop = c.measurementsTop?.isNotEmpty == true;
    final hasBottom = c.measurementsBottom?.isNotEmpty == true;

    if (isMale) {
      // Male: top and bottom side-by-side
      if (hasTop && hasBottom) {
        return [
          pw.Row(
            crossAxisAlignment: pw.CrossAxisAlignment.start,
            children: [
              pw.Expanded(child: _measSection('TOP MEASUREMENTS', c.measurementsTop!)),
              pw.SizedBox(width: 16),
              pw.Expanded(child: _measSection('BOTTOM MEASUREMENTS', c.measurementsBottom!)),
            ],
          ),
        ];
      } else if (hasTop) {
        return [_measSection('TOP MEASUREMENTS', c.measurementsTop!)];
      } else if (hasBottom) {
        return [_measSection('BOTTOM MEASUREMENTS', c.measurementsBottom!)];
      }
      return [];
    }

    // Female: split top into blouse and dress
    final blouseM = <String, dynamic>{};
    final dressM = <String, dynamic>{};
    if (hasTop) {
      c.measurementsTop!.forEach((k, v) {
        if (k.startsWith('blouse_')) blouseM[k.substring(7)] = v;
        else if (k.startsWith('dress_')) dressM[k.substring(6)] = v;
        else blouseM[k] = v; // legacy unprefixed → treat as blouse
      });
    }
    final hasBlouse = blouseM.isNotEmpty;
    final hasDress = dressM.isNotEmpty;
    final widgets = <pw.Widget>[];

    if (hasBlouse && hasDress) {
      // Blouse | Dress side by side
      widgets.add(pw.Row(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          pw.Expanded(child: _measSection('BLOUSE', blouseM)),
          pw.SizedBox(width: 16),
          pw.Expanded(child: _measSection('DRESS', dressM)),
        ],
      ));
      if (hasBottom) {
        widgets.add(pw.SizedBox(height: 12));
        widgets.add(_measSection('BOTTOM MEASUREMENTS', c.measurementsBottom!));
      }
    } else if (hasBlouse || hasDress) {
      // Only one tab has data — show it with bottom side by side
      final topLabel = hasBlouse ? 'BLOUSE MEASUREMENTS' : 'DRESS MEASUREMENTS';
      final topData = hasBlouse ? blouseM : dressM;
      if (hasBottom) {
        widgets.add(pw.Row(
          crossAxisAlignment: pw.CrossAxisAlignment.start,
          children: [
            pw.Expanded(child: _measSection(topLabel, topData)),
            pw.SizedBox(width: 16),
            pw.Expanded(child: _measSection('BOTTOM MEASUREMENTS', c.measurementsBottom!)),
          ],
        ));
      } else {
        widgets.add(_measSection(topLabel, topData));
      }
    } else if (hasBottom) {
      widgets.add(_measSection('BOTTOM MEASUREMENTS', c.measurementsBottom!));
    }

    return widgets;
  }

  static pw.Widget _measSection(String title, Map<String, dynamic> measurements) {
    final entries = measurements.entries.toList();
    return pw.Container(
      padding: const pw.EdgeInsets.all(12),
      decoration: pw.BoxDecoration(
        color: _surface,
        borderRadius: pw.BorderRadius.circular(8),
        border: pw.Border.all(color: _accent, width: 0.5),
      ),
      child: pw.Column(
        crossAxisAlignment: pw.CrossAxisAlignment.start,
        children: [
          pw.Container(
            margin: const pw.EdgeInsets.only(bottom: 10),
            padding: const pw.EdgeInsets.symmetric(horizontal: 8, vertical: 4),
            decoration: pw.BoxDecoration(
              color: _headerDark,
              borderRadius: pw.BorderRadius.circular(4),
            ),
            child: pw.Text(title,
                style: pw.TextStyle(fontSize: 11, fontWeight: pw.FontWeight.bold, color: _accent)),
          ),
          ...entries.map((e) => pw.Padding(
            padding: const pw.EdgeInsets.symmetric(vertical: 3),
            child: pw.Row(
              mainAxisAlignment: pw.MainAxisAlignment.spaceBetween,
              children: [
                pw.Text(e.key,
                    style: pw.TextStyle(fontSize: 12, color: _text2)),
                pw.Text('${e.value} in',
                    style: pw.TextStyle(fontSize: 12, fontWeight: pw.FontWeight.bold)),
              ],
            ),
          )),
        ],
      ),
    );
  }

  static pw.Widget _summaryRow(String label, String value, {bool isBold = false, PdfColor color = PdfColors.black}) {
    return pw.Padding(
      padding: const pw.EdgeInsets.symmetric(vertical: 2),
      child: pw.Row(
        mainAxisSize: pw.MainAxisSize.min,
        children: [
          pw.Text(label, style: pw.TextStyle(fontSize: 12, fontWeight: isBold ? pw.FontWeight.bold : pw.FontWeight.normal)),
          pw.SizedBox(width: 20),
          pw.SizedBox(
            width: 100,
            child: pw.Text(value,
                textAlign: pw.TextAlign.right,
                style: pw.TextStyle(fontSize: 12, fontWeight: isBold ? pw.FontWeight.bold : pw.FontWeight.normal, color: color)),
          ),
        ],
      ),
    );
  }
}
