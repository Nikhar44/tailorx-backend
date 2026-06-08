import 'dart:convert';
import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:url_launcher/url_launcher.dart';
import '../models/models.dart';
import '../services/api_service.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import '../utils/pdf_helper.dart';
import '../widgets/common_widgets.dart';
// PrivacyText is exported from common_widgets via privacy_helper import

double _n(dynamic v){if(v==null)return 0;if(v is num)return v.toDouble();if(v is String)return double.tryParse(v)??0;return 0;}

class InvoicesScreen extends StatefulWidget {
  const InvoicesScreen({super.key});
  @override State<InvoicesScreen> createState()=>InvoicesScreenState();
}

class InvoicesScreenState extends State<InvoicesScreen>{
  final _api=Api();final _lang=AppLang();
  List<Invoice> _list=[];bool _loading=true;String _filter='';String _search='';
  final _searchCtrl=TextEditingController();
  final _fmt=NumberFormat.currency(locale:'en_IN',symbol:'\u20B9',decimalDigits:0);

  @override void initState(){super.initState();_load();}

  Future<void> refresh() => _load();

  Future<void> _load() async {
    setState(()=>_loading=true);
    try{final inv=await _api.getInvoices(status:_filter.isNotEmpty?_filter:null);
      if(mounted){if(_search.isNotEmpty){final q=_search.toLowerCase();
        setState(()=>_list=inv.where((i)=>(i.customerName??'').toLowerCase().contains(q)||(i.garment??'').toLowerCase().contains(q)).toList());
      }else{setState(()=>_list=inv);}}}
    catch(e){if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('$e')));}
    finally{if(mounted)setState(()=>_loading=false);}
  }

  // Summary totals
  // Use advance+dueAmount as effective total — robust against old server leaving
  // totalAmount=0 or not updating advance/due_amount after a payment.
  double _effective(Invoice i) =>
      i.totalAmount > 0 ? i.totalAmount : (i.advance + i.dueAmount);

  double get _totalRev  => _list.fold(0, (s, i) => s + _effective(i));
  double get _totalPaid => _list.fold(0, (s, i) {
    if (i.status == 'paid') return s + _effective(i); // advance+due = full amount
    return s + i.advance;                             // partial or unpaid
  });
  double get _totalDue  => _list.fold(0, (s, i) {
    if (i.status == 'paid') return s;    // nothing owed on paid invoices
    return s + i.dueAmount;
  });

  void _viewBill(Invoice inv){
    final invNo='INV-${inv.id.toString().padLeft(4,'0')}';
    final date=inv.billDate!=null?DateFormat('dd MMM yyyy').format(DateTime.parse(inv.billDate!)):DateFormat('dd MMM yyyy').format(DateTime.now());
    showModalBottomSheet(context:context,isScrollControlled:true,backgroundColor:Colors.transparent,
      builder:(ctx)=>Container(height:MediaQuery.of(ctx).size.height*0.9,
        decoration:BoxDecoration(color:T.bg,borderRadius:const BorderRadius.vertical(top:Radius.circular(T.rXl))),
        child:Column(children:[
          const SizedBox(height:12),
          Container(width:36,height:4,decoration:BoxDecoration(color:T.border,borderRadius:BorderRadius.circular(2))),
          Padding(padding:const EdgeInsets.fromLTRB(20,12,20,0),child:Row(children:[
            Text('Bill Preview',style:T.displaySm),const Spacer(),
            if(inv.dueAmount>0) GestureDetector(onTap:(){Navigator.pop(ctx);_pay(inv);},
              child:Container(padding:const EdgeInsets.symmetric(horizontal:12,vertical:6),
                decoration:BoxDecoration(color:T.success.withOpacity(0.1),borderRadius:BorderRadius.circular(8)),
                child:Text('Pay',style:T.bodySm.copyWith(color:T.success,fontWeight:FontWeight.w600)))),
            const SizedBox(width:8),
            GestureDetector(onTap:(){Navigator.pop(ctx);_share(inv);},
              child:Container(padding:const EdgeInsets.symmetric(horizontal:12,vertical:6),
                decoration:BoxDecoration(color:T.info.withOpacity(0.1),borderRadius:BorderRadius.circular(8)),
                child:Text('Share',style:T.bodySm.copyWith(color:T.info,fontWeight:FontWeight.w600)))),])),
          const SizedBox(height:12),
          Expanded(child:SingleChildScrollView(padding:const EdgeInsets.fromLTRB(16,0,16,24),
            child:Container(padding:const EdgeInsets.all(24),
              decoration:BoxDecoration(color:T.card,borderRadius:BorderRadius.circular(T.rMd),boxShadow:T.shadowElev),
              child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                Row(crossAxisAlignment:CrossAxisAlignment.start,children:[
                  if (_api.boutiqueLogo != null)
                    Container(
                      width: 72, height: 72,
                      margin: const EdgeInsets.only(right: 14),
                      decoration: BoxDecoration(
                        borderRadius: BorderRadius.circular(8),
                        border: Border.all(color: T.border),
                      ),
                      clipBehavior: Clip.antiAlias,
                      child: Image.network(
                        _api.boutiqueLogo!,
                        fit: BoxFit.contain,
                        errorBuilder: (_, __, ___) => const Icon(Icons.broken_image_rounded, size: 28),
                      ),
                    ),
                  Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                    Text(_api.boutiqueName??'TailorX',style:T.heading.copyWith(fontSize:18, fontWeight: FontWeight.w800)),
                    if(_api.boutiqueAddress!=null)
                      Text(_api.boutiqueAddress!, style: T.bodySm, maxLines: 2, overflow: TextOverflow.ellipsis),
                    if(_api.boutiqueGST!=null)
                      Text('GSTIN: ${_api.boutiqueGST}', style: T.bodySm.copyWith(fontWeight: FontWeight.bold)),])),
                  Column(crossAxisAlignment:CrossAxisAlignment.end,children:[
                    Text('INVOICE',style:T.label.copyWith(fontSize:12,letterSpacing:3,color:T.accent)),
                    const SizedBox(height:2),
                    Text(invNo,style:T.bodySm.copyWith(fontWeight:FontWeight.w600)),]),]),
                const SizedBox(height:20),Container(height:1,color:T.border),const SizedBox(height:16),
                Row(crossAxisAlignment:CrossAxisAlignment.start,children:[
                  Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                    Text('BILL TO',style:T.label.copyWith(fontSize:9)),const SizedBox(height:4),
                    Text(inv.customerName??'Customer',style:T.body.copyWith(fontWeight:FontWeight.w600)),
                    if(inv.customerPhone?.isNotEmpty==true)Text(inv.customerPhone!,style:T.bodySm),])),
                  Column(crossAxisAlignment:CrossAxisAlignment.end,children:[
                    Text('DATE',style:T.label.copyWith(fontSize:9)),const SizedBox(height:4),
                    Text(date,style:T.body.copyWith(fontWeight:FontWeight.w500)),
                    const SizedBox(height:8),StatusBadge(status:inv.status,isInvoice:true),]),]),
                const SizedBox(height:20),
                Container(decoration:BoxDecoration(border:Border.all(color:T.border),borderRadius:BorderRadius.circular(8)),
                  child:Column(children:[
                    Container(padding:const EdgeInsets.symmetric(horizontal:12,vertical:10),
                      decoration:BoxDecoration(color:T.headerDark.withOpacity(0.05),
                        borderRadius:const BorderRadius.vertical(top:Radius.circular(7))),
                      child:Row(children:[Expanded(flex:3,child:Text('ITEM',style:T.label.copyWith(fontSize:9))),
                        Expanded(flex:2,child:Text('AMOUNT',style:T.label.copyWith(fontSize:9),textAlign:TextAlign.right)),])),
                    Container(height:1,color:T.border),
                    Padding(padding:const EdgeInsets.symmetric(horizontal:12,vertical:12),
                      child:Row(children:[Expanded(flex:3,child:Text(inv.garment??'Order #${inv.orderId}',style:T.body.copyWith(fontWeight:FontWeight.w500))),
                        Expanded(flex:2,child:Text(_fmt.format(inv.subtotal),style:T.body,textAlign:TextAlign.right)),])),])),
                const SizedBox(height:16),
                Container(padding:const EdgeInsets.all(16),
                  decoration:BoxDecoration(color:T.surface.withOpacity(0.5),borderRadius:BorderRadius.circular(8)),
                  child:Column(children:[
                    _BillRow('Subtotal',_fmt.format(inv.subtotal)),
                    if(inv.discountAmt>0)...[const SizedBox(height:6),
                      _BillRow('Discount${inv.discountPct>0?" (${inv.discountPct.toStringAsFixed(0)}%)":""}',
                        '- ${_fmt.format(inv.discountAmt)}',vc:T.success)],
                    const SizedBox(height:8),Container(height:1,color:T.border),const SizedBox(height:8),
                    _BillRow('Total',_fmt.format(inv.totalAmount),bold:true),
                    const SizedBox(height:6),_BillRow('Paid',_fmt.format(inv.advance),vc:T.success),
                    const SizedBox(height:8),Container(height:2,color:T.headerDark),const SizedBox(height:8),
                    Row(mainAxisAlignment:MainAxisAlignment.spaceBetween,children:[
                      Text('BALANCE DUE',style:T.label.copyWith(fontSize:11,fontWeight:FontWeight.w700,color:T.headerDark)),
                      Text(_fmt.format(inv.dueAmount),style:T.heading.copyWith(fontSize:18,
                        color:inv.dueAmount>0?T.danger:T.success)),]),])),
                if(inv.remarks?.isNotEmpty==true)...[const SizedBox(height:16),
                  Text('REMARKS',style:T.label.copyWith(fontSize:9)),const SizedBox(height:4),
                  Text(inv.remarks!,style:T.bodySm)],
                const SizedBox(height:24),Container(height:1,color:T.border),const SizedBox(height:12),
                Center(child:Text('Thank you for your business!',style:T.bodySm.copyWith(fontStyle:FontStyle.italic))),
                const SizedBox(height:4),
                Center(child:Text('${_api.boutiqueName??""} \u2022 Surat, Gujarat',style:T.bodySm.copyWith(fontSize:9))),
              ]))))])));
  }

  // Public entry-point called from HomeScreen when the user taps "Create Invoice"
  // from within the Orders tab (e.g. after marking an order Delivered).
  void createInvoiceForOrder(Order order) {
    // Give Flutter one frame to finish switching tabs before pushing the sheet.
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (mounted) _createInvoice(preselected: order);
    });
  }

  void _createInvoice({Order? preselected}) async {
    List<Order> orders=[];
    try{orders=await _api.getOrders();}catch(_){}
    if(orders.isEmpty&&mounted){ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content:Text('Create orders first')));return;}
    if(!mounted)return;
    Order? sel = preselected; final dpCtrl=TextEditingController(text:'0');
    final advCtrl=TextEditingController(text: preselected!=null&&preselected.advance>0 ? preselected.advance.toStringAsFixed(0) : '');
    final remCtrl=TextEditingController();
    final trialCtrl=TextEditingController();
    final fk=GlobalKey<FormState>();

    showModalBottomSheet(context:context,isScrollControlled:true,backgroundColor:Colors.transparent,
      builder:(ctx)=>StatefulBuilder(builder:(ctx,setSt){
        final sub=_n(sel?.amount);final dp=double.tryParse(dpCtrl.text)??0;final da=sub*dp/100;
        final tot=sub-da;final adv=double.tryParse(advCtrl.text)??_n(sel?.advance);final due=tot-adv;
        return Container(height:MediaQuery.of(ctx).size.height*0.88,
          decoration:BoxDecoration(color:T.bg,borderRadius:const BorderRadius.vertical(top:Radius.circular(T.rXl))),
          child:Column(children:[
            const SizedBox(height:12),Container(width:36,height:4,decoration:BoxDecoration(color:T.border,borderRadius:BorderRadius.circular(2))),
            Expanded(child:Form(key:fk,child:ListView(padding:const EdgeInsets.fromLTRB(20,20,20,30),children:[
              Text('Create Invoice',style:T.displayMd),const SizedBox(height:6),
              Text('Select an order to generate a bill',style:T.bodySm),const SizedBox(height:20),
              Text('SELECT ORDER',style:T.label),const SizedBox(height:6),
              if(sel!=null) Container(padding:const EdgeInsets.all(12),margin:const EdgeInsets.only(bottom:8),
                decoration:BoxDecoration(color:T.success.withOpacity(0.06),borderRadius:BorderRadius.circular(T.rMd),
                  border:Border.all(color:T.success.withOpacity(0.3))),
                child:Row(children:[
                  Container(width:3,height:32,color:T.stageColor(sel!.status),margin:const EdgeInsets.only(right:10)),
                  Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                    Text(sel!.customerName??'',style:T.body.copyWith(fontWeight:FontWeight.w600)),
                    Text('${sel!.description} (${_fmt.format(sel!.amount)})',style:T.bodySm),])),
                  GestureDetector(onTap:()=>setSt((){sel=null;advCtrl.clear();}),
                    child:const Icon(Icons.close_rounded,size:16,color:T.danger)),])),
              if(sel==null)
                Autocomplete<Order>(
                  optionsBuilder:(t){if(t.text.isEmpty)return orders;final q=t.text.toLowerCase();
                    return orders.where((o)=>(o.customerName??'').toLowerCase().contains(q)||(o.garment??'').toLowerCase().contains(q));},
                  displayStringForOption:(o)=>'${o.customerName??""} \u2014 ${o.description}',
                  fieldViewBuilder:(ctx,ctrl,focus,_)=>TextFormField(controller:ctrl,focusNode:focus,style:T.body,
                    decoration:InputDecoration(hintText:'Type customer or garment...',
                      prefixIcon:Icon(Icons.search_rounded,size:18,color:T.text3)),
                    validator:(_)=>sel==null?'Select an order':null),
                  optionsViewBuilder:(ctx,onSel,opts)=>Align(alignment:Alignment.topLeft,
                    child:Material(elevation:4,borderRadius:BorderRadius.circular(T.rMd),
                      child:Container(constraints:BoxConstraints(maxHeight:200,maxWidth:MediaQuery.of(ctx).size.width-48),
                        decoration:BoxDecoration(color:T.card,borderRadius:BorderRadius.circular(T.rMd)),
                        child:ListView.builder(padding:EdgeInsets.zero,shrinkWrap:true,itemCount:opts.length,
                          itemBuilder:(_,i){final o=opts.elementAt(i);
                            return InkWell(onTap:(){onSel(o);setSt((){sel=o;advCtrl.text=_n(o.advance).toStringAsFixed(0);});},
                              child:Padding(padding:const EdgeInsets.symmetric(horizontal:14,vertical:10),
                                child:Row(children:[
                                  Container(width:3,height:28,color:T.stageColor(o.status),margin:const EdgeInsets.only(right:10)),
                                  Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                                    Text(o.customerName??'',style:T.body.copyWith(fontWeight:FontWeight.w600,fontSize:12)),
                                    Text('${o.description} (${_fmt.format(o.amount)})',style:T.bodySm,maxLines:1,overflow:TextOverflow.ellipsis),]))])));}))))),
              if(sel!=null)...[const SizedBox(height:16),
                Container(padding:const EdgeInsets.all(16),
                  decoration:BoxDecoration(color:T.card,borderRadius:BorderRadius.circular(T.rMd),boxShadow:T.shadowCard,
                    border:Border.all(color:T.accent.withOpacity(0.2))),
                  child:Column(children:[
                    _BillRow('Subtotal',_fmt.format(sub)),const SizedBox(height:12),
                    Row(children:[Expanded(child:TxField(label:'Discount %',hint:'0',controller:dpCtrl,
                      keyboardType:TextInputType.number,onChanged:(_)=>setSt((){}))),
                      const SizedBox(width:12),
                      Column(crossAxisAlignment:CrossAxisAlignment.end,children:[
                        Text('DISCOUNT',style:T.label),const SizedBox(height:6),
                        Text('- ${_fmt.format(da)}',style:T.body.copyWith(color:T.success)),]),]),
                    const SizedBox(height:12),Container(height:1,color:T.border),const SizedBox(height:12),
                    _BillRow('Total',_fmt.format(tot),bold:true),const SizedBox(height:12),
                    TxField(label:'Advance Received',hint:'0',controller:advCtrl,
                      keyboardType:TextInputType.number,onChanged:(_)=>setSt((){})),
                    const SizedBox(height:12),
                    Container(padding:const EdgeInsets.all(12),
                      decoration:BoxDecoration(color:due>0?T.danger.withOpacity(0.06):T.success.withOpacity(0.06),
                        borderRadius:BorderRadius.circular(8)),
                      child:Row(mainAxisAlignment:MainAxisAlignment.spaceBetween,children:[
                        Text('BALANCE DUE',style:T.label.copyWith(fontWeight:FontWeight.w700)),
                        Text(_fmt.format(due),style:T.heading.copyWith(color:due>0?T.danger:T.success)),])),])),
                const SizedBox(height:14),
                TxField(label:'Trial Date (optional)',hint:'dd/mm/yyyy',controller:trialCtrl),
                const SizedBox(height:10),
                TxField(label:'Remarks',hint:'Notes...',controller:remCtrl,maxLines:2),
                const SizedBox(height:24),
                Container(height:52,decoration:BoxDecoration(gradient:T.headerGrad,borderRadius:BorderRadius.circular(T.rMd),
                  boxShadow:[BoxShadow(color:T.headerDark.withOpacity(0.3),blurRadius:16,offset:const Offset(0,6))]),
                  child:Material(color:Colors.transparent,child:InkWell(
                    onTap:()async{if(!fk.currentState!.validate())return;
                      final inv=Invoice(orderId:sel!.id,customerId:sel!.customerId,
                        customerName:sel!.customerName,customerPhone:sel!.customerPhone,
                        customerCity:sel!.city,customerAddress:sel!.address,
                        garment:sel!.garment,subtotal:sub,discountPct:dp,discountAmt:da,
                        trialDate:trialCtrl.text.trim().isEmpty?null:trialCtrl.text.trim(),
                        deliveryDate:sel!.dueDate,
                        advance:adv,dueAmount:due>0?due:0,remarks:remCtrl.text.trim());
                      try{await _api.createInvoice(inv);if(ctx.mounted)Navigator.pop(ctx);
                        if(mounted)ScaffoldMessenger.of(context).showSnackBar(const SnackBar(content:Text('Invoice created')));
                      }catch(e){if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('$e')));
                      }finally{_load();}},
                    borderRadius:BorderRadius.circular(T.rMd),
                    child:Center(child:Text('CREATE INVOICE',style:T.btn.copyWith(color:T.accent,letterSpacing:1.5)))))),
              ],])))]));}));
  }

  void _pay(Invoice inv){
    final ac=TextEditingController(text:inv.dueAmount.toStringAsFixed(0));final fk=GlobalKey<FormState>();
    showModalBottomSheet(context:context,isScrollControlled:true,backgroundColor:Colors.transparent,
      builder:(ctx)=>Container(decoration:BoxDecoration(color:T.bg,borderRadius:const BorderRadius.vertical(top:Radius.circular(T.rXl))),
        child:Padding(padding:EdgeInsets.only(bottom:MediaQuery.of(ctx).viewInsets.bottom,left:20,right:20,top:24),
          child:Form(key:fk,child:Column(mainAxisSize:MainAxisSize.min,crossAxisAlignment:CrossAxisAlignment.stretch,children:[
            Center(child:Container(width:36,height:4,decoration:BoxDecoration(color:T.border,borderRadius:BorderRadius.circular(2)))),
            const SizedBox(height:16),Text(_lang.t('record_payment'),style:T.displaySm),
            const SizedBox(height:14),
            Container(padding:const EdgeInsets.all(14),decoration:BoxDecoration(color:T.card,borderRadius:BorderRadius.circular(T.rMd),boxShadow:T.shadowCard),
              child:Row(mainAxisAlignment:MainAxisAlignment.spaceBetween,children:[
                _Mini('Total',_fmt.format(inv.totalAmount)),_Mini('Paid',_fmt.format(inv.advance),c:T.success),
                _Mini('Due',_fmt.format(inv.dueAmount),c:T.danger),])),
            const SizedBox(height:16),
            TxField(label:_lang.t('payment_amount'),hint:'0',controller:ac,keyboardType:TextInputType.number,
              validator:(v){if(v==null||v.trim().isEmpty)return'Required';if((double.tryParse(v)??0)<=0)return'Invalid';return null;}),
            const SizedBox(height:24),
            Container(height:52,decoration:BoxDecoration(gradient:T.headerGrad,borderRadius:BorderRadius.circular(T.rMd)),
              child:Material(color:Colors.transparent,child:InkWell(
                onTap:()async{if(!fk.currentState!.validate())return;final a=double.parse(ac.text.trim());
                  try{
                    final newAdv=inv.advance+a;
                    await _api.updateInvoicePayment(inv.id!,inv,newAdv);
                    if(ctx.mounted)Navigator.pop(ctx);
                    _load();
                    if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('Payment of ${_fmt.format(a)} recorded')));
                    // ── Auto WhatsApp when fully paid ──────────────────────
                    final fullyPaid = inv.totalAmount > 0 && newAdv >= inv.totalAmount;
                    if(fullyPaid && inv.customerPhone?.isNotEmpty==true){
                      final raw=inv.customerPhone!.replaceAll(RegExp(r'[^0-9]'),'');
                      final phone=raw.length==10?'91$raw':raw;
                      final boutique=_api.boutiqueName??'TailorX';
                      final invNo='INV-${inv.id.toString().padLeft(4,"0")}';
                      final msg='Dear ${inv.customerName??'Customer'},\n\n'
                        'Your payment of ${_fmt.format(a)} has been received. '
                        'Bill $invNo of ${_fmt.format(inv.totalAmount)} '
                        'for *${inv.garment??'your order'}* is now *fully paid*. '
                        '✅ Thank you for your business!\n\n'
                        '— $boutique';
                      await launchUrl(
                        Uri.parse('https://wa.me/$phone?text=${Uri.encodeComponent(msg)}'),
                        mode:LaunchMode.externalApplication);
                    }
                  }catch(e){if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('$e')));}},
                borderRadius:BorderRadius.circular(T.rMd),
                child:Center(child:Text(_lang.t('record_payment').toUpperCase(),style:T.btn.copyWith(color:T.accent)))))),
            const SizedBox(height:20),])))));
  }

  void _share(Invoice inv){
    final msg='${_api.boutiqueName??""} - INV-${inv.id.toString().padLeft(4,"0")}\n\n'
      'Customer: ${inv.customerName}\nItem: ${inv.garment??""}\n'
      'Total: ${_fmt.format(inv.totalAmount)}\nPaid: ${_fmt.format(inv.advance)}\n'
      'Balance: ${_fmt.format(inv.dueAmount)}\n\nThank you!';
    showModalBottomSheet(context:context,backgroundColor:Colors.transparent,
      builder:(ctx)=>Container(decoration:BoxDecoration(color:T.bg,borderRadius:const BorderRadius.vertical(top:Radius.circular(T.rXl))),
        child:Padding(padding:const EdgeInsets.all(24),child:Column(mainAxisSize:MainAxisSize.min,children:[
          Text(_lang.t('share_bill'),style:T.displaySm),const SizedBox(height:24),
          Row(mainAxisAlignment:MainAxisAlignment.spaceEvenly,children:[
            _SBtn(Icons.chat_rounded,'WhatsApp',const Color(0xFF25D366),(){Navigator.pop(ctx);
              launchUrl(Uri.parse('https://wa.me/91${inv.customerPhone??""} ?text=${Uri.encodeComponent(msg)}'),mode:LaunchMode.externalApplication);}),
            _SBtn(Icons.sms_rounded,'SMS',T.info,(){Navigator.pop(ctx);
              launchUrl(Uri.parse('sms:${inv.customerPhone??""}?body=${Uri.encodeComponent(msg)}'));}),
            _SBtn(Icons.email_rounded,'Email',T.purple,(){Navigator.pop(ctx);
              launchUrl(Uri.parse('mailto:?subject=Invoice&body=${Uri.encodeComponent(msg)}'));}),
            _SBtn(Icons.picture_as_pdf_rounded,'PDF',T.danger,(){Navigator.pop(ctx);
              PdfHelper.generateAndShareInvoice(inv,
                boutiqueName: _api.boutiqueName,
                boutiqueAddress: _api.boutiqueAddress,
                boutiquePhone: _api.boutiquePhone,
                boutiqueGST: _api.boutiqueGST,
                boutiqueLogo: _api.boutiqueLogo,
                termsAndConditions: _api.termsAndConditions);
            }),
          ]),const SizedBox(height:20),]))));
  }

  void _downloadPdf(Invoice inv){
    final invNo='INV-${inv.id.toString().padLeft(4,"0")}';
    final date=DateFormat('dd MMM yyyy').format(DateTime.now());
    final bn=_api.boutiqueName??'TailorX';
    final html='<!DOCTYPE html><html><head><meta charset="UTF-8"><title>$invNo</title>'
      '<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:Segoe UI,Arial,sans-serif;color:#1a1a2e;padding:40px}'
      '.inv{max-width:600px;margin:0 auto;border:1px solid #e8e5df;padding:40px}'
      '.hdr{display:flex;justify-content:space-between;padding-bottom:16px;border-bottom:2px solid #1a1a2e;margin-bottom:24px}'
      '.logo{font-size:24px;font-weight:700;color:#d4a574;letter-spacing:3px}'
      '.invt{font-size:20px;letter-spacing:4px;color:#d4a574;font-weight:300}'
      'table{width:100%;border-collapse:collapse;margin:20px 0}th{background:#f8f7f4;padding:10px;text-align:left;font-size:10px;letter-spacing:1.5px;border-bottom:1px solid #e8e5df}'
      'td{padding:12px;font-size:13px;border-bottom:1px solid #f1f0ed}'
      '.totals{background:#f8f7f4;padding:16px;margin:16px 0}.row{display:flex;justify-content:space-between;padding:4px 0;font-size:13px}'
      '.row.bold{font-weight:700;font-size:15px}.row.due{font-size:18px;font-weight:700;color:#cf4747;border-top:2px solid #1a1a2e;padding-top:12px;margin-top:8px}'
      '.footer{text-align:center;margin-top:24px;padding-top:16px;border-top:1px solid #e8e5df;font-size:11px;color:#9e9ea8;font-style:italic}'
      '@media print{body{padding:0}.inv{border:none}button{display:none!important}}</style></head><body>'
      '<div class="inv"><div class="hdr"><div>'
      '${_api.boutiqueLogo!=null?"<img src=\""+_api.boutiqueLogo!+"\" style=\"height:50px;margin-bottom:8px\">":""}'
      '<div class="logo">' + (bn.toUpperCase()) + '</div><div style="font-size:12px;font-weight:600;margin-top:4px">Premium Bespoke Tailoring</div></div>'
      '<div style="text-align:right"><div class="invt">INVOICE</div><div style="font-size:12px;color:#6b6b7b;margin-top:4px">$invNo</div></div></div>'
      '<div style="display:flex;justify-content:space-between;margin:20px 0"><div><div style="font-size:9px;letter-spacing:2px;color:#9e9ea8">BILL TO</div>'
      '<div style="font-size:13px;font-weight:500;margin-top:4px">${inv.customerName??""}</div>'
      '${inv.customerPhone?.isNotEmpty==true?"<div style=\"font-size:11px;color:#6b6b7b\">${inv.customerPhone}</div>":""}</div>'
      '<div style="text-align:right"><div style="font-size:9px;letter-spacing:2px;color:#9e9ea8">DATE</div>'
      '<div style="font-size:13px;font-weight:500;margin-top:4px">$date</div></div></div>'
      '<table><tr><th>Item</th><th style="text-align:right">Amount</th></tr>'
      '<tr><td>${inv.garment??""}</td><td style="text-align:right">${_fmt.format(inv.subtotal)}</td></tr></table>'
      '<div class="totals"><div class="row"><span>Subtotal</span><span>${_fmt.format(inv.subtotal)}</span></div>'
      '${inv.discountAmt>0?"<div class=\"row\" style=\"color:#2d8f6f\"><span>Discount</span><span>- ${_fmt.format(inv.discountAmt)}</span></div>":""}'
      '<div class="row bold"><span>Total</span><span>${_fmt.format(inv.totalAmount)}</span></div>'
      '<div class="row" style="color:#2d8f6f"><span>Paid</span><span>${_fmt.format(inv.advance)}</span></div>'
      '<div class="row due"><span>Balance Due</span><span>${_fmt.format(inv.dueAmount)}</span></div></div>'
      '<div class="footer">Thank you for your business!<br>$bn \u2022 Surat, Gujarat</div></div>'
      '<div style="text-align:center;margin-top:20px"><button onclick="window.print()" '
      'style="padding:12px 32px;background:#1a1a2e;color:#d4a574;border:none;cursor:pointer;font-size:13px;letter-spacing:2px">PRINT / SAVE AS PDF</button></div></body></html>';
    launchUrl(Uri.dataFromString(html,mimeType:'text/html',encoding:utf8),mode:LaunchMode.externalApplication);
  }

  @override
  Widget build(BuildContext context){
    return Scaffold(backgroundColor:T.bg,body:Column(children:[
      // Summary card (matching .summary-card)
      if(_list.isNotEmpty) Padding(padding:const EdgeInsets.fromLTRB(18,12,18,8),
        child:Container(padding:const EdgeInsets.all(16),
          decoration:BoxDecoration(gradient:const LinearGradient(colors:[Color(0xFF1C1C1C),Color(0xFF2A2A3A)]),
            borderRadius:BorderRadius.circular(T.rMd)),
          child:Column(children:[
            Row(children:[Text('TOTAL REVENUE',style:TextStyle(fontSize:12,letterSpacing:2,fontWeight:FontWeight.w600,
              color:Colors.white.withOpacity(0.4))),const Spacer(),
              PrivacyText(_fmt.format(_totalRev),style:GoogleFonts.prata(fontSize:36,fontWeight:FontWeight.w400,color:T.accent))]),
            Text('${_list.length} invoices',style:TextStyle(fontSize:12,color:Colors.white.withOpacity(0.5))),
            const SizedBox(height:14),
            Container(height:1,color:Colors.white.withOpacity(0.08)),
            const SizedBox(height:14),
            Row(children:[
              Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                PrivacyText(_fmt.format(_totalPaid),style:GoogleFonts.prata(fontSize:22,fontWeight:FontWeight.w400,color:const Color(0xFF5EC09A))),
                Text('COLLECTED',style:TextStyle(fontSize:10,letterSpacing:1.4,fontWeight:FontWeight.w600,color:Colors.white.withOpacity(0.4))),])),
              Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                PrivacyText(_fmt.format(_totalDue),style:GoogleFonts.prata(fontSize:22,fontWeight:FontWeight.w400,color:const Color(0xFFF0B85A))),
                Text('PENDING',style:TextStyle(fontSize:10,letterSpacing:1.4,fontWeight:FontWeight.w600,color:Colors.white.withOpacity(0.4))),])),]),]))),
      // Search
      Padding(padding:const EdgeInsets.fromLTRB(18,4,18,4),
        child:Container(decoration:BoxDecoration(color:T.card,borderRadius:BorderRadius.circular(12),boxShadow:T.shadowCard),
          child:TextField(controller:_searchCtrl,style:T.body.copyWith(fontSize:18),
            decoration:InputDecoration(hintText:'Search invoices...',
              prefixIcon:Icon(Icons.search_rounded,size:20,color:T.text3),
              suffixIcon:_search.isNotEmpty?IconButton(icon:const Icon(Icons.close_rounded,size:20),
                onPressed:(){_searchCtrl.clear();setState(()=>_search='');_load();}):null,
              border:InputBorder.none,filled:false,contentPadding:const EdgeInsets.symmetric(horizontal:12,vertical:10)),
            onChanged:(v){setState(()=>_search=v);_load();}))),
      // Filter pills
      SizedBox(height:50,child:ListView(scrollDirection:Axis.horizontal,
        padding:const EdgeInsets.symmetric(horizontal:18,vertical:6),
        children:[_pill('All',''),_pill('Unpaid','unpaid'),_pill('Partial','partial'),_pill('Paid','paid')])),
      // Invoice list (matching .inv rows)
      Expanded(child:_loading
        ?const Center(child:CircularProgressIndicator(strokeWidth:1.5,color:T.accent))
        :_list.isEmpty
          ?EmptyState(icon:Icons.payments_outlined,title:_lang.t('no_invoices'),
            subtitle:'Create invoices from your orders',buttonLabel:'CREATE INVOICE',onPressed:()=>_createInvoice())
          :RefreshIndicator(onRefresh:_load,color:T.accent,
            child:ListView.builder(padding:const EdgeInsets.fromLTRB(18,4,18,80),itemCount:_list.length,
              itemBuilder:(_,i){final inv=_list[i];final sc=T.invColor(inv.status);
                return Padding(padding:const EdgeInsets.only(bottom:6),
                  child:Material(color:T.card,borderRadius:BorderRadius.circular(12),
                    child:InkWell(onTap:()=>_viewBill(inv),borderRadius:BorderRadius.circular(12),
                      child:Padding(padding:const EdgeInsets.symmetric(horizontal:12,vertical:11),
                        child:Row(children:[
                          // Status icon (matching .inv-status)
                          Container(width:40,height:40,decoration:BoxDecoration(
                            color:sc.withOpacity(0.12),borderRadius:BorderRadius.circular(10)),
                            child:Center(child:Text(
                              inv.status=='paid'?'✓':inv.status=='partial'?'◐':'!',
                              style:TextStyle(fontSize:18,fontWeight:FontWeight.w800,color:sc)))),
                          const SizedBox(width:12),
                          Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                            Text(inv.customerName??'Unknown',style:T.body.copyWith(fontSize:18,fontWeight:FontWeight.w700)),
                            Text(inv.garment??'Invoice #${inv.id}',style:T.bodySm.copyWith(fontSize:14, fontWeight: FontWeight.w500)),])),
                          Column(crossAxisAlignment:CrossAxisAlignment.end,children:[
                            Text(_fmt.format(inv.totalAmount),style:GoogleFonts.prata(
                              fontSize:20,fontWeight:FontWeight.w400,color:T.text)),
                            const SizedBox(height:3),
                            if(inv.status=='paid' || inv.dueAmount<=0)
                              const Text('Paid',style:TextStyle(fontSize:12,fontWeight:FontWeight.w700,color:T.success))
                            else
                              Text('Due ${_fmt.format(inv.dueAmount)}',style:const TextStyle(
                                fontSize:12,fontWeight:FontWeight.w700,color:T.danger)),]),
                        ])))));}))),
    ]),
    floatingActionButton:FloatingActionButton(onPressed:()=>_createInvoice(),child:const Icon(Icons.add_rounded,size:22)));
  }

  Widget _pill(String l,String v){final sel=_filter==v;
    return Padding(padding:const EdgeInsets.only(right:8),
      child:GestureDetector(onTap:(){setState(()=>_filter=v);_load();},
        child:Container(padding:const EdgeInsets.symmetric(horizontal:16,vertical:8),
          decoration:BoxDecoration(color:sel?T.headerDark:T.surface,borderRadius:BorderRadius.circular(8)),
          child:Center(child: Text(l,style:TextStyle(fontSize:12,fontWeight:FontWeight.w800,letterSpacing:0.5,color:sel?Colors.white:T.text2))))));}
}

class _BillRow extends StatelessWidget{
  final String l,v;final bool bold;final Color? vc;
  const _BillRow(this.l,this.v,{this.bold=false,this.vc});
  @override Widget build(BuildContext c)=>Row(mainAxisAlignment:MainAxisAlignment.spaceBetween,children:[
    Text(l,style:bold?T.body.copyWith(fontWeight:FontWeight.w700):T.bodySm),
    Text(v,style:(bold?T.body.copyWith(fontWeight:FontWeight.w700):T.bodySm).copyWith(color:vc)),]);}

class _Mini extends StatelessWidget{
  final String l,v;final Color? c;const _Mini(this.l,this.v,{this.c});
  @override Widget build(BuildContext ctx)=>Column(children:[
    Text(l.toUpperCase(),style:T.label.copyWith(fontSize:10)),const SizedBox(height:2),
    Text(v,style:T.bodySm.copyWith(fontSize: 16, fontWeight:FontWeight.w700,color:c??T.text)),]);}

class _SBtn extends StatelessWidget{
  final IconData ic;final String l;final Color c;final VoidCallback onTap;
  const _SBtn(this.ic,this.l,this.c,this.onTap);
  @override Widget build(BuildContext ctx)=>GestureDetector(onTap:onTap,child:Column(children:[
    Container(width:56,height:56,decoration:BoxDecoration(color:c.withOpacity(0.1),borderRadius:BorderRadius.circular(16)),
      child:Icon(ic,color:c,size:24)),const SizedBox(height:6),
    Text(l,style:T.bodySm.copyWith(fontSize:10)),]));}
