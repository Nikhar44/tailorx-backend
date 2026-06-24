import 'package:flutter/material.dart';
import 'package:google_fonts/google_fonts.dart';
import 'package:intl/intl.dart';
import 'package:image_picker/image_picker.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import '../models/models.dart';
import '../services/api_service.dart';
import '../utils/constants.dart';
import '../utils/pdf_helper.dart';
import '../utils/theme.dart';
import '../utils/lang.dart';
import '../widgets/common_widgets.dart';

double _n(dynamic v) { if (v==null) return 0; if (v is num) return v.toDouble(); if (v is String) return double.tryParse(v)??0; return 0; }

class OrdersScreen extends StatefulWidget {
  final Customer? initialCustomer;
  final VoidCallback? onHandled;
  final ValueNotifier<int>? refreshNotifier;
  final Function(Order)? onCreateInvoice;
  const OrdersScreen({super.key, this.initialCustomer, this.onHandled, this.refreshNotifier, this.onCreateInvoice});
  @override
  State<OrdersScreen> createState() => OrdersScreenState();
}

class OrdersScreenState extends State<OrdersScreen> {
  final _api = Api(); final _lang = AppLang();
  List<Order> _list = []; List<Customer> _custs = [];
  bool _loading = true; String _filter = ''; String _search = '';
  final _searchCtrl = TextEditingController();
  final _fmt = NumberFormat.currency(locale:'en_IN',symbol:'₹',decimalDigits:0);

  @override void initState() {
    super.initState();
    _load();
    widget.refreshNotifier?.addListener(refresh);
    WidgetsBinding.instance.addPostFrameCallback((_) {
      if (widget.initialCustomer != null) {
        _newOrder(customer: widget.initialCustomer);
        widget.onHandled?.call();
      }
    });
  }

  @override
  void dispose() {
    widget.refreshNotifier?.removeListener(refresh);
    _searchCtrl.dispose();
    super.dispose();
  }

  Future<void> refresh() => _load();

  @override
  void didUpdateWidget(OrdersScreen oldWidget) {
    super.didUpdateWidget(oldWidget);
    if (widget.initialCustomer != null && widget.initialCustomer != oldWidget.initialCustomer) {
      _newOrder(customer: widget.initialCustomer);
      widget.onHandled?.call();
    }
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final o = await _api.getOrders(status: _filter.isNotEmpty ? _filter : null);
      if (mounted) {
        if (_search.isNotEmpty) {
          final q = _search.toLowerCase();
          setState(() => _list = o.where((o) =>
            (o.customerName??'').toLowerCase().contains(q) ||
            (o.garment??'').toLowerCase().contains(q)).toList());
        } else { setState(() => _list = o); }
      }
    } catch (e) { if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e'))); }
    finally { if (mounted) setState(() => _loading = false); }
  }

  LinearGradient _ag(int i) {
    final g = [
      const [Color(0xFFE8C49A),Color(0xFFD4A574)], const [Color(0xFF7C5CBF),Color(0xFF5C3FA3)],
      const [Color(0xFF4A7FC1),Color(0xFF2D5A94)], const [Color(0xFF2BA5A5),Color(0xFF1F7878)],
      const [Color(0xFF2D8F6F),Color(0xFF1F6650)],
    ];
    return LinearGradient(begin:Alignment.topLeft,end:Alignment.bottomRight,colors:g[i%g.length]);
  }

  // ─── ORDER PHOTOS (cloth/material + design reference) ───────────────────────
  Future<String?> _uploadOrderPhoto(ImageSource source) async {
    try {
      final file = await ImagePicker().pickImage(source: source, imageQuality: 70, maxWidth: 1024);
      if (file == null) return null;
      final bytes = await file.readAsBytes();
      final mime = (file.mimeType ?? 'image/jpeg').toLowerCase();
      final ext = mime.contains('png') ? 'png' : (mime.contains('webp') ? 'webp' : 'jpg');
      final fileName = 'order_${DateTime.now().millisecondsSinceEpoch}.$ext';
      final storage = Supabase.instance.client.storage.from('order-photos');
      await storage.uploadBinary(fileName, bytes, fileOptions: FileOptions(contentType: mime, upsert: true));
      final url = storage.getPublicUrl(fileName);
      return url;
    } catch (e) {
      if (mounted) {
        showDialog(context: context, builder: (_) => AlertDialog(
          title: const Text('Photo Upload Failed'),
          content: Text('$e'),
          actions: [TextButton(onPressed: () => Navigator.pop(context), child: const Text('OK'))],
        ));
      }
      return null;
    }
  }

  void _showPhotoSourceOptions(BuildContext ctx, String title, void Function(ImageSource) onPick) {
    showModalBottomSheet(
      context: ctx, backgroundColor: Colors.transparent, useSafeArea: true, isScrollControlled: true,
      useRootNavigator: true,
      builder: (sheetCtx) {
        final bottomPad = MediaQuery.of(sheetCtx).padding.bottom;
        return T.sheetWrap(sheetCtx, Container(
          decoration: BoxDecoration(color: T.bg, borderRadius: const BorderRadius.vertical(top: Radius.circular(T.rXl))),
          padding: EdgeInsets.fromLTRB(20, 20, 20, 20 + bottomPad),
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Container(width: 36, height: 4, decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2))),
            const SizedBox(height: 16),
            Text(title, style: T.displaySm),
            const SizedBox(height: 16),
            _PhotoOption(
              icon: Icons.photo_library_rounded, color: T.info,
              label: 'Choose from Gallery',
              onTap: () { Navigator.pop(sheetCtx); onPick(ImageSource.gallery); }),
            const SizedBox(height: 10),
            _PhotoOption(
              icon: Icons.camera_alt_rounded, color: T.success,
              label: 'Take a Photo',
              onTap: () { Navigator.pop(sheetCtx); onPick(ImageSource.camera); }),
          ]),
        ));
      },
    );
  }

  // Full-screen photo viewer (used from the order detail view)
  void _showFullPhoto(String url, String title) {
    showDialog(
      context: context,
      barrierColor: Colors.black.withOpacity(0.92),
      builder: (ctx) => Dialog(
        backgroundColor: Colors.transparent,
        insetPadding: const EdgeInsets.all(16),
        child: Stack(children: [
          ClipRRect(
            borderRadius: BorderRadius.circular(T.rMd),
            child: InteractiveViewer(
              maxScale: 4,
              child: Image.network(url, fit: BoxFit.contain,
                errorBuilder: (_, __, ___) => Container(
                  height: 200, color: T.surface,
                  child: Icon(Icons.broken_image_rounded, color: T.text3, size: 40))))),
          Positioned(top: 8, right: 8,
            child: GestureDetector(
              onTap: () => Navigator.pop(ctx),
              child: Container(
                padding: const EdgeInsets.all(6),
                decoration: BoxDecoration(color: Colors.black.withOpacity(0.5), shape: BoxShape.circle),
                child: const Icon(Icons.close_rounded, color: Colors.white, size: 20)))),
          Positioned(bottom: 12, left: 0, right: 0,
            child: Center(child: Container(
              padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
              decoration: BoxDecoration(color: Colors.black.withOpacity(0.5), borderRadius: BorderRadius.circular(8)),
              child: Text(title, style: const TextStyle(color: Colors.white, fontSize: 13, fontWeight: FontWeight.w600))))),
        ]),
      ),
    );
  }

  // Builds Garment/Fabric (+ optional reference photos) detail sections.
  // If the order has per-item data (items list), renders one block per item;
  // otherwise falls back to the legacy single garment/fabric/photo fields.
  List<Widget> _itemsDetailWidgets(Order o) {
    if (o.items.isNotEmpty) {
      final widgets = <Widget>[];
      for (var i = 0; i < o.items.length; i++) {
        final it = o.items[i];
        if (i > 0) widgets.add(const SizedBox(height: 10));
        widgets.add(_DetailSection(
          title: o.items.length > 1 ? 'Item ${i + 1}' : 'Garment',
          child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
            Text(it.garment?.isNotEmpty == true ? it.garment! : '—',
              style: T.body.copyWith(fontSize: 17, fontWeight: FontWeight.w500)),
            if (it.fabric?.isNotEmpty == true) ...[
              const SizedBox(height: 4),
              Text(it.fabric!, style: T.body.copyWith(fontSize: 15, color: T.text2)),
            ],
            if ((it.clothPhotoUrl?.isNotEmpty == true) || (it.designPhotoUrl?.isNotEmpty == true)) ...[
              const SizedBox(height: 10),
              Row(children: [
                if (it.clothPhotoUrl?.isNotEmpty == true)
                  Expanded(child: _DetailPhotoThumb(
                    label: 'Cloth / Material', url: it.clothPhotoUrl!,
                    onTap: () => _showFullPhoto(it.clothPhotoUrl!, 'Cloth / Material Photo'))),
                if (it.clothPhotoUrl?.isNotEmpty == true && it.designPhotoUrl?.isNotEmpty == true)
                  const SizedBox(width: 12),
                if (it.designPhotoUrl?.isNotEmpty == true)
                  Expanded(child: _DetailPhotoThumb(
                    label: 'Design', url: it.designPhotoUrl!,
                    onTap: () => _showFullPhoto(it.designPhotoUrl!, 'Design Photo'))),
              ]),
            ],
          ]),
        ));
      }
      return widgets;
    }

    // Legacy fallback (orders created before per-item photos)
    return [
      _DetailSection(title: 'Garment', child:
        Text(o.garment?.isNotEmpty == true ? o.garment! : '—',
          style: T.body.copyWith(fontSize: 17, fontWeight: FontWeight.w500))),
      if (o.fabric?.isNotEmpty == true) ...[
        const SizedBox(height: 10),
        _DetailSection(title: 'Fabric', child: Text(o.fabric!, style: T.body.copyWith(fontSize: 16))),
      ],
      if ((o.clothPhotoUrl?.isNotEmpty == true) || (o.designPhotoUrl?.isNotEmpty == true)) ...[
        const SizedBox(height: 10),
        _DetailSection(title: 'Reference Photos', child:
          Row(children: [
            if (o.clothPhotoUrl?.isNotEmpty == true)
              Expanded(child: _DetailPhotoThumb(
                label: 'Cloth / Material', url: o.clothPhotoUrl!,
                onTap: () => _showFullPhoto(o.clothPhotoUrl!, 'Cloth / Material Photo'))),
            if (o.clothPhotoUrl?.isNotEmpty == true && o.designPhotoUrl?.isNotEmpty == true)
              const SizedBox(width: 12),
            if (o.designPhotoUrl?.isNotEmpty == true)
              Expanded(child: _DetailPhotoThumb(
                label: 'Design', url: o.designPhotoUrl!,
                onTap: () => _showFullPhoto(o.designPhotoUrl!, 'Design Photo'))),
          ])),
      ],
    ];
  }

  // ─── NEW ORDER ──────────────────────────────────────────────────────────────
  void _newOrder({Customer? customer}) async {
    try { _custs = await _api.getCustomers(); } catch (_) {}
    if (_custs.isEmpty && mounted) {
      ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text(_lang.t('add_customers_first')))); return; }
    if (!mounted) return;

    Customer? sel = customer;
    Map<String,dynamic> mkItem() => {
      '_key': UniqueKey(),
      'garment': null,
      'fabricCtrl': TextEditingController(),
      'qtyCtrl': TextEditingController(text:'1'),
      'priceCtrl': TextEditingController(),
      'clothPhotoUrl': null,
      'designPhotoUrl': null,
      'uploadingCloth': false,
      'uploadingDesign': false,
    };
    final items = <Map<String,dynamic>>[mkItem()];
    final notesCtrl = TextEditingController();
    final advCtrl = TextEditingController();
    DateTime? dueDate; DateTime? trialDate; final fk = GlobalKey<FormState>();

    showModalBottomSheet(context:context,isScrollControlled:true,backgroundColor:Colors.transparent,
      builder:(ctx) => StatefulBuilder(builder:(ctx,setSt) {
        return T.sheetScaffold(ctx,heightFraction:0.93,child:Column(children:[
            const SizedBox(height:12),
            Container(width:36,height:4,decoration:BoxDecoration(color:T.border,borderRadius:BorderRadius.circular(2))),
            Expanded(child:Form(key:fk,child:ListView(padding:EdgeInsets.fromLTRB(20,20,20,30+MediaQuery.of(ctx).viewInsets.bottom),children:[
              Text(_lang.t('create_order'),style:T.displayMd),
              const SizedBox(height:20),
              Text(_lang.t('customer').toUpperCase(),style:T.label),
              const SizedBox(height:6),
              if (sel != null)
                Container(padding:const EdgeInsets.all(12),margin:const EdgeInsets.only(bottom:8),
                  decoration:BoxDecoration(color:T.success.withOpacity(0.06),borderRadius:BorderRadius.circular(T.rMd),
                    border:Border.all(color:T.success.withOpacity(0.3))),
                  child:Row(children:[
                    Container(width:44,height:44,decoration:BoxDecoration(gradient:T.accentGrad,borderRadius:BorderRadius.circular(8)),
                      child:Center(child:Text(sel!.initials,style:const TextStyle(fontSize:16,fontWeight:FontWeight.w700,color:T.headerDark)))),
                    const SizedBox(width:10),
                    Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                      Text(sel!.name,style:T.body.copyWith(fontWeight:FontWeight.w600,fontSize:18)),
                      Text(sel!.phone,style:T.bodySm.copyWith(fontSize:16)),])),
                    GestureDetector(onTap:()=>setSt(()=>sel=null),
                      child:const Icon(Icons.close_rounded,size:20,color:T.danger)),])),
              if (sel == null)
                Autocomplete<Customer>(
                  optionsBuilder:(t) { if(t.text.isEmpty) return _custs; final q=t.text.toLowerCase();
                    return _custs.where((c)=>c.name.toLowerCase().contains(q)||c.phone.contains(q)); },
                  displayStringForOption:(c)=>'${c.name} — ${c.phone}',
                  fieldViewBuilder:(ctx,ctrl,focus,onSub)=>TextFormField(controller:ctrl,focusNode:focus,style:T.body,
                    decoration:InputDecoration(hintText:'Type name or phone...',
                      prefixIcon:Icon(Icons.search_rounded,size:18,color:T.text3)),
                    validator:(_)=>sel==null?_lang.t('required'):null),
                  optionsViewBuilder:(ctx,onSel,opts)=>Align(alignment:Alignment.topLeft,
                    child:Material(elevation:4,borderRadius:BorderRadius.circular(T.rMd),
                      child:Container(constraints:BoxConstraints(maxHeight:200,maxWidth:MediaQuery.of(ctx).size.width-48),
                        decoration:BoxDecoration(color:T.card,borderRadius:BorderRadius.circular(T.rMd)),
                        child:ListView.builder(padding:EdgeInsets.zero,shrinkWrap:true,itemCount:opts.length,
                          itemBuilder:(_,i){final c=opts.elementAt(i);
                            return InkWell(onTap:(){onSel(c);setSt(()=>sel=c);},
                              child:Padding(padding:const EdgeInsets.symmetric(horizontal:14,vertical:10),
                                child:Row(children:[
                                  Container(width:40,height:40,decoration:BoxDecoration(gradient:T.accentGrad,borderRadius:BorderRadius.circular(6)),
                                    child:Center(child:Text(c.initials,style:const TextStyle(fontSize:14,fontWeight:FontWeight.w700,color:T.headerDark)))),
                                  const SizedBox(width:10),
                                  Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                                    Text(c.name,style:T.body.copyWith(fontWeight:FontWeight.w600,fontSize:14)),
                                    Text(c.phone,style:T.bodySm.copyWith(fontSize:12)),]),])));
                          }))))),
              const SizedBox(height:18),
              Row(mainAxisAlignment:MainAxisAlignment.spaceBetween,children:[
                Text(_lang.t('order_items').toUpperCase(),style:T.label),
                GestureDetector(onTap:()=>setSt(()=>items.add(mkItem())),
                  child:Container(padding:const EdgeInsets.symmetric(horizontal:10,vertical:5),
                    decoration:BoxDecoration(color:T.success.withOpacity(0.1),borderRadius:BorderRadius.circular(8)),
                    child:Text('+ Add Item',style:T.bodySm.copyWith(color:T.success,fontWeight:FontWeight.w600)))),]),
              const SizedBox(height:8),
              ...items.asMap().entries.map((entry){final idx=entry.key;final it=entry.value;
                return Container(key:it['_key'] as Key,margin:const EdgeInsets.only(bottom:8),padding:const EdgeInsets.all(12),
                  decoration:BoxDecoration(color:T.card,borderRadius:BorderRadius.circular(T.rMd),boxShadow:T.shadowCard),
                  child:Column(children:[
                    Row(children:[
                      Container(padding:const EdgeInsets.symmetric(horizontal:10,vertical:5),
                        decoration:BoxDecoration(gradient:T.accentGrad,borderRadius:BorderRadius.circular(6)),
                        child:Text('${idx+1}',style:const TextStyle(fontSize:12,fontWeight:FontWeight.w700,color:T.headerDark))),
                      const Spacer(),
                      if(items.length>1)
                        GestureDetector(onTap:()=>setSt(()=>items.removeAt(idx)),
                          child:Container(padding:const EdgeInsets.all(4),
                            decoration:BoxDecoration(color:T.danger.withOpacity(0.1),borderRadius:BorderRadius.circular(6)),
                            child:const Icon(Icons.close_rounded,size:18,color:T.danger))),]),
                    const SizedBox(height:10),
                    DropdownButtonFormField<String>(value:it['garment']as String?,
                      decoration:InputDecoration(hintText:_lang.t('garment'),contentPadding:const EdgeInsets.symmetric(horizontal:14,vertical:12)),
                      items:C.garments.map((g)=>DropdownMenuItem(value:g,child:Text(g,style:T.body))).toList(),
                      onChanged:(v)=>setSt(()=>it['garment']=v),
                      validator:(v)=>v==null?'Select garment':null),
                    const SizedBox(height:8),
                    TextFormField(controller:it['fabricCtrl']as TextEditingController,style:T.body,
                      decoration:InputDecoration(hintText:'${_lang.t("fabric")} (e.g. Silk)',contentPadding:const EdgeInsets.symmetric(horizontal:14,vertical:12))),
                    const SizedBox(height:8),
                    Row(children:[
                      SizedBox(width:80,child:TextFormField(controller:it['qtyCtrl']as TextEditingController,style:T.body,keyboardType:TextInputType.number,
                        decoration:const InputDecoration(hintText:'Qty',contentPadding:EdgeInsets.symmetric(horizontal:14,vertical:12)),
                        validator:(v){if(v==null||v.trim().isEmpty)return 'Qty'; if(int.tryParse(v.trim())==null||int.parse(v.trim())<1)return 'Invalid'; return null;})),
                      const SizedBox(width:8),
                      Expanded(child:TextFormField(controller:it['priceCtrl']as TextEditingController,style:T.body,keyboardType:const TextInputType.numberWithOptions(decimal:true),
                        decoration:const InputDecoration(hintText:'Price per item (₹)',prefixText:'₹ ',contentPadding:EdgeInsets.symmetric(horizontal:14,vertical:12)),
                        validator:(v){if(v==null||v.trim().isEmpty)return 'Enter price'; if(double.tryParse(v.trim())==null)return 'Invalid'; return null;})),
                    ]),
                    const SizedBox(height:10),
                    Text('REFERENCE PHOTOS (OPTIONAL)',style:T.label.copyWith(fontSize:10)),
                    const SizedBox(height:6),
                    Row(children:[
                      Expanded(child:_OrderPhotoTile(
                        label:'Cloth / Material', icon:Icons.checkroom_rounded, height:90,
                        url:it['clothPhotoUrl']as String?, uploading:it['uploadingCloth']as bool,
                        onTap:()=>_showPhotoSourceOptions(ctx,'Cloth / Material Photo',(src)async{
                          setSt(()=>it['uploadingCloth']=true);
                          final url=await _uploadOrderPhoto(src);
                          setSt((){it['uploadingCloth']=false; if(url!=null) it['clothPhotoUrl']=url;});
                        }),
                        onRemove:()=>setSt(()=>it['clothPhotoUrl']=null))),
                      const SizedBox(width:8),
                      Expanded(child:_OrderPhotoTile(
                        label:'Design', icon:Icons.brush_rounded, height:90,
                        url:it['designPhotoUrl']as String?, uploading:it['uploadingDesign']as bool,
                        onTap:()=>_showPhotoSourceOptions(ctx,'Design Photo',(src)async{
                          setSt(()=>it['uploadingDesign']=true);
                          final url=await _uploadOrderPhoto(src);
                          setSt((){it['uploadingDesign']=false; if(url!=null) it['designPhotoUrl']=url;});
                        }),
                        onRemove:()=>setSt(()=>it['designPhotoUrl']=null))),
                    ]),
                    ]));
              }),
              const SizedBox(height:14),
              Text('ADVANCE PAID',style:T.label),
              const SizedBox(height:6),
              TextFormField(controller:advCtrl,style:T.body,keyboardType:const TextInputType.numberWithOptions(decimal:true),
                decoration:const InputDecoration(hintText:'Advance amount (₹)',prefixText:'₹ ',contentPadding:EdgeInsets.symmetric(horizontal:14,vertical:12))),
              const SizedBox(height:14),
              Row(crossAxisAlignment:CrossAxisAlignment.start,children:[
                Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                  Text('TRIAL DATE',style:T.label),
                  const SizedBox(height:6),
                  GestureDetector(onTap:()async{
                    final d=await showDatePicker(context:ctx,initialDate:trialDate??DateTime.now().add(const Duration(days:3)),
                      firstDate:DateTime.now(),lastDate:DateTime.now().add(const Duration(days:365)));
                    if(d!=null)setSt(()=>trialDate=d);},
                    child:Container(padding:const EdgeInsets.symmetric(horizontal:14,vertical:14),
                      decoration:BoxDecoration(color:T.surface,borderRadius:BorderRadius.circular(T.rMd)),
                      child:Row(children:[
                        const Icon(Icons.calendar_today_rounded,size:18,color:T.text3),const SizedBox(width:10),
                        Expanded(child:Text(trialDate!=null?DateFormat('dd MMM yyyy').format(trialDate!):_lang.t('select_date'),
                          style:T.body.copyWith(fontSize:16,color:trialDate!=null?T.text:T.text3),overflow:TextOverflow.ellipsis)),]))),
                ])),
                const SizedBox(width:10),
                Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                  Text(_lang.t('delivery_date').toUpperCase(),style:T.label),
                  const SizedBox(height:6),
                  GestureDetector(onTap:()async{
                    final d=await showDatePicker(context:ctx,initialDate:dueDate??DateTime.now().add(const Duration(days:7)),
                      firstDate:DateTime.now(),lastDate:DateTime.now().add(const Duration(days:365)));
                    if(d!=null)setSt(()=>dueDate=d);},
                    child:Container(padding:const EdgeInsets.symmetric(horizontal:14,vertical:14),
                      decoration:BoxDecoration(color:T.surface,borderRadius:BorderRadius.circular(T.rMd)),
                      child:Row(children:[
                        const Icon(Icons.calendar_today_rounded,size:18,color:T.text3),const SizedBox(width:10),
                        Expanded(child:Text(dueDate!=null?DateFormat('dd MMM yyyy').format(dueDate!):_lang.t('select_date'),
                          style:T.body.copyWith(fontSize:16,color:dueDate!=null?T.text:T.text3),overflow:TextOverflow.ellipsis)),]))),
                ])),
              ]),
              const SizedBox(height:14),
              TxField(label:_lang.t('notes'),hint:'Design notes...',controller:notesCtrl,maxLines:3),
              const SizedBox(height:24),
              Container(height:52,decoration:BoxDecoration(gradient:T.headerGrad,borderRadius:BorderRadius.circular(T.rMd),
                boxShadow:[BoxShadow(color:T.headerDark.withOpacity(0.3),blurRadius:16,offset:const Offset(0,6))]),
                child:Material(color:Colors.transparent,child:InkWell(
                  onTap:()async{
                    if(!fk.currentState!.validate()) return;
                    final parts=<String>[];
                    for(final i in items){
                      final g=i['garment']as String?;
                      final f=(i['fabricCtrl']as TextEditingController).text;
                      if(g==null||g.isEmpty)continue; String p=g; if(f.isNotEmpty)p+=' ($f)'; parts.add(p);}
                    final orderItems=items.where((i)=>(i['garment']as String?)?.isNotEmpty==true).map((i)=>OrderItem(
                      garment:i['garment']as String?,
                      fabric:(i['fabricCtrl']as TextEditingController).text,
                      qty:int.tryParse((i['qtyCtrl']as TextEditingController).text.trim())??1,
                      price:double.tryParse((i['priceCtrl']as TextEditingController).text.trim()),
                      clothPhotoUrl:i['clothPhotoUrl']as String?,designPhotoUrl:i['designPhotoUrl']as String?,
                    )).toList();
                    final total=orderItems.fold(0.0,(s,it)=>s+it.total);
                    final adv=(double.tryParse(advCtrl.text.trim())??0).clamp(0,total).toDouble();
                    final due=(total-adv).clamp(0.0,double.infinity);
                    final order=Order(customerId:sel!.id,customerName:sel!.name,
                      garment:parts.join(', '),
                      fabric:orderItems.map((i)=>i.fabric??'').where((f)=>f.isNotEmpty).join(', '),
                      amount:total,advance:adv,dueDate:dueDate?.toIso8601String().split('T').first,
                      trialDate:trialDate?.toIso8601String().split('T').first,notes:notesCtrl.text.trim(),
                      items:orderItems,
                      clothPhotoUrl:orderItems.isNotEmpty?orderItems.first.clothPhotoUrl:null,
                      designPhotoUrl:orderItems.isNotEmpty?orderItems.first.designPhotoUrl:null);
                    try{
                      final created=await _api.createOrder(order);
                      final invStatus=due<=0?'paid':adv>0?'partial':'unpaid';
                      await _api.createInvoice(Invoice(
                        orderId:created.id,customerId:sel!.id,customerName:sel!.name,customerPhone:sel!.phone,
                        garment:parts.join(', '),
                        deliveryDate:dueDate?.toIso8601String().split('T').first,
                        trialDate:trialDate?.toIso8601String().split('T').first,
                        subtotal:total,advance:adv,dueAmount:due,status:invStatus,
                      ));
                      if(ctx.mounted)Navigator.pop(ctx);
                      if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text(_lang.t('order_created'))));
                    }catch(e){if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('$e')));
                    }finally{_load();}},
                  borderRadius:BorderRadius.circular(T.rMd),
                  child:Center(child:Text(_lang.t('create_order').toUpperCase(),
                    style:T.btn.copyWith(color:T.accent,letterSpacing:1.5)))))),
            ])))
          ]));
      }));
  }

  // ─── JOB CARD (internal work order — given to employees/tailors) ───────────
  String _measLabel(String key) {
    var k = key;
    if (k.startsWith('blouse_')) k = 'Blouse ${k.substring(7)}';
    else if (k.startsWith('dress_')) k = 'Dress ${k.substring(6)}';
    return k.split('_').map((w) => w.isEmpty ? w : '${w[0].toUpperCase()}${w.substring(1)}').join(' ');
  }

  void _showJobCard(Order o) {
    Customer? cust;
    try { cust = _custs.firstWhere((c) => c.id == o.customerId); } catch (_) {}
    final meas = cust?.allMeasurements ?? <String, dynamic>{};
    final dueDate = o.dueDate?.isNotEmpty == true ? o.dueDate : null;

    showModalBottomSheet(
      context: context, isScrollControlled: true, backgroundColor: Colors.transparent,
      builder: (ctx) => T.sheetScaffold(ctx, heightFraction: 0.92, child: Column(children: [
          // ── Header ──
          Container(
            padding: const EdgeInsets.fromLTRB(18, 16, 18, 20),
            decoration: const BoxDecoration(gradient: T.headerGrad, borderRadius: BorderRadius.vertical(top: Radius.circular(T.rXl))),
            child: Column(children: [
              Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                GestureDetector(onTap: () => Navigator.pop(ctx),
                  child: const Icon(Icons.arrow_back_ios_rounded, size: 18, color: T.headerText)),
                Row(children: [
                  GestureDetector(
                    onTap: () => PdfHelper.generateAndShareJobCard(o, cust,
                      boutiqueName: _api.boutiqueName, boutiqueAddress: _api.boutiqueAddress, boutiquePhone: _api.boutiquePhone),
                    child: const Icon(Icons.share_rounded, size: 16, color: T.headerText)),
                  const SizedBox(width: 16),
                  GestureDetector(
                    onTap: () => PdfHelper.generateAndPrintJobCard(o, cust,
                      boutiqueName: _api.boutiqueName, boutiqueAddress: _api.boutiqueAddress, boutiquePhone: _api.boutiquePhone),
                    child: const Icon(Icons.print_rounded, size: 16, color: T.headerText)),
                ]),
              ]),
              const SizedBox(height: 14),
              Row(children: [
                Container(
                  padding: const EdgeInsets.all(10),
                  decoration: BoxDecoration(color: Colors.white.withOpacity(0.12), borderRadius: BorderRadius.circular(T.rSm)),
                  child: const Icon(Icons.content_cut_rounded, color: T.headerText, size: 22)),
                const SizedBox(width: 12),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text('Job Card', style: GoogleFonts.prata(fontSize: 22, fontWeight: FontWeight.w400, color: Colors.white)),
                  const SizedBox(height: 4),
                  Text('Order #${o.id ?? 0} · ${o.customerName ?? "Unknown"}',
                    style: TextStyle(fontSize: 12, color: Colors.white.withOpacity(0.6), fontWeight: FontWeight.w500)),
                ])),
              ]),
            ]),
          ),
          // ── Body ──
          Expanded(child: ListView(padding: const EdgeInsets.fromLTRB(16, 16, 16, 80), children: [
            if (dueDate != null) ...[
              _DetailSection(title: 'Delivery Date', child:
                Text(dueDate, style: T.body.copyWith(fontSize: 17, fontWeight: FontWeight.w700, color: T.danger))),
              const SizedBox(height: 10),
            ],
            ..._itemsDetailWidgets(o),
            const SizedBox(height: 10),
            _DetailSection(title: 'Customer Measurements', child:
              meas.isEmpty
                ? Text('No saved measurements for this customer.',
                    style: T.bodySm.copyWith(color: T.text3, fontStyle: FontStyle.italic))
                : Wrap(spacing: 8, runSpacing: 8, children: meas.entries.map((e) =>
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 8),
                      decoration: BoxDecoration(color: T.surface, borderRadius: BorderRadius.circular(T.rSm), border: Border.all(color: T.border)),
                      child: Text('${_measLabel(e.key)}: ${e.value}"',
                        style: T.bodySm.copyWith(fontWeight: FontWeight.w600)))
                  ).toList())),
            if (o.notes?.isNotEmpty == true) ...[
              const SizedBox(height: 10),
              _DetailSection(title: 'Special Instructions / Notes', child:
                Text(o.notes!, style: T.body.copyWith(fontSize: 15))),
            ],
            const SizedBox(height: 16),
            Center(child: Text('Internal use only — not a billing document',
              style: T.bodySm.copyWith(color: T.text3, fontStyle: FontStyle.italic))),
          ])),
        ]),
      ),
    );
  }

  // ─── ORDER DETAIL VIEW ──────────────────────────────────────────────────────
  void _viewOrder(Order o, int idx) {
    showModalBottomSheet(
      context: context, isScrollControlled: true, backgroundColor: Colors.transparent,
      builder: (ctx) => StatefulBuilder(builder: (ctx, setSt) => T.sheetScaffold(ctx, heightFraction: 0.92, child: Column(children: [
          // ── Gradient header ──
          Container(
            padding: const EdgeInsets.fromLTRB(18, 16, 18, 20),
            decoration: const BoxDecoration(gradient: T.headerGrad, borderRadius: BorderRadius.vertical(top: Radius.circular(T.rXl))),
            child: Column(children: [
              Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                GestureDetector(onTap: () => Navigator.pop(ctx),
                  child: const Icon(Icons.arrow_back_ios_rounded, size: 18, color: T.headerText)),
                Row(children: [
                  GestureDetector(
                    onTap: () => _showJobCard(o),
                    child: const Icon(Icons.content_cut_rounded, size: 17, color: T.headerText)),
                  const SizedBox(width: 16),
                  GestureDetector(
                    onTap: () { Navigator.pop(ctx); _editOrder(o); },
                    child: const Icon(Icons.edit_rounded, size: 16, color: T.headerText)),
                  const SizedBox(width: 16),
                  GestureDetector(
                    onTap: () { Navigator.pop(ctx); _deleteOrder(o); },
                    child: const Icon(Icons.delete_rounded, size: 16, color: T.headerText)),
                ]),
              ]),
              const SizedBox(height: 18),
              // Customer avatar + name + order ID
              Row(crossAxisAlignment: CrossAxisAlignment.center, children: [
                Container(
                  width: 64, height: 64,
                  decoration: BoxDecoration(
                    gradient: _ag(idx), borderRadius: BorderRadius.circular(18),
                    boxShadow: [BoxShadow(color: T.accent.withOpacity(0.35), blurRadius: 18, offset: const Offset(0, 8))]),
                  child: Center(child: Text(
                    (o.customerName?.isNotEmpty == true ? o.customerName! : '?')[0].toUpperCase(),
                    style: GoogleFonts.prata(fontSize: 32, fontWeight: FontWeight.w400, color: Colors.white)))),
                const SizedBox(width: 14),
                Expanded(child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
                  Text(o.customerName ?? 'Unknown',
                    style: GoogleFonts.prata(fontSize: 26, fontWeight: FontWeight.w400, color: Colors.white)),
                  const SizedBox(height: 6),
                  Row(children: [
                    Text('Order #${o.id ?? 0}',
                      style: TextStyle(fontSize: 13, color: Colors.white.withOpacity(0.5), fontWeight: FontWeight.w500, letterSpacing: 0.5)),
                    const SizedBox(width: 10),
                    Container(
                      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
                      decoration: BoxDecoration(color: T.stageColor(o.stage).withOpacity(0.22), borderRadius: BorderRadius.circular(4)),
                      child: Text(o.stage.toUpperCase(),
                        style: TextStyle(fontSize: 11, fontWeight: FontWeight.w800, letterSpacing: 0.8, color: T.stageColor(o.stage)))),
                  ]),
                ])),
              ]),
              const SizedBox(height: 16),
              // Stage progress bar
              Row(children: List.generate(C.statuses.length, (j) {
                final ci = C.statuses.indexWhere((s) => s.toLowerCase() == o.stage.toLowerCase());
                return Expanded(child: Container(
                  margin: const EdgeInsets.symmetric(horizontal: 1.5), height: 4,
                  decoration: BoxDecoration(
                    color: j <= ci ? T.stageColor(o.stage) : Colors.white.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(2))));
              })),
              const SizedBox(height: 6),
              Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                Text('Received', style: TextStyle(fontSize: 10, color: Colors.white.withOpacity(0.4), fontWeight: FontWeight.w500)),
                Text('Delivered', style: TextStyle(fontSize: 10, color: Colors.white.withOpacity(0.4), fontWeight: FontWeight.w500)),
              ]),
            ]),
          ),

          // ── Scrollable body ──
          Expanded(child: ListView(padding: const EdgeInsets.fromLTRB(16, 16, 16, 80), children: [

            // Garment, fabric & per-item reference photos
            ..._itemsDetailWidgets(o),
            const SizedBox(height: 10),

            // Payment summary
            Container(
              padding: const EdgeInsets.all(16),
              decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd),
                boxShadow: T.shadowCard, border: Border.all(color: T.accent.withOpacity(0.12))),
              child: Column(children: [
                _PayRow('Total Amount', _fmt.format(o.totalAmount), T.text),
                const SizedBox(height: 10),
                _PayRow('Advance Paid', _fmt.format(o.advanceAmount),
                  o.advanceAmount > 0 ? T.success : T.text2),
                Padding(
                  padding: const EdgeInsets.symmetric(vertical: 10),
                  child: Divider(color: T.border, height: 1)),
                _PayRow('Balance Due', _fmt.format(o.balanceAmount),
                  o.balanceAmount > 0 ? T.danger : T.success, bold: true),
              ])),
            const SizedBox(height: 10),

            // Trial & Delivery dates
            if (o.trialDate != null || o.dueDate != null) ...[
              Row(children: [
                if (o.trialDate != null)
                  Expanded(child: _DetailSection(
                    title: 'Trial Date',
                    child: Row(children: [
                      Icon(Icons.calendar_today_rounded, size: 16, color: T.text2),
                      const SizedBox(width: 8),
                      Text(DateFormat('dd MMM yyyy').format(DateTime.parse(o.trialDate!)),
                        style: T.body.copyWith(fontSize: 16, fontWeight: FontWeight.w500)),
                    ]))),
                if (o.trialDate != null && o.dueDate != null) const SizedBox(width: 12),
                if (o.dueDate != null)
                  Expanded(child: _DetailSection(
                    title: 'Delivery Date',
                    child: Row(children: [
                      Icon(Icons.calendar_today_rounded, size: 16, color: T.text2),
                      const SizedBox(width: 8),
                      Text(DateFormat('dd MMM yyyy').format(DateTime.parse(o.dueDate!)),
                        style: T.body.copyWith(fontSize: 16, fontWeight: FontWeight.w500)),
                    ]))),
              ]),
              const SizedBox(height: 10),
            ],

            // Notes
            if (o.notes?.isNotEmpty == true) ...[
              _DetailSection(title: 'Notes', child:
                Text(o.notes!, style: T.body.copyWith(fontSize: 15), maxLines: 6, overflow: TextOverflow.ellipsis)),
              const SizedBox(height: 10),
            ],

            // Created at
            if (o.createdAt != null)
              Padding(
                padding: const EdgeInsets.only(top: 4),
                child: Text('Created ${DateFormat("dd MMM yyyy").format(DateTime.parse(o.createdAt!))}',
                  style: T.bodySm.copyWith(fontSize: 12, color: T.text3), textAlign: TextAlign.center)),
          ])),

          // ── Bottom action bar ──
          Container(
            padding: const EdgeInsets.fromLTRB(16, 8, 16, 24),
            decoration: BoxDecoration(
              gradient: LinearGradient(begin: Alignment.topCenter, end: Alignment.bottomCenter,
                colors: [T.bg.withOpacity(0), T.bg])),
            child: Row(children: [
              // Edit button
              Expanded(child: GestureDetector(
                onTap: () { Navigator.pop(ctx); _editOrder(o); },
                child: Container(
                  height: 50,
                  decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
                  child: Center(child: Text('EDIT',
                    style: TextStyle(fontSize: 13, fontWeight: FontWeight.w600, letterSpacing: 0.8, color: T.text)))))),
              const SizedBox(width: 8),
              // Create Bill button
              if (widget.onCreateInvoice != null)
                Expanded(child: GestureDetector(
                  onTap: () { Navigator.pop(ctx); widget.onCreateInvoice!(o); },
                  child: Container(
                    height: 50,
                    decoration: BoxDecoration(
                      color: T.accent.withOpacity(0.12),
                      borderRadius: BorderRadius.circular(T.rMd),
                      border: Border.all(color: T.accent.withOpacity(0.3))),
                    child: Row(mainAxisAlignment: MainAxisAlignment.center, children: [
                      Icon(Icons.receipt_long_outlined, size: 16, color: T.accent),
                      const SizedBox(width: 6),
                      Text('BILL', style: TextStyle(fontSize: 13, fontWeight: FontWeight.w700, letterSpacing: 0.8, color: T.accent)),
                    ])))),
              const SizedBox(width: 8),
              // Change Status button
              Expanded(flex: 2, child: GestureDetector(
                onTap: () { Navigator.pop(ctx); _statusSheet(o); },
                child: Container(
                  height: 50,
                  decoration: BoxDecoration(gradient: T.headerGrad, borderRadius: BorderRadius.circular(T.rMd),
                    boxShadow: [BoxShadow(color: T.headerDark.withOpacity(0.3), blurRadius: 12, offset: const Offset(0, 4))]),
                  child: Center(child: Text('CHANGE STATUS',
                    style: T.btn.copyWith(color: T.accent, letterSpacing: 1.2)))))),
            ]),
          ),
        ]),
      )),
    );
  }

  // ─── EDIT ORDER ─────────────────────────────────────────────────────────────
  void _editOrder(Order o) {
    final garmentCtrl = TextEditingController(text: o.garment ?? '');
    final fabricCtrl  = TextEditingController(text: o.fabric ?? '');
    final amtCtrl     = TextEditingController(text: o.amount > 0 ? o.amount.toStringAsFixed(0) : '');
    final advCtrl     = TextEditingController(text: o.advance > 0 ? o.advance.toStringAsFixed(0) : '');
    final notesCtrl   = TextEditingController(text: o.notes ?? '');
    DateTime? dueDate = o.dueDate != null ? DateTime.tryParse(o.dueDate!) : null;
    final fk = GlobalKey<FormState>();
    String? clothPhotoUrl = o.clothPhotoUrl; String? designPhotoUrl = o.designPhotoUrl;
    bool uploadingCloth = false; bool uploadingDesign = false;

    showModalBottomSheet(
      context: context, isScrollControlled: true, backgroundColor: Colors.transparent,
      builder: (ctx) => StatefulBuilder(builder: (ctx, setSt) {
        final amt = double.tryParse(amtCtrl.text) ?? 0;
        final adv = double.tryParse(advCtrl.text) ?? 0;
        final bal = (amt - adv).clamp(0.0, double.infinity);
        return Container(
          height: MediaQuery.of(ctx).size.height * 0.93,
          decoration: BoxDecoration(color: T.bg, borderRadius: const BorderRadius.vertical(top: Radius.circular(T.rXl))),
          child: Column(children: [
            const SizedBox(height: 12),
            Container(width: 36, height: 4, decoration: BoxDecoration(color: T.border, borderRadius: BorderRadius.circular(2))),
            Expanded(child: Form(key: fk, child: ListView(padding: EdgeInsets.fromLTRB(20, 20, 20, 30 + MediaQuery.of(ctx).viewInsets.bottom), children: [
              Text('Edit Order', style: T.displayMd),
              const SizedBox(height: 4),
              Text('${o.customerName ?? ''} · Order #${o.id ?? ''}',
                style: T.bodySm.copyWith(color: T.text2)),
              const SizedBox(height: 20),

              TxField(
                label: 'Garment',
                hint: 'e.g. Blouse, Lehenga x2',
                controller: garmentCtrl,
                validator: (v) => v == null || v.trim().isEmpty ? 'Required' : null),
              const SizedBox(height: 12),
              TxField(label: 'Fabric', hint: 'e.g. Silk, Cotton (optional)', controller: fabricCtrl),
              const SizedBox(height: 12),

              Row(children: [
                Expanded(child: TxField(
                  label: 'Total Amount (₹)',
                  hint: '0',
                  controller: amtCtrl,
                  keyboardType: TextInputType.number,
                  onChanged: (_) => setSt(() {}),
                  validator: (v) => v == null || v.isEmpty ? 'Required' : null)),
                const SizedBox(width: 10),
                Expanded(child: TxField(
                  label: 'Advance Paid (₹)',
                  hint: '0',
                  controller: advCtrl,
                  keyboardType: TextInputType.number,
                  onChanged: (_) => setSt(() {}))),
              ]),
              const SizedBox(height: 10),

              Container(
                padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 12),
                decoration: BoxDecoration(
                  color: bal > 0 ? T.danger.withOpacity(0.06) : T.success.withOpacity(0.06),
                  borderRadius: BorderRadius.circular(8)),
                child: Row(mainAxisAlignment: MainAxisAlignment.spaceBetween, children: [
                  Text('BALANCE DUE', style: T.label.copyWith(fontWeight: FontWeight.w700)),
                  Text(_fmt.format(bal),
                    style: T.heading.copyWith(color: bal > 0 ? T.danger : T.success)),
                ])),
              const SizedBox(height: 16),

              Text('DELIVERY DATE', style: T.label),
              const SizedBox(height: 6),
              GestureDetector(
                onTap: () async {
                  final d = await showDatePicker(
                    context: ctx,
                    initialDate: dueDate ?? DateTime.now().add(const Duration(days: 7)),
                    firstDate: DateTime.now().subtract(const Duration(days: 365)),
                    lastDate: DateTime.now().add(const Duration(days: 730)));
                  if (d != null) setSt(() => dueDate = d);
                },
                child: Container(
                  padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
                  decoration: BoxDecoration(color: T.surface, borderRadius: BorderRadius.circular(T.rMd)),
                  child: Row(children: [
                    Icon(Icons.calendar_today_rounded, size: 18,
                      color: dueDate != null ? T.accent : T.text3),
                    const SizedBox(width: 10),
                    Text(
                      dueDate != null ? DateFormat('dd MMM yyyy').format(dueDate!) : 'Select Date',
                      style: T.body.copyWith(fontSize: 18, color: dueDate != null ? T.text : T.text3)),
                  ]))),
              const SizedBox(height: 14),

              Text('REFERENCE PHOTOS', style: T.label),
              const SizedBox(height: 6),
              Row(children: [
                Expanded(child: _OrderPhotoTile(
                  label: 'Material / Cloth Photo', icon: Icons.checkroom_rounded,
                  url: clothPhotoUrl, uploading: uploadingCloth,
                  onTap: () => _showPhotoSourceOptions(ctx, 'Cloth / Material Photo', (src) async {
                    setSt(() => uploadingCloth = true);
                    final url = await _uploadOrderPhoto(src);
                    setSt(() { uploadingCloth = false; if (url != null) clothPhotoUrl = url; });
                  }),
                  onRemove: () => setSt(() => clothPhotoUrl = null))),
                const SizedBox(width: 10),
                Expanded(child: _OrderPhotoTile(
                  label: 'Design Photo', icon: Icons.brush_rounded,
                  url: designPhotoUrl, uploading: uploadingDesign,
                  onTap: () => _showPhotoSourceOptions(ctx, 'Design Photo', (src) async {
                    setSt(() => uploadingDesign = true);
                    final url = await _uploadOrderPhoto(src);
                    setSt(() { uploadingDesign = false; if (url != null) designPhotoUrl = url; });
                  }),
                  onRemove: () => setSt(() => designPhotoUrl = null))),
              ]),
              const SizedBox(height: 14),

              TxField(label: 'Notes', hint: 'Design notes, special instructions...', controller: notesCtrl, maxLines: 3),
              const SizedBox(height: 24),

              Container(
                height: 52,
                decoration: BoxDecoration(gradient: T.headerGrad, borderRadius: BorderRadius.circular(T.rMd),
                  boxShadow: [BoxShadow(color: T.headerDark.withOpacity(0.3), blurRadius: 16, offset: const Offset(0, 6))]),
                child: Material(color: Colors.transparent, child: InkWell(
                  onTap: () async {
                    if (!fk.currentState!.validate()) return;
                    try {
                      await _api.updateOrder(
                        o.id!,
                        garment: garmentCtrl.text.trim(),
                        fabric: fabricCtrl.text.trim(),
                        amount: double.tryParse(amtCtrl.text) ?? o.amount,
                        advance: double.tryParse(advCtrl.text) ?? o.advance,
                        dueDate: dueDate?.toIso8601String().split('T').first,
                        notes: notesCtrl.text.trim(),
                        clothPhotoUrl: clothPhotoUrl ?? '',
                        designPhotoUrl: designPhotoUrl ?? '');
                      if (ctx.mounted) Navigator.pop(ctx);
                      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
                        const SnackBar(content: Text('Order updated successfully')));
                    } catch (e) {
                      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
                    } finally { _load(); }
                  },
                  borderRadius: BorderRadius.circular(T.rMd),
                  child: Center(child: Text('SAVE CHANGES',
                    style: T.btn.copyWith(color: T.accent, letterSpacing: 1.5)))))),
            ]))),
          ]),
        );
      }),
    );
  }

  // ─── DELETE ORDER ───────────────────────────────────────────────────────────
  void _deleteOrder(Order o) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: T.card,
        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(T.rLg)),
        title: Text('Delete Order?', style: T.heading),
        content: Text(
          'Delete order #${o.id} for "${o.customerName}"?\nThis cannot be undone.',
          style: T.body),
        actions: [
          TextButton(onPressed: () => Navigator.pop(ctx, false),
            child: Text('Cancel', style: TextStyle(color: T.text2))),
          ElevatedButton(
            style: ElevatedButton.styleFrom(backgroundColor: T.danger, foregroundColor: Colors.white,
              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8))),
            onPressed: () => Navigator.pop(ctx, true),
            child: const Text('DELETE')),
        ],
      ));
    if (ok == true) {
      try {
        await _api.deleteOrder(o.id!);
        _load();
        if (mounted) ScaffoldMessenger.of(context).showSnackBar(
          SnackBar(content: Text('Order #${o.id} deleted')));
      } catch (e) {
        if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
      }
    }
  }

  // ─── STATUS SHEET ───────────────────────────────────────────────────────────
  void _statusSheet(Order o) {
    showModalBottomSheet(context:context, isScrollControlled: true, backgroundColor:Colors.transparent,
      builder:(ctx)=>T.sheetWrap(ctx,Container(
        constraints: BoxConstraints(maxHeight: MediaQuery.of(context).size.height * 0.8),
        decoration:BoxDecoration(color:T.bg,borderRadius:const BorderRadius.vertical(top:Radius.circular(T.rXl))),
        child:Padding(padding:const EdgeInsets.all(24),child:Column(
          mainAxisSize:MainAxisSize.min,crossAxisAlignment:CrossAxisAlignment.stretch,children:[
            Center(child:Container(width:36,height:4,decoration:BoxDecoration(color:T.border,borderRadius:BorderRadius.circular(2)))),
            const SizedBox(height:16),
            Text(_lang.t('update_status'),style:T.displaySm),
            const SizedBox(height:4),
            Text('${o.customerName??""} — ${o.description}',style:T.bodySm,maxLines:1,overflow:TextOverflow.ellipsis),
            const SizedBox(height:16),
            Flexible(
              child: SingleChildScrollView(
                child: Column(children: C.statuses.map((s)=>Padding(padding:const EdgeInsets.only(bottom:6),
                  child:Material(color:Colors.transparent,child:InkWell(
                    onTap:()async{Navigator.pop(ctx);
                      try{
                        final updated=await _api.updateOrderStatus(o.id!,s,amount:o.amount,advance:o.advance);
                        _load();
                        if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('Stage updated to $s')));
                        // Offer to create an invoice when order is marked Delivered
                        if(s=='Delivered'&&widget.onCreateInvoice!=null&&mounted){
                          final create=await showDialog<bool>(context:context,builder:(ctx)=>AlertDialog(
                            backgroundColor:T.card,shape:RoundedRectangleBorder(borderRadius:BorderRadius.circular(T.rLg)),
                            title:Text('Create Invoice?',style:T.heading),
                            content:Text('Would you like to generate a bill for ${updated.customerName}\'s order now?',style:T.body),
                            actions:[
                              TextButton(onPressed:()=>Navigator.pop(ctx,false),child:Text('Later',style:TextStyle(color:T.text2))),
                              ElevatedButton(
                                style:ElevatedButton.styleFrom(backgroundColor:T.headerDark,foregroundColor:T.accent,
                                  shape:RoundedRectangleBorder(borderRadius:BorderRadius.circular(8))),
                                onPressed:()=>Navigator.pop(ctx,true),
                                child:const Text('CREATE BILL')),]));
                          if(create==true&&mounted)widget.onCreateInvoice!(updated);
                        }
                      }catch(e){if(mounted)ScaffoldMessenger.of(context).showSnackBar(SnackBar(content:Text('$e')));}},
                    borderRadius:BorderRadius.circular(T.rMd),
                    child:Container(padding:const EdgeInsets.all(14),
                      decoration:BoxDecoration(
                        color:o.status.toLowerCase()==s.toLowerCase()?T.stageColor(s).withOpacity(0.08):T.card,
                        borderRadius:BorderRadius.circular(T.rMd),
                        border:Border.all(color:o.status.toLowerCase()==s.toLowerCase()?T.stageColor(s):T.border,
                          width:o.status.toLowerCase()==s.toLowerCase()?1.5:1)),
                      child:Row(children:[
                        Container(width:10,height:10,decoration:BoxDecoration(color:T.stageColor(s),shape:BoxShape.circle)),
                        const SizedBox(width:12),
                        Text(s,style:T.body.copyWith(fontWeight:o.status.toLowerCase()==s.toLowerCase()?FontWeight.w700:FontWeight.w400)),
                        if(o.status.toLowerCase()==s.toLowerCase())...[const Spacer(),
                          Icon(Icons.check_circle_rounded,size:18,color:T.stageColor(s))],])))))).toList()),
              ),
            ),
            const SizedBox(height:8),
          ]))))));
  }

  // ─── BUILD ──────────────────────────────────────────────────────────────────
  @override
  Widget build(BuildContext context) {
    return Scaffold(backgroundColor:T.bg,body:Column(children:[
      // Search bar
      Padding(padding:const EdgeInsets.fromLTRB(18,12,18,4),
        child:Container(decoration:BoxDecoration(color:T.card,borderRadius:BorderRadius.circular(12),boxShadow:T.shadowCard),
          child:TextField(controller:_searchCtrl,style:T.body.copyWith(fontSize:18),
            decoration:InputDecoration(hintText:'Search orders...',
              prefixIcon:Icon(Icons.search_rounded,size:20,color:T.text3),
              suffixIcon:_search.isNotEmpty?IconButton(icon:const Icon(Icons.close_rounded,size:20),
                onPressed:(){_searchCtrl.clear();setState(()=>_search='');_load();}):null,
              border:InputBorder.none,filled:false,contentPadding:const EdgeInsets.symmetric(horizontal:12,vertical:10)),
            onChanged:(v){setState(()=>_search=v);_load();}))),

      // Filter pills
      SizedBox(height:50,child:ListView(scrollDirection:Axis.horizontal,
        padding:const EdgeInsets.symmetric(horizontal:18,vertical:6),
        children:['',... C.statuses].map((s){final sel=_filter==s;
          return Padding(padding:const EdgeInsets.only(right:6),
            child:GestureDetector(onTap:(){setState(()=>_filter=s);_load();},
              child:Container(padding:const EdgeInsets.symmetric(horizontal:16,vertical:6),
                decoration:BoxDecoration(color:sel?T.headerDark:T.surface,borderRadius:BorderRadius.circular(8)),
                child:Center(child: Text(s.isEmpty?'All':s, style:TextStyle(fontSize:12,fontWeight:FontWeight.w600,
                  letterSpacing:0.5,color:sel?Colors.white:T.text2))))));
        }).toList())),

      // Order list
      Expanded(child:_loading
        ?const Center(child:CircularProgressIndicator(strokeWidth:1.5,color:T.accent))
        :_list.isEmpty
          ?EmptyState(icon:Icons.receipt_long_outlined,title:_lang.t('no_orders'),
            subtitle:_lang.t('create_first_order'),buttonLabel:_lang.t('create_order'),onPressed:_newOrder)
          :RefreshIndicator(onRefresh:_load,color:T.accent,
            child:ListView.builder(padding:const EdgeInsets.fromLTRB(18,4,18,80),itemCount:_list.length,
              itemBuilder:(_,i){final o=_list[i];final sc=T.stageColor(o.stage);
                final ci=C.statuses.indexWhere((s)=>s.toLowerCase()==o.stage.toLowerCase());
                return Dismissible(
                  key: Key('order_${o.id}'),
                  direction: DismissDirection.endToStart,
                  confirmDismiss: (_) async {
                    return await showDialog<bool>(
                      context: context,
                      builder: (ctx) => AlertDialog(
                        backgroundColor: T.card,
                        shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(T.rLg)),
                        title: Text('Delete Order?', style: T.heading),
                        content: Text('Delete order #${o.id} for "${o.customerName}"?\nThis cannot be undone.', style: T.body),
                        actions: [
                          TextButton(onPressed: () => Navigator.pop(ctx, false),
                            child: Text('Cancel', style: TextStyle(color: T.text2))),
                          ElevatedButton(
                            style: ElevatedButton.styleFrom(backgroundColor: T.danger, foregroundColor: Colors.white,
                              shape: RoundedRectangleBorder(borderRadius: BorderRadius.circular(8))),
                            onPressed: () => Navigator.pop(ctx, true),
                            child: const Text('DELETE')),
                        ],
                      )) ?? false;
                  },
                  onDismissed: (_) async {
                    try {
                      await _api.deleteOrder(o.id!);
                      if (mounted) ScaffoldMessenger.of(context).showSnackBar(
                        SnackBar(content: Text('Order #${o.id} deleted'),
                          action: SnackBarAction(label: 'OK', onPressed: () {})));
                    } catch (e) {
                      if (mounted) ScaffoldMessenger.of(context).showSnackBar(SnackBar(content: Text('$e')));
                      _load(); // reload if delete failed
                    }
                  },
                  background: Container(
                    margin: const EdgeInsets.only(bottom: 7),
                    decoration: BoxDecoration(color: T.danger, borderRadius: BorderRadius.circular(12)),
                    alignment: Alignment.centerRight,
                    padding: const EdgeInsets.only(right: 20),
                    child: Column(mainAxisAlignment: MainAxisAlignment.center, children: [
                      const Icon(Icons.delete_rounded, color: Colors.white, size: 24),
                      const SizedBox(height: 4),
                      const Text('DELETE', style: TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.w800, letterSpacing: 0.8)),
                    ])),
                  child: Padding(padding:const EdgeInsets.only(bottom:7),
                  child:Material(color:T.card,borderRadius:BorderRadius.circular(12),
                    child:InkWell(
                      onTap:()=>_viewOrder(o, i),
                      borderRadius:BorderRadius.circular(12),
                      child:Container(
                        padding:const EdgeInsets.all(12),
                        decoration:BoxDecoration(
                          borderRadius:BorderRadius.circular(12),
                          boxShadow:T.shadowCard,
                          // Red left accent when balance is outstanding
                          border: o.balanceAmount > 0
                            ? Border(left: BorderSide(color: T.danger, width: 3))
                            : null,
                        ),
                        child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                          // Row 1: ID + stage + due date + bill icon
                          Row(children:[
                            Text('#${o.id??0}',style:GoogleFonts.prata(fontSize:18,fontWeight:FontWeight.w400,color:T.text2,letterSpacing:0.6)),
                            const SizedBox(width:8),
                            Container(padding:const EdgeInsets.symmetric(horizontal:8,vertical:3),
                              decoration:BoxDecoration(color:sc.withOpacity(0.12),borderRadius:BorderRadius.circular(4)),
                              child:Text(o.stage.toUpperCase(),style:TextStyle(fontSize:12,fontWeight:FontWeight.w800,letterSpacing:0.8,color:sc))),
                            const Spacer(),
                            if(o.dueDate!=null)
                              Text('Due ${DateFormat("dd MMM").format(DateTime.parse(o.dueDate!))}',
                                style:T.bodySm.copyWith(fontSize:13,fontWeight:FontWeight.w600)),
                            const SizedBox(width:6),
                            // Bill icon — opens invoice form pre-filled for this order
                            GestureDetector(
                              onTap:(){if(widget.onCreateInvoice!=null)widget.onCreateInvoice!(o);},
                              child:Container(
                                padding:const EdgeInsets.all(6),
                                decoration:BoxDecoration(
                                  color:T.accent.withOpacity(0.12),
                                  borderRadius:BorderRadius.circular(7)),
                                child:Icon(Icons.receipt_long_outlined,size:16,color:T.accent))),
                          ]),
                          const SizedBox(height:8),
                          // Row 2: avatar + customer name + garment
                          Row(crossAxisAlignment:CrossAxisAlignment.center,children:[
                            Container(width:46,height:46,decoration:BoxDecoration(gradient:_ag(i),shape:BoxShape.circle),
                              child:Center(child:Text((o.customerName?.isNotEmpty == true ? o.customerName! : '?')[0].toUpperCase(),
                                style:GoogleFonts.prata(fontSize:22,fontWeight:FontWeight.w400,color:Colors.white)))),
                            const SizedBox(width:10),
                            Expanded(child:Column(crossAxisAlignment:CrossAxisAlignment.start,children:[
                              Text(o.customerName??'Unknown',style:T.body.copyWith(fontSize:17,fontWeight:FontWeight.w700)),
                              Text(o.description,style:T.bodySm.copyWith(fontSize:13),maxLines:1,overflow:TextOverflow.ellipsis),])),
                            // ── Payment column ──
                            Column(crossAxisAlignment:CrossAxisAlignment.end,children:[
                              Text(_fmt.format(o.totalAmount),
                                style:GoogleFonts.prata(fontSize:20,fontWeight:FontWeight.w400,color:T.text)),
                              const SizedBox(height:5),
                              // Balance badge — prominent, color-coded
                              if(o.balanceAmount > 0)
                                Container(
                                  padding:const EdgeInsets.symmetric(horizontal:9,vertical:4),
                                  decoration:BoxDecoration(
                                    color:T.danger.withOpacity(0.1),
                                    borderRadius:BorderRadius.circular(6),
                                    border:Border.all(color:T.danger.withOpacity(0.35),width:1)),
                                  child:Text('DUE ${_fmt.format(o.balanceAmount)}',
                                    style:TextStyle(fontSize:12,fontWeight:FontWeight.w800,letterSpacing:0.5,color:T.danger)))
                              else if(o.advanceAmount > 0)
                                Container(
                                  padding:const EdgeInsets.symmetric(horizontal:9,vertical:4),
                                  decoration:BoxDecoration(
                                    color:T.success.withOpacity(0.1),
                                    borderRadius:BorderRadius.circular(6),
                                    border:Border.all(color:T.success.withOpacity(0.35),width:1)),
                                  child:const Text('PAID',
                                    style:TextStyle(fontSize:12,fontWeight:FontWeight.w800,letterSpacing:0.5,color:T.success)))
                              else
                                Container(
                                  padding:const EdgeInsets.symmetric(horizontal:9,vertical:4),
                                  decoration:BoxDecoration(
                                    color:T.warning.withOpacity(0.1),
                                    borderRadius:BorderRadius.circular(6),
                                    border:Border.all(color:T.warning.withOpacity(0.35),width:1)),
                                  child:const Text('NO ADV',
                                    style:TextStyle(fontSize:12,fontWeight:FontWeight.w800,letterSpacing:0.5,color:T.warning))),
                            ]),
                          ]),
                          // Stage progress bar
                          const SizedBox(height:10),
                          Row(children:List.generate(C.statuses.length,(j)=>Expanded(
                            child:Container(margin:const EdgeInsets.symmetric(horizontal:1.5),height:3,
                              decoration:BoxDecoration(color:j<=ci?sc:T.surface,borderRadius:BorderRadius.circular(2)))))),
                        ])),
                    ),
                  ),
                ));
              }))),
    ]),
    floatingActionButton:FloatingActionButton(onPressed:_newOrder,
      child:const Icon(Icons.add_rounded,size:22)));
  }
}

// ─── HELPER WIDGETS ─────────────────────────────────────────────────────────

class _DetailSection extends StatelessWidget {
  final String title;
  final Widget child;
  const _DetailSection({required this.title, required this.child});

  @override
  Widget build(BuildContext context) => Container(
    padding: const EdgeInsets.all(14),
    decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      Text(title.toUpperCase(), style: TextStyle(fontSize: 11, fontWeight: FontWeight.w700, letterSpacing: 0.8, color: T.text3)),
      const SizedBox(height: 6),
      child,
    ]));
}

class _PayRow extends StatelessWidget {
  final String label, value;
  final Color color;
  final bool bold;
  const _PayRow(this.label, this.value, this.color, {this.bold = false});

  @override
  Widget build(BuildContext context) => Row(
    mainAxisAlignment: MainAxisAlignment.spaceBetween,
    children: [
      Text(label, style: T.body.copyWith(color: T.text2, fontSize: 14)),
      Text(value, style: T.body.copyWith(
        color: color,
        fontWeight: bold ? FontWeight.w700 : FontWeight.w500,
        fontSize: bold ? 19 : 16)),
    ]);
}

class _DetailPhotoThumb extends StatelessWidget {
  final String label;
  final String url;
  final VoidCallback onTap;
  const _DetailPhotoThumb({required this.label, required this.url, required this.onTap});

  @override
  Widget build(BuildContext context) => GestureDetector(
    onTap: onTap,
    child: Column(crossAxisAlignment: CrossAxisAlignment.start, children: [
      ClipRRect(
        borderRadius: BorderRadius.circular(T.rSm),
        child: AspectRatio(
          aspectRatio: 1,
          child: Image.network(url, fit: BoxFit.cover,
            errorBuilder: (_, __, ___) => Container(
              color: T.surface,
              child: Icon(Icons.broken_image_rounded, color: T.text3)),
            loadingBuilder: (_, child, progress) => progress == null ? child : Container(
              color: T.surface,
              child: const Center(child: SizedBox(width: 18, height: 18,
                child: CircularProgressIndicator(strokeWidth: 2)))),
          ))),
      const SizedBox(height: 6),
      Text(label, style: T.bodySm.copyWith(fontSize: 12)),
    ]));
}

// ─── ORDER PHOTO PICKER WIDGETS ─────────────────────────────────────────────

class _OrderPhotoTile extends StatelessWidget {
  final String label;
  final IconData icon;
  final String? url;
  final bool uploading;
  final VoidCallback onTap;
  final VoidCallback onRemove;
  final double height;
  const _OrderPhotoTile({
    required this.label, required this.icon, required this.url,
    required this.uploading, required this.onTap, required this.onRemove,
    this.height = 120,
  });

  @override
  Widget build(BuildContext context) {
    final hasPhoto = url != null && url!.isNotEmpty;
    return GestureDetector(
      onTap: uploading ? null : onTap,
      child: Container(
        height: height,
        clipBehavior: Clip.antiAlias,
        decoration: BoxDecoration(
          color: T.card,
          borderRadius: BorderRadius.circular(T.rMd),
          border: Border.all(color: T.border),
          image: hasPhoto ? DecorationImage(image: NetworkImage(url!), fit: BoxFit.cover) : null,
        ),
        child: Stack(children: [
          if (!hasPhoto)
            Center(
              child: Column(mainAxisSize: MainAxisSize.min, children: [
                Icon(icon, size: 26, color: T.text3),
                const SizedBox(height: 6),
                Text(label, textAlign: TextAlign.center, style: T.bodySm.copyWith(fontSize: 12, fontWeight: FontWeight.w600)),
                const SizedBox(height: 2),
                Text('Tap to add', style: T.bodySm.copyWith(fontSize: 11, color: T.text3)),
              ]),
            ),
          if (hasPhoto) ...[
            Positioned(left: 0, right: 0, bottom: 0,
              child: Container(
                padding: const EdgeInsets.symmetric(vertical: 5),
                color: Colors.black.withOpacity(0.45),
                child: Text(label, textAlign: TextAlign.center,
                  style: const TextStyle(color: Colors.white, fontSize: 11, fontWeight: FontWeight.w600)))),
            Positioned(top: 6, right: 6,
              child: GestureDetector(
                onTap: onRemove,
                child: Container(
                  padding: const EdgeInsets.all(4),
                  decoration: BoxDecoration(color: Colors.black.withOpacity(0.5), shape: BoxShape.circle),
                  child: const Icon(Icons.close_rounded, size: 16, color: Colors.white)))),
          ],
          if (uploading)
            Positioned.fill(
              child: Container(
                color: Colors.black.withOpacity(0.35),
                child: const Center(
                  child: SizedBox(width: 22, height: 22,
                    child: CircularProgressIndicator(strokeWidth: 2.4, color: Colors.white))))),
        ]),
      ),
    );
  }
}

class _PhotoOption extends StatelessWidget {
  final IconData icon;
  final Color color;
  final String label;
  final VoidCallback onTap;
  const _PhotoOption({required this.icon, required this.color, required this.label, required this.onTap});

  @override
  Widget build(BuildContext context) => InkWell(
    onTap: onTap,
    borderRadius: BorderRadius.circular(T.rMd),
    child: Container(
      padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 14),
      decoration: BoxDecoration(color: T.card, borderRadius: BorderRadius.circular(T.rMd), boxShadow: T.shadowCard),
      child: Row(children: [
        Container(width: 44, height: 44,
          decoration: BoxDecoration(color: color.withOpacity(0.1), borderRadius: BorderRadius.circular(10)),
          child: Icon(icon, size: 22, color: color)),
        const SizedBox(width: 14),
        Expanded(child: Text(label, style: T.body.copyWith(fontWeight: FontWeight.w600, fontSize: 16))),
        Icon(Icons.chevron_right_rounded, size: 18, color: T.text3),
      ]),
    ),
  );
}
