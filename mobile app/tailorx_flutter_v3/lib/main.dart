import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import 'package:supabase_flutter/supabase_flutter.dart';
import 'utils/theme.dart';
import 'utils/constants.dart';
import 'screens/splash_screen.dart';

void main() async {
  WidgetsFlutterBinding.ensureInitialized();

  await Supabase.initialize(url: C.supabaseUrl, anonKey: C.supabaseKey);

  SystemChrome.setSystemUIOverlayStyle(const SystemUiOverlayStyle(
    statusBarColor: Colors.transparent,
    statusBarIconBrightness: Brightness.light,
    systemNavigationBarColor: Colors.white,
    systemNavigationBarIconBrightness: Brightness.dark));

  runApp(const TailorXApp());
}

class TailorXApp extends StatelessWidget {
  const TailorXApp({super.key});
  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: 'TailorX',
      debugShowCheckedModeBanner: false,
      theme: T.theme,
      home: const SplashScreen(),
    );
  }
}
