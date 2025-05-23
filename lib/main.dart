import 'dart:async';
import 'dart:io';

import 'package:crossdrop/window/platform_menu_bar.dart';
import 'package:flutter/material.dart';
import 'package:macos_ui/macos_ui.dart';
import 'package:provider/provider.dart';
import 'package:shared_preferences/shared_preferences.dart';
import 'package:window_manager/window_manager.dart';
import 'package:device_info_plus/device_info_plus.dart';
import 'package:system_tray/system_tray.dart';

import 'theme.dart';

class AppConfig {
  static String get name => 'CrossDrop';
}

void main() async {
  WidgetsFlutterBinding.ensureInitialized();
  await windowManager.ensureInitialized();

  WindowOptions windowOptions = WindowOptions(
    center: true,
    backgroundColor: Colors.transparent,
    skipTaskbar: false,
    windowButtonVisibility: true,
    minimumSize: const Size(400, 250),
    maximumSize: const Size(800, 600),
    alwaysOnTop: true,
    title: AppConfig.name,
  );

  windowManager.waitUntilReadyToShow(windowOptions, () async {
    await windowManager.hide();
  });

  // await const MacosWindowUtilsConfig(
  //   toolbarStyle: NSWindowToolbarStyle.unified,
  // ).apply();

  runApp(const App());
}

class App extends StatefulWidget {
  const App({Key? key}) : super(key: key);

  @override
  State<App> createState() => _AppState();
}

class _AppState extends State<App> {
  final TextEditingController _deviceNameController = TextEditingController();

  final SystemTray _systemTray = SystemTray();
  final Menu menu = Menu();

  @override
  void initState() {
    super.initState();
    initSystemTray();
    initDeviceNameController();
  }

  @override
  void dispose() {
    super.dispose();
    _deviceNameController.dispose();
  }

  Future<void> initSystemTray() async {
    String path = Platform.isWindows ? 'assets/icons/system_tray_icon.ico' : 'assets/icons/system_tray_icon.png';

    // We first init the systray menu and then add the menu entries
    await _systemTray.initSystemTray(iconPath: path, toolTip: 'CrossDrop: Nearby Share for all platforms');

    // handle system tray event
    _systemTray.registerSystemTrayEventHandler((eventName) {
      if (eventName == kSystemTrayEventClick) {
        Platform.isWindows ? windowManager.show() : _systemTray.popUpContextMenu();
      } else if (eventName == kSystemTrayEventRightClick) {
        Platform.isWindows ? _systemTray.popUpContextMenu() : windowManager.show();
      }
    });

    await menu.buildFrom([
      MenuItemLabel(label: 'Show', onClicked: (menuItem) => windowManager.show()),
      MenuItemLabel(label: 'Hide', onClicked: (menuItem) => windowManager.hide()),
      MenuItemLabel(
          label: 'Exit',
          onClicked: (menuItem) {
            windowManager.close();
            exit(0);
          }),
    ]);

    _systemTray.setContextMenu(menu);
  }

  Future<void> initDeviceNameController() async {
    // Get deviceName from SharedPreferences and device name from device_info_plus
    // If text in controller is empty, set to deviceName from SharedPreferences if it exists and is not empty, otherwise set to device name from device_info_plus
    SharedPreferences.getInstance().then((prefs) {
      String deviceName = prefs.getString('deviceName') ?? '';
      if (deviceName.isEmpty) {
        DeviceInfoPlugin deviceInfo = DeviceInfoPlugin();
        if (Platform.isIOS) {
          deviceInfo.iosInfo.then((info) {
            deviceName = info.name;
            SharedPreferences.getInstance().then((prefs) {
              prefs.setString('deviceName', deviceName);
              setState(() {
                _deviceNameController.text = deviceName;
              });
            });
          });
        } else if (Platform.isMacOS) {
          deviceInfo.macOsInfo.then((info) {
            deviceName = info.computerName;
            SharedPreferences.getInstance().then((prefs) {
              prefs.setString('deviceName', deviceName);
              setState(() {
                _deviceNameController.text = deviceName;
              });
            });
          });
        } else if (Platform.isLinux) {
          deviceInfo.linuxInfo.then((info) {
            deviceName = info.prettyName;
            SharedPreferences.getInstance().then((prefs) {
              prefs.setString('deviceName', deviceName);
              setState(() {
                _deviceNameController.text = deviceName;
              });
            });
          });
        }
      } else {
        setState(() {
          _deviceNameController.text = deviceName;
        });
      }
    });
  }

  @override
  Widget build(BuildContext context) {
    return ChangeNotifierProvider(
      create: (_) => AppTheme(),
      builder: (context, _) {
        final appTheme = context.watch<AppTheme>();
        return Platform.isMacOS
            ? AppMacos(
                appTheme: appTheme,
                deviceNameController: _deviceNameController,
              )
            : AppMaterial(
                appTheme: appTheme,
                deviceNameController: _deviceNameController,
              );
      },
    );
  }
}

class AppMaterial extends StatelessWidget {
  const AppMaterial({
    super.key,
    required this.appTheme,
    required TextEditingController deviceNameController,
  }) : _deviceNameController = deviceNameController;

  final AppTheme appTheme;
  final TextEditingController _deviceNameController;

  @override
  Widget build(BuildContext context) {
    return MaterialApp(
      title: AppConfig.name,
      theme: ThemeData.light(),
      darkTheme: ThemeData.dark(),
      themeMode: appTheme.mode,
      debugShowCheckedModeBanner: false,
      home: Scaffold(
        appBar: AppBar(
          title: Text(
            AppConfig.name,
            textAlign: TextAlign.center,
          ),
          centerTitle: true,
        ),
        body: SingleChildScrollView(
          padding: const EdgeInsets.all(20),
          child: Column(
            children: [
              SizedBox(
                width: 300.0,
                child: TextField(
                  decoration: const InputDecoration(
                    labelText: 'Device name',
                  ),
                  maxLines: 1,
                  controller: _deviceNameController,
                  onEditingComplete: () async {
                    SharedPreferences prefs = await SharedPreferences.getInstance();
                    prefs.setString('deviceName', _deviceNameController.text);
                  },
                ),
              ),
            ],
          ),
        ),
      ),
    );
  }
}

class AppMacos extends StatelessWidget {
  const AppMacos({
    super.key,
    required this.appTheme,
    required TextEditingController deviceNameController,
  }) : _deviceNameController = deviceNameController;

  final AppTheme appTheme;
  final TextEditingController _deviceNameController;

  @override
  Widget build(BuildContext context) {
    return MacosApp(
      title: AppConfig.name,
      theme: MacosThemeData.light(),
      darkTheme: MacosThemeData.dark(),
      themeMode: appTheme.mode,
      debugShowCheckedModeBanner: false,
      home: AppPlatformMenuBar(
        child: MacosScaffold(
          toolBar: ToolBar(
            title: Text(
              AppConfig.name,
              textAlign: TextAlign.center,
            ),
            centerTitle: true,
          ),
          children: [
            ContentArea(
              builder: (context, scrollController) {
                return SingleChildScrollView(
                  padding: const EdgeInsets.all(20),
                  child: Column(
                    children: [
                      SizedBox(
                        width: 300.0,
                        child: MacosTextField(
                          placeholder: 'Device name',
                          maxLines: 1,
                          controller: _deviceNameController,
                          onEditingComplete: () async {
                            SharedPreferences prefs = await SharedPreferences.getInstance();
                            prefs.setString('deviceName', _deviceNameController.text);
                          },
                        ),
                      ),
                    ],
                  ),
                );
              },
            ),
          ],
        ),
      ),
    );
  }
}
