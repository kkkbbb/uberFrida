#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use frida::{DeviceManager, Frida, Message, ScriptHandler, ScriptOption, ScriptRuntime, SpawnOptions};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;
use base64::{engine::general_purpose, Engine};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static COLLECT_DATA: LazyLock<Mutex<CollectData>> = LazyLock::new(||{Mutex::new(CollectData::default())});

#[derive(Default,Serialize)]
struct CollectData {
    register_url: Option<String>,
    code_verifier: Option<String>,
}

const JSON_TEMPLATE: &str = r#"
{
    "register_url":"",
    "pack1":{
        "url":"https://cn-geo1.uber.com/rt/silk-screen/submit-form",
        "headers":{
          "User-Agent": "Cronet/119.0.6045.31@c76b9b6a",
          "Accept": "*/*",
          "Accept-Encoding": "gzip, deflate",
          "Content-Type": "application/json",
          "x-uber-device-location-accuracy": "5.0",
          "x-uber-device-mobile-iso2": "CN",
          "x-uber-device-location-longitude": "100.5649717",
          "x-uber-device": "android",
          "x-uber-device-language": "zh_CN",
          "x-uber-device-location-altitude": "0.0",
          "x-uber-device-os": "12",
          "x-uber-device-sdk": "31",
          "x-uber-client-version": "4.575.10001",
          "x-uber-session-swap-mobile": "FALSE",
          "x-uber-device-manufacturer": "Google",
          "x-uber-device-width-pixel": "1440",
          "x-uber-device-location-speed": "0.0",
          "x-uber-device-model": "",
          "x-uber-device-height-pixel": "2872"
        },
        "body":{
          "formContainerAnswer": {
            "inAuthSessionID": "xxx",
            "formAnswer": {
              "flowType": "SIGN_IN",
              "screenAnswers": [
                {
                  "screenType": "SESSION_VERIFICATION",
                  "fieldAnswers": [
                    {
                      "fieldType": "SESSION_VERIFICATION_CODE",
                      "sessionVerificationCode": "xxx"
                    },
                    {
                      "fieldType": "CODE_VERIFIER",
                      "codeVerifier": "xxxxxxx"
                    }
                  ],
                  "eventType": "TypeVerifySession"
                }
              ],
              "deviceData": "xxxx",
              "firstPartyClientID": "zozycDbnl17oSjKXdw_x_QuNvq5wfRHq",
              "standardFlow": true
            }
          }
        }
    },
    "pack2": {
        "url": "https://cn-geo1.uber.com/rt/users/arch-signin-token",
        "headers": {
          "authorization": "xxxx",
          "uberctx-is-admin": "null",
          "x-uber-client-id": "com.ubercab",
          "x-uber-app-lifecycle-state": "foreground",
          "x-uber-device-timezone": "Asia/Shanghai",
          "x-uber-device-location-course": "90.0",
          "x-uber-client-name": "client",
          "x-uber-device-time-24-format-enabled": "0",
          "x-uber-device-scale-factor": "3.5",
          "x-uber-session-swap-bb8": "FALSE"
        },
        "body": {
          "request": {
            "stateToken": "xxxxx",
            "nextURL": "https://xlb.uber.com",
            "allCookies": true
          }
        }
    }
}
"#;

const DEVICE_DATA_TEMPLATE: &str = r#"
{
    "androidId": "959f93521cb5f5d4",
    "batteryLevel": 0.65,
    "batteryStatus": "unplugged",
    "carrier": "T-Mobile",
    "carrierMcc": "310",
    "carrierMnc": "260",
    "course": 90,
    "cpuAbi": ", arm64-v8a",
    "deviceAltitude": 0,
    "deviceIds": {
        "androidId": "959f93521cb5f5d4",
        "appDeviceId": "b7057f0a-b5ab-3239-bde2-d5d9b4f6622a",
        "drmId": "43DF21DB79C145E05E6F9B1BDEB07A1E191DAD978874B23EB85A0DED3A9CD1A9",
        "googleAdvertisingId": "f936bfb8-e03c-46be-adf0-5b7b7058699d",
        "googleAppSetId": "4a88aa18-2cd2-44a8-5dfe-bd0fc00ae6d2",
        "installationUuid": "4021a604-a347-4731-a07a-c62e94d7814c",
        "perfId": "842714B5-5E47-D904-E4B6-2F6A63511ECE",
        "udid": "cc83b5e5-0b9e-3a27-8e44-459b38bc5b67"
    },
    "deviceLatitude": 22.378755,
    "deviceLongitude": 100.5649717,
    "deviceModel": "sdk_gphone64_arm64",
    "deviceOsName": "Android",
    "deviceOsVersion": "12",
    "emulator": true,
    "epoch": {
        "value": 1749030937571
    },
    "horizontalAccuracy": 5,
    "ipAddress": "10.0.2.16",
    "libCount": 0,
    "locationServiceEnabled": true,
    "mockGpsOn": false,
    "rooted": false,
    "sourceApp": "rider",
    "specVersion": "2.0",
    "speed": 0,
    "systemTimeZone": "Asia/Shanghai",
    "version": "4.575.10001",
    "versionChecksum": "f8aa5a20c5a5d0f1802c88508a5a3c2c",
    "verticalAccuracy": 0,
    "wifiConnected": true
}
"#;

impl CollectData {
    fn is_complete(&self) -> bool {
        self.register_url.is_some() && self.code_verifier.is_some()
    }
}

fn main() {
    let script = r#"
        function enumClass(className){
            try{
                return Java.use(className)
            }catch(error){
                Java.enumerateClassLoaders({
                    onMatch: function(loader){
                        try {
                            if(loader.findClass(className)){
                                Java.classFactory.loader = loader;
                            }
                        }catch(error){}
                    },onComplete: function(){}
                })
            }
            return Java.use(className)
        }
        
        Java.perform(function(){
            Java.use("android.webkit.WebView").loadUrl.overload("java.lang.String","java.util.Map").implementation = function() {
                console.log("url "+arguments[0]);
                return this.loadUrl.apply(this,arguments);
            }
            enumClass("com.uber.identity.api.uauth.internal.helper.f").a.overload("java.lang.String").implementation = function() {
                let verifier = this.a.apply(this,arguments);
                console.log("verifier "+arguments[0]);
                return verifier;
            }
        })
    "#;
    
    let device_manager = DeviceManager::obtain(&FRIDA);
    let mut local_device = device_manager.get_local_device().unwrap();
    let pid = local_device.spawn("com.ubercab", &SpawnOptions::new()).unwrap();
    let session = local_device.attach(pid).unwrap();
    local_device.resume(pid).expect("TODO: panic message");
    

    if !session.is_detached() {
        println!("[*] Attached");

        let mut script_option = ScriptOption::new()
            .set_name("example")
            .set_runtime(ScriptRuntime::QJS);
        let mut script = session
            .create_script(script, &mut script_option)
            .unwrap();

        script.handle_message(Handler).unwrap();

        script.load().unwrap();
        println!("[*] Script loaded");

        thread::sleep(Duration::from_secs(20));
        script.unload().unwrap();
        println!("[*] Script unloaded");

        session.detach().unwrap();
        println!("[*] Session detached");
    }
    
}


struct Handler;

impl ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
       match message {
           
           Message::Log(log) => {
               let raw_data = log.payload.split(' ').collect::<Vec<&str>>();
               if raw_data[0].to_string() == "url" {
                   println!("[*] collect url");
                   COLLECT_DATA.lock().unwrap().register_url = Some(raw_data[1].to_string());
               }else if raw_data[0].to_string() == "verifier" {
                   println!("[*] collect verifier");
                   COLLECT_DATA.lock().unwrap().code_verifier = Some(raw_data[1].to_string());
               }

           },
           _ =>{
               println!("[*] Unknown message");
               println!("{:?}", message)
           }
       }

        if COLLECT_DATA.lock().unwrap().is_complete() {
            let reg_url = COLLECT_DATA.lock().unwrap().register_url.clone().unwrap();
            let mut pack_data:Value = serde_json::from_str(JSON_TEMPLATE).unwrap();
            let mut device_data:Value = serde_json::from_str(DEVICE_DATA_TEMPLATE).unwrap();
            pack_data["register_url"] = json!(reg_url);
            pack_data["pack1"]["body"]["formContainerAnswer"]["formAnswer"]["screenAnswers"][0]["fieldAnswers"][1]["codeVerifier"] = json!(COLLECT_DATA.lock().unwrap().code_verifier.clone().unwrap().to_string());
            
            device_data["deviceIds"]["installationUuid"] = json!(Uuid::new_v4().to_string());
            
            pack_data["formContainerAnswer"]["formAnswer"]["deviceData"] = json!(device_data.to_string());
            println!("JSON string: {}", pack_data.to_string());
            let base64_encoded = general_purpose::STANDARD.encode(pack_data.to_string());
            println!("Base64 encoded: {}", base64_encoded);
            let client = reqwest::blocking::Client::new();
            let params = [("upbase64", base64_encoded)];
            let response = client.get("http://8.138.196.204:8029/uberapi").query(&params).send().unwrap();

            println!("[*] Response: {:?}", response);
        }
    }
}