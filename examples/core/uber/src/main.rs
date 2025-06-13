#![cfg(all(target_os = "android", target_arch = "aarch64"))]
#![recursion_limit = "256"]

use frida::{DeviceManager, Frida, Message, ScriptHandler, ScriptOption, ScriptRuntime, SpawnOptions};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use base64::{engine::general_purpose, Engine};
use serde::Serialize;
use serde_json::{json, Value};
use uuid::Uuid;
use rand::{random, Rng};
use hex;
use reqwest::Url;

static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static COLLECT_DATA: LazyLock<Mutex<CollectData>> = LazyLock::new(||{Mutex::new(CollectData::default())});

#[derive(Default,Serialize)]
struct CollectData {
    register_url: Option<String>,
    code_verifier: Option<String>,
}





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
                let challenge = this.a.apply(this,arguments);
                console.log("chanllenge "+challenge);
                console.log("verifier "+ arguments[0]);
                return challenge;
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
                   println!("[*] collect url {}",log.payload);
                   COLLECT_DATA.lock().unwrap().register_url = Some(raw_data[1].to_string());
               }else if raw_data[0].to_string() == "verifier" {
                   println!("[*] collect verifier {}",log.payload);
                   COLLECT_DATA.lock().unwrap().code_verifier = Some(raw_data[1].to_string());
               }else {
                   println!("[*] Unknown log {}", log.payload);
               }

           },
           _ =>{
               println!("[*] Unknown message");
               println!("{:?}", message)
           }
       }

        if COLLECT_DATA.lock().unwrap().is_complete() {
            let reg_url = COLLECT_DATA.lock().unwrap().register_url.clone().unwrap();

            let mut first_party_client_id = String::new();
            let mut app_device_id = String::new();
            let mut uber_cold_launch_id = String::new();
            for (key,value) in Url::parse(&reg_url).unwrap().query_pairs() {
                if key == "firstPartyClientID" {
                    first_party_client_id = value.to_string();
                }else if key == "app_url" {
                    for (key1,value1) in Url::parse(&reg_url).unwrap().query_pairs() {
                        if key1 == "x-uber-app-device-id" {
                            app_device_id = value1.to_string();
                        }else if key1 == "x-uber-cold-launch-id" {
                            uber_cold_launch_id = value1.to_string();
                        }
                    }
                }
            }

            let mut pack_data:Value = gen_request(&*first_party_client_id, &*app_device_id, &*uber_cold_launch_id);
            pack_data["register_url"] = json!(reg_url);
            pack_data["pack1"]["body"]["formContainerAnswer"]["formAnswer"]["screenAnswers"][0]["fieldAnswers"][1]["codeVerifier"] = json!(COLLECT_DATA.lock().unwrap().code_verifier.clone().unwrap().to_string());

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

pub fn gen_request(first_party_client_id:&str, app_device_id:&str, cold_launch_id:&str) -> Value {
    let mut rng = rand::rng();
    let uber_request_uuid = Uuid::new_v4().to_string();
    let drm_bytes: [u8; 32] = random();
    let drm_id = hex::encode_upper(drm_bytes).to_uppercase();
    let user_session_id = Uuid::new_v4().to_string();
    let call_uuid = Uuid::new_v4().to_string();
    let device_id_byte: [u8; 32] = random();
    let uber_device_id = hex::encode(device_id_byte);
    let network_request_uuid = Uuid::new_v4().to_string();
    let device_epoch = format!("{}{}",SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("Time went backwards")
        .as_millis() as u64,rng.random_range(1000..9999));
    // let uberctx_cold_launch_id = Uuid::new_v4().to_string();
    let uber_client_session = Uuid::new_v4().to_string();
    let uber_id = Uuid::new_v4().to_string();
    let state_token = Uuid::new_v4().to_string();

    let android_id_bytee:[u8;8] = rng.random();
    let android_id = hex::encode(android_id_bytee);
    let google_ad_id = Uuid::new_v4().to_string();
    let google_ad_set_id = Uuid::new_v4().to_string();
    let install_uuid = Uuid::new_v4().to_string();
    let pref_id = Uuid::new_v4().to_string();
    let uuid_id = Uuid::new_v3(&Uuid::NAMESPACE_DNS, pref_id.as_bytes()).to_string();


    let device_data_template: Value = json!({
        "androidId": android_id,
        "batteryLevel": 0.65,
        "batteryStatus": "unplugged",
        "carrier": "T-Mobile",
        "carrierMcc": "310",
        "carrierMnc": "260",
        "course": 90,
        "cpuAbi": ", arm64-v8a",
        "deviceAltitude": 0,
        "deviceIds": {
            "androidId": android_id,
            "appDeviceId": app_device_id,
            "drmId":drm_id,
            "googleAdvertisingId": google_ad_id,
            "googleAppSetId": google_ad_set_id,
            "installationUuid": install_uuid,
            "perfId": pref_id,
            "udid": uuid_id
        },
        "deviceLatitude": 22.378755,
        "deviceLongitude": 100.5649717,
        "deviceModel": "sdk_gphone64_arm64",
        "deviceOsName": "Android",
        "deviceOsVersion": "12",
        "emulator": true,
        "epoch": {
            "value": device_epoch,
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
        "wifiConnected": true});

        let json_template: Value = json!({
        "register_url":"",
        "pack1":{
            "url":"https://cn-geo1.uber.com/rt/silk-screen/submit-form",
            "headers":{
              "User-Agent": "Cronet/119.0.6045.31@c76b9b6a",
              "Content-Type": "application/json",
              "x-uber-device-mobile-iso2": "CN",
              "x-uber-drm-id": drm_id,
              "x-uber-device": "android",
              "x-uber-device-language": "zh_CN",
              "x-uber-device-os": "12",
              "x-uber-device-sdk": "31",
              "x-uber-request-uuid": uber_request_uuid,
              "x-uber-client-user-session-id": user_session_id,
              "x-uber-client-version": "4.575.10001",
              "x-uber-session-swap-mobile": "TRUE",
              "x-uber-device-manufacturer": "redroid",
              "x-uber-device-width-pixel": "720",
              "x-uber-call-uuid": call_uuid,
              "x-uber-device-id": uber_device_id,
              "x-uber-device-model": "redroid12_arm64",
              "x-uber-device-height-pixel": "1184",
              "uberctx-mobile-initiated": "true",
              "x-uber-app-variant": "",
              "uberctx-client-network-request-uuid": network_request_uuid,
              "x-uber-session-enabled": "TRUE",
              "x-uber-device-epoch": device_epoch,
              "x-uber-session": "eyJ1c2VyX3Nlc3Npb24iOiJaWGxLZWxwWVRucGhWemwxV0RKc2EwbHFjRGRKYmxZeFlWZFJhVTl1YzJsa2JVWnpaRmRWYVU5cFNYZE9SMGt4V1hwTk5FOURNSGROVjFKcVRGUlNiRTE2UVhSUFZFcHNXWGt4YkZsNldYbE9WRWswVDFSck5FMUVTV2xtV0RCelNXMVdOR05IYkhsYVdFNW1XVmhSYVU5dWMybGtiVVp6WkZkVmFVOXFSVE5PUkd0M1RVUnJlazU2WXpCTmFrWTVURU5LYW1OdFZtaGtSMVpyV0RKR01FbHFjRGRKYmxwb1lraFdiRWxxYjNoT2VsRTFUVVJCTTA1VVl6Tk9SRWw0Wmxnd1BRPT0iLCJjb29raWVfZXhwaXJlc19hdCI6eyJ2YWx1ZSI6MTc0OTAwNzU5NzMxN30sImNvb2tpZV9jcmVhdGVkX2F0Ijp7InZhbHVlIjoxNzQ5MDA3NTg3MzE3fSwiYWN0aW9uIjoyfQ",
              "uberctx-cold-launch-id": cold_launch_id,
              "uberctx-is-admin": "null",
              "x-uber-client-id": "com.ubercab",
              "x-uber-app-lifecycle-state": "foreground",
              "x-uber-device-timezone": "Asia/Shanghai",
              "x-uber-client-name": "client",
              "x-uber-client-session": uber_client_session,
              "x-uber-device-time-24-format-enabled": "0",
              "x-uber-device-scale-factor": "2.0",
              "x-uber-app-device-id": app_device_id,
              "x-uber-session-swap-bb8": "FALSE"
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
                  "deviceData": device_data_template.to_string(),
                  "firstPartyClientID": first_party_client_id,
                  "standardFlow": true
                }
              }
            }
        },
        "pack2": {
            "url": "https://cn-geo1.uber.com/rt/users/arch-signin-token",
            "headers": {
              "User-Agent": "Cronet/119.0.6045.31@c76b9b6a",
              "Content-Type": "application/json",
              "x-uber-device-mobile-iso2": "CN",
              "x-uber-drm-id": drm_id,
              "x-uber-device": "android",
              "x-uber-device-language": "zh_CN",
              "authorization": "Bearer xxxx",
              "x-uber-device-os": "12",
              "x-uber-device-sdk": "31",
              "x-uber-request-uuid": uber_request_uuid,
              "x-uber-client-user-session-id": user_session_id,
              "x-uber-client-version": "4.575.10001",
              "x-uber-session-swap-mobile": "FALSE",
              "x-uber-device-manufacturer": "redroid",
              "x-uber-device-width-pixel": "720",
              "x-uber-call-uuid": call_uuid,
              "x-uber-device-id": uber_device_id,
              "x-uber-id": uber_id,
              "x-uber-device-model": "redroid12_arm64",
              "x-uber-device-height-pixel": "1184",
              "uberctx-mobile-initiated": "true",
              "x-uber-app-variant": "",
              "x-uber-token": "no-token",
              "uberctx-client-network-request-uuid": network_request_uuid,
              "x-uber-session-enabled": "TRUE",
              "x-uber-device-epoch": device_epoch,
              "x-uber-session": "eyJ1c2VyX3Nlc3Npb24iOiJaWGxLZWxwWVRucGhWemwxV0RKc2EwbHFjRGRKYmxZeFlWZFJhVTl1YzJsa2JVWnpaRmRWYVU5cFNURmFSMFV6VDBScmQwMVRNV2xOUkZsM1RGUlJOVmxVVlhSUFJFbDRXV2t4YkU1cVVUUk9NbGw2V2tSTmVsa3lWV2xtV0RCelNXMVdOR05IYkhsYVdFNW1XVmhSYVU5dWMybGtiVVp6WkZkVmFVOXFSVE5PUkd0M1RXcFJNMDlVVVRCT2VrSTVURU5LYW1OdFZtaGtSMVpyV0RKR01FbHFjRGRKYmxwb1lraFdiRWxxYjNoT2VsRTFUVVJKZDAxNlRUUk5hazB5Wmxnd1BRPT0iLCJjb29raWVfZXhwaXJlc19hdCI6eyJ2YWx1ZSI6MTc0OTAyMzAwNDQ3Mn0sImNvb2tpZV9jcmVhdGVkX2F0Ijp7InZhbHVlIjoxNzQ5MDIyOTk0NDcyfSwiYWN0aW9uIjoyfQ",
              "uberctx-cold-launch-id": cold_launch_id,
              "uberctx-is-admin": "null",
              "x-uber-client-id": "com.ubercab",
              "x-uber-app-lifecycle-state": "foreground",
              "x-uber-device-timezone": "Asia/Shanghai",
              "x-uber-client-name": "client",
              "x-uber-client-session": uber_client_session,
              "x-uber-device-time-24-format-enabled": "0",
              "x-uber-device-scale-factor": "2.0",
              "x-uber-app-device-id": app_device_id,
              "x-uber-session-swap-bb8": "FALSE"
            },
            "body": {
              "request": {
                "stateToken": state_token,
                "nextURL": "https://xlb.uber.com",
                "allCookies": true
              }
            }
        }
    });
    json_template
}