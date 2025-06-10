#![cfg(all(target_os = "android", target_arch = "aarch64"))]

use std::ops::Deref;
use frida::{DeviceManager, Frida, Message, ScriptHandler, ScriptOption, ScriptRuntime, SpawnOptions};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::Duration;
use base64::{engine::general_purpose, Engine};
use serde::Serialize;

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
            let json = serde_json::to_string(COLLECT_DATA.deref()).unwrap();
            println!("JSON string: {}", json);
            let base64_encoded = general_purpose::STANDARD.encode(json);
            println!("Base64 encoded: {}", base64_encoded);
            let client = reqwest::blocking::Client::new();
            let params = [("upbase64", base64_encoded)];
            let response = client.get("http://8.138.196.204:8029/uberapi").query(&params).send().unwrap();

            println!("[*] Response: {:?}", response);
        }
    }
}