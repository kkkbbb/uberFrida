#![cfg(all(target_os = "android", target_arch = "aarch64"))]
#![recursion_limit = "256"]

use frida::{DeviceManager, Frida, Message, ScriptHandler, ScriptOption, ScriptRuntime, SpawnOptions};
use std::sync::{LazyLock, Mutex};
use std::thread;
use std::time::{Duration};


static FRIDA: LazyLock<Frida> = LazyLock::new(|| unsafe { Frida::obtain() });
static IS_SUCCESS: LazyLock<Mutex<bool>> = LazyLock::new(||{Mutex::new(false)});

fn main() {
    let script = r#"
        Interceptor.attach(Module.findExportByName("libdrm.so","drmGetDevices2"), {
            onEnter: function(args) {

            },
            onLeave: function(retval) {
                console.log("drmGetDevices2 called with args:", retval);
                retval.replace(0);
            }
        });
    "#;
    
    let device_manager = DeviceManager::obtain(&FRIDA);
    let mut local_device = device_manager.get_local_device().unwrap();
    let pid = local_device.spawn("com.vlite.unittest", &SpawnOptions::new()).unwrap();
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

        thread::sleep(Duration::from_secs(5));
        
        script.unload().unwrap();
        println!("[*] Script unloaded");

        session.detach().unwrap();
        println!("[*] Session detached");
    }
    
}


struct Handler;

impl ScriptHandler for Handler {
    fn on_message(&mut self, message: &Message, _data: Option<Vec<u8>>) {
       println!("[*] Message: {:?}", message);
    }
}