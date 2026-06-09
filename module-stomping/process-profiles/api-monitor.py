import sys
import json
import frida

LOG_FILE = "active_telemetry.jsonl"
# TOGGLE FLAG: Set to True for Chrome/Browsers, False for Notepad++/Single apps
ENABLE_CHILD_GATING = False  

# The JavaScript instrumentation payload to inject
JS_CODE = """
const seenFunctions = new Set();
const moduleName = "wininet.dll";

function instrumentModule() {
    try {
        const targetModule = Process.getModuleByName(moduleName);
        const exports = targetModule.enumerateExports();
        
        console.log(`[+] Successfully located ${moduleName}. Instrumenting ${exports.length} exports...`);

        exports.forEach(exp => {
            try {
                Interceptor.attach(exp.address, {
                    onEnter(args) {
                        if (!seenFunctions.has(exp.name)) {
                            seenFunctions.add(exp.name);
                            send({
                                type: 'activity',
                                process_id: Process.id,
                                module_name: moduleName,
                                function_name: exp.name
                            });
                        }
                    }
                });
            } catch (err) {
                // Safely bypass forward-edge mitigation/CFG exceptions
            }
        });
    } catch (e) {
        // Retry shortly if the module isn't loaded yet
        setTimeout(instrumentModule, 50);
    }
}

instrumentModule();
"""

def on_message(message, data):
    """Callback to process and save telemetry coming out of the injected JS agent."""
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('type') == 'activity':
            log_entry = {
                "pid": payload['process_id'],
                "module": payload['module_name'],
                "function": payload['function_name']
            }
            
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
                
            print(f"[LOGGED] PID {log_entry['pid']} -> {log_entry['function']}()")
            
    elif message['type'] == 'error':
        print(f"[-] JS Error: {message['description']}")

def on_child_added(child):
    """Callback triggered automatically if child gating is active and a child spawns."""
    print(f"[+] Child Process Detected! PID: {child.pid} | Path: {child.path}")
    try:
        session = device.attach(child.pid)
        script = session.create_script(JS_CODE)
        script.on('message', on_message)
        script.load()
        device.resume(child.pid)
        print(f"[*] Successfully instrumented and resumed child PID: {child.pid}")
    except Exception as e:
        print(f"[-] Failed to instrument child PID {child.pid}: {e}")

# Initialize device manager
device = frida.get_local_device()

# Configure target binary path and flags
# TARGET_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
TARGET_PATH = r"C:\Program Files\Notepad++\notepad++.exe"
TARGET_FLAGS = [TARGET_PATH]

try:
    print(f"[*] Bootstrapping instrumentation loop for {TARGET_PATH}...")
    print(f"[*] Child Gating Status: {'ENABLED' if ENABLE_CHILD_GATING else 'DISABLED'}")
    
    # 1. Conditionally register the device-level callback
    if ENABLE_CHILD_GATING:
        device.on('child-added', on_child_added)

    # 2. Spawn the process with the configured gating flag
    pid = device.spawn(TARGET_FLAGS, child_gating=ENABLE_CHILD_GATING)
    session = device.attach(pid)
    
    # 3. Conditionally enable session-level child tracking
    if ENABLE_CHILD_GATING:
        session.enable_child_gating()
    
    # Load script into the primary parent process
    script = session.create_script(JS_CODE)
    script.on('message', on_message)
    script.load()
    
    device.resume(pid)
    print(f"[+] Root process running at PID {pid}. Press Ctrl+C to stop tracking.\n" + "="*80)
    
    sys.stdin.read()

except KeyboardInterrupt:
    print("\n[*] Terminating telemetry loop.")
    sys.exit(0)
except Exception as e:
    print(f"[-] Initialization failure: {e}")