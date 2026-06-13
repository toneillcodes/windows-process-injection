import sys
import json
import frida

LOG_FILE = "active_telemetry.jsonl"
# TOGGLE FLAG: Set to True for Chrome/Browsers, False for Notepad++/Single apps
ENABLE_CHILD_GATING = False  

# CONNECTION MODE: Set to a running PID (e.g., 1234) to attach, or None to spawn fresh
TARGET_PID = 10032  

# The JavaScript instrumentation payload to inject
JS_CODE = """
const seenFunctions = new Set();
const moduleName = "uxtheme.dll";

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

# Configure fallback spawn target path and flags
TARGET_PATH = r"C:\Program Files\Notepad++\notepad++.exe"
TARGET_FLAGS = [TARGET_PATH]

try:
    # 1. Conditionally register child gating callbacks if enabled
    if ENABLE_CHILD_GATING:
        device.on('child-added', on_child_added)

    # 2. Establish Session based on connection mode (Attach vs Spawn)
    if TARGET_PID is not None:
        print(f"[*] Attaching to existing process PID: {TARGET_PID}...")
        session = device.attach(TARGET_PID)
        pid = TARGET_PID
        should_resume = False
    else:
        print(f"[*] Bootstrapping fresh instance for {TARGET_PATH}...")
        pid = device.spawn(TARGET_FLAGS, child_gating=ENABLE_CHILD_GATING)
        session = device.attach(pid)
        should_resume = True

    print(f"[*] Child Gating Status: {'ENABLED' if ENABLE_CHILD_GATING else 'DISABLED'}")
    
    # 3. Conditionally enable session-level child tracking
    if ENABLE_CHILD_GATING:
        session.enable_child_gating()
    
    # Load script into the target process session
    script = session.create_script(JS_CODE)
    script.on('message', on_message)
    script.load()
    
    # 4. Only resume if we spawned it suspended
    if should_resume:
        device.resume(pid)
        print(f"[+] Root process spawned and running at PID {pid}.")
    else:
        print(f"[+] Successfully attached to running PID {pid}.")
        
    print("[*] Telemetry active. Press Ctrl+C to stop tracking.\n" + "="*80)
    sys.stdin.read()

except KeyboardInterrupt:
    print("\n[*] Terminating telemetry loop.")
    sys.exit(0)
except Exception as e:
    print(f"[-] Initialization failure: {e}")