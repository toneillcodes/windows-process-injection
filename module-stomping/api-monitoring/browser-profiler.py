import sys
import json
import frida

LOG_FILE = "active_telemetry.jsonl"

# The JavaScript instrumentation payload to inject into EVERY process
JS_CODE = """
const seenFunctions = new Set();
const moduleName = "uxtheme.dll";

function instrumentModule() {
    try {
        // FIX: Get the concrete module instance first, then call its instance method
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
                // Safely catch forward-edge mitigation/CFG exceptions on specific pointers
            }
        });
    } catch (e) {
        // If the module isn't loaded yet, try again shortly
        setTimeout(instrumentModule, 50);
    }
}

// Kick off the tracking loop
instrumentModule();
"""

def old_on_message(message, data):
    """Callback to process telemetry coming out of the injected JS agent."""
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('type') == 'activity':
            print(f"[ACTIVE] PID {payload['process_id']} -> {payload['function_name']}() called.")
    elif message['type'] == 'error':
        print(f"[-] JS Error: {message['description']}")

def on_message(message, data):
    """Callback to process and save telemetry coming out of the injected JS agent."""
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('type') == 'activity':
            # Format the entry cleanly
            log_entry = {
                "pid": payload['process_id'],
                "module": payload['module_name'],
                "function": payload['function_name']
            }
            
            # Append immediately to the JSONL file
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
                
            print(f"[LOGGED] PID {log_entry['pid']} -> {log_entry['function']}()")
            
    elif message['type'] == 'error':
        print(f"[-] JS Error: {message['description']}")

def on_child_added(child):
    """Callback triggered automatically whenever the browser forks or spawns a child."""
    print(f"[+] Child Process Detected! PID: {child.pid} | Path: {child.path}")
    try:
        # Attach to the newly born child process
        session = device.attach(child.pid)
        script = session.create_script(JS_CODE)
        script.on('message', on_message)
        script.load()
        
        # Resume the child process now that our hooks are firmly established
        device.resume(child.pid)
        print(f"[*] Successfully instrumented and resumed PID: {child.pid}")
    except Exception as e:
        print(f"[-] Failed to instrument child PID {child.pid}: {e}")

# Initialize the local Frida device manager
device = frida.get_local_device()

# Tell the device manager to intercept all downstream child processes
device.on('child-added', on_child_added)

# 1. Add command-line flags to force a clean, independent browser tree
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
CHROME_FLAGS = [
    CHROME_PATH,
    "--no-sandbox",                # Drops sandbox restrictions so Frida can inject into children
    "--disable-gpu",               # Prevents volatile GPU process isolation loops
    "--user-data-dir=C:\\Windows\\Temp\\FridaChromeProfile", # Forces a brand new session context
    "--no-first-run",
    "--no-default-browser-check"
]

try:
    print(f"[*] Bootstrapping instrumentation loop for {CHROME_PATH}...")
    
    # Spawn using the explicit flags and enable device-level gating
    pid = device.spawn(CHROME_FLAGS, child_gating=True)
    session = device.attach(pid)
    
    # 2. CRITICAL: Enable session-level child gating explicitly
    session.enable_child_gating() # Tells Windows to track CreateProcessInternalW
    
    script = session.create_script(JS_CODE)
    script.on('message', on_message)
    script.load()
    
    device.resume(pid)
    print(f"[+] Root process running at PID {pid}. Gating active. Press Ctrl+C to stop tracking.\n" + "="*80)
    
    sys.stdin.read()

except KeyboardInterrupt:
    print("\n[*] Terminating telemetry loop. Processing dormancy baselines...")
    sys.exit(0)
except Exception as e:
    print(f"[-] Initialization failure: {e}")