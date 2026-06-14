import sys
import json
import frida
import argparse

def get_javascript_payload(module_name):
    """Generates the JS instrumentation code, injecting the target module name."""
    return f"""
    const seenFunctions = new Set();
    const moduleName = "{module_name}";

    function instrumentModule() {{
        try {{
            const targetModule = Process.getModuleByName(moduleName);
            const exports = targetModule.enumerateExports();
            
            console.log(`[+] Successfully located ${{moduleName}}. Instrumenting ${{exports.length}} exports...`);

            exports.forEach(exp => {{
                try {{
                    Interceptor.attach(exp.address, {{
                        onEnter(args) {{
                            if (!seenFunctions.has(exp.name)) {{
                                seenFunctions.add(exp.name);
                                send({{
                                    type: 'activity',
                                    process_id: Process.id,
                                    module_name: moduleName,
                                    function_name: exp.name
                                }});
                            }}
                        }}
                    }});
                }} catch (err) {{
                    // Safely bypass forward-edge mitigation/CFG exceptions
                }}
            }});
        }} catch (e) {{
            // Retry shortly if the module isn't loaded yet
            setTimeout(instrumentModule, 50);
        }}
    }}

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
            
            # Use the globally configured log file path
            with open(GLOBAL_LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
                
            print(f"[LOGGED] PID {log_entry['pid']} -> {log_entry['function']}()")
            
    elif message['type'] == 'error':
        print(f"[-] JS Error: {message['description']}")

def on_child_added(child):
    """Callback triggered automatically if child gating is active and a child spawns."""
    print(f"[+] Child Process Detected! PID: {child.pid} | Path: {child.path}")
    try:
        session = device.attach(child.pid)
        script = session.create_script(GLOBAL_JS_CODE)
        script.on('message', on_message)
        script.load()
        device.resume(child.pid)
        print(f"[*] Successfully instrumented and resumed child PID: {child.pid}")
    except Exception as e:
        print(f"[-] Failed to instrument child PID {child.pid}: {e}")

if __name__ == "__main__":
    # 1. Setup argument switches
    parser = argparse.ArgumentParser(description="Frida Dynamic API Monitoring Telemetry Agent")
    
    parser.add_argument(
        "-m", "--module", 
        required=True, 
        help="Name of the target DLL module to instrument (e.g., uxtheme.dll)."
    )
    
    parser.add_argument(
        "-p", "--pid", 
        type=int, 
        default=None, 
        help="Target running process ID to attach to. If omitted, defaults to spawning a fresh instance."
    )
    
    parser.add_argument(
        "-l", "--log",
        default="active_telemetry.jsonl",
        help="Path where the analytical JSONL log manifest should be saved (default: active_telemetry.jsonl)."
    )
    
    parser.add_argument(
        "--child-gating", 
        action="store_true", 
        help="Enable child gating to automatically track and instrument child processes."
    )
    
    args = parser.parse_args()
    
    # 2. Assign configuration variables from switches
    ENABLE_CHILD_GATING = args.child_gating
    TARGET_PID = args.pid
    TARGET_MODULE = args.module
    GLOBAL_LOG_FILE = args.log  # Made global for the on_message callback scope
    
    # Generate the payload string with the parameter injected
    GLOBAL_JS_CODE = get_javascript_payload(TARGET_MODULE)

    # Initialize device manager
    device = frida.get_local_device()

    # Configure fallback spawn target path and flags
    TARGET_PATH = r"C:\Program Files\Notepad++\notepad++.exe"
    TARGET_FLAGS = [TARGET_PATH]

    try:
        # Conditionally register child gating callbacks if enabled
        if ENABLE_CHILD_GATING:
            device.on('child-added', on_child_added)

        # Establish Session based on connection mode (Attach vs Spawn)
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
        print(f"[*] Targeted Evaluation Module: {TARGET_MODULE}")
        print(f"[*] Destination Log Manifest: {GLOBAL_LOG_FILE}")
        
        # Conditionally enable session-level child tracking
        if ENABLE_CHILD_GATING:
            session.enable_child_gating()
        
        # Load script into the target process session
        script = session.create_script(GLOBAL_JS_CODE)
        script.on('message', on_message)
        script.load()
        
        # Only resume if we spawned it suspended
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