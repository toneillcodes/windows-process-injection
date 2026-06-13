import os
import sys
import time
import json
import frida
import threading
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

# -----------------------------------------------------------------------------
# 1. FRIDA INSTRUMENTATION CONFIGURATION
# -----------------------------------------------------------------------------
LOG_FILE = "automated_telemetry.jsonl"
DEBUG_PORT = 9222

# const moduleName = "Windows.System.Launcher.dll";

JS_CODE = """
const seenFunctions = new Set();
const moduleName = "uxtheme.dll";

function instrumentModule() {
    try {
        const targetModule = Process.getModuleByName(moduleName);
        const exports = targetModule.enumerateExports();
        
        console.log(`[+] [Frida] Instrumenting ${exports.length} exports in ${moduleName}`);

        exports.forEach(exp => {
            try {
                Interceptor.attach(exp.address, {
                    onEnter(args) {
                        let contextualName = exp.name;

                        // SPECIAL HANDLING FOR STRATEGY A:
                        if (exp.name === "DllGetActivationFactory" || exp.name === "DllGetClassObject") {
                            try {
                                const hString = args[0];
                                const stringPtr = Memory.readPointer(hString.add(Process.pointerSize === 8 ? 16 : 8));
                                const className = Memory.readUtf16String(stringPtr);
                                
                                if (className) {
                                    contextualName += ` (${className})`;
                                }
                            } catch (strErr) {
                                contextualName += " (Unknown Class String)";
                            }
                        }

                        if (!seenFunctions.has(contextualName)) {
                            seenFunctions.add(contextualName);
                            send({
                                type: 'activity',
                                timestamp: new Date().toISOString(),
                                process_id: Process.id,
                                process_name: Process.mainModule.name,
                                module_name: moduleName,
                                function_name: contextualName
                            });
                        }
                    }
                });
            } catch (err) {
                // Skip protected/non-executable pointers safely
            }
        });
    } catch (e) {
        setTimeout(instrumentModule, 50);
    }
}

instrumentModule();
"""

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if payload.get('type') == 'activity':
            log_entry = {
                "timestamp": payload.get('timestamp'),
                "pid": payload['process_id'],
                "process_name": payload['process_name'],
                "module": payload['module_name'],
                "function": payload['function_name']
            }
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
            print(f"[TELEMETRY] {log_entry['module']}!{log_entry['function']}()")
    elif message['type'] == 'error':
        print(f"[-] [Frida Error]: {message['description']}")

def on_child_added(child):
    proc_path = child.path.lower() if child.path else ""
    proc_name = os.path.basename(proc_path)
    
    if "crashpad" in proc_name or "watcher" in proc_name or "broker" in proc_name:
        print(f"[!] Skipping restricted utility process: PID {child.pid} ({proc_name})")
        try:
            device.resume(child.pid)
        except Exception:
            pass
        return

    print(f"[+] Noticed child process PID {child.pid} ({proc_name}), instrumenting...")
    try:
        session = device.attach(child.pid)
        session.enable_child_gating()
        
        script = session.create_script(JS_CODE)
        script.on('message', on_message)
        script.load()
        
        device.resume(child.pid) 
        print(f"[+] Successfully resumed child PID {child.pid}")
    except frida.PermissionDeniedError:
        print(f"[-] Permission Denied injecting into PID {child.pid}. Resuming cleanly.")
        try:
            device.resume(child.pid)
        except Exception:
            pass
    except Exception as e:
        print(f"[-] Failed to handle child PID {child.pid}: {e}")
        try:
            device.resume(child.pid)
        except Exception:
            pass

# Initialize Frida Device
device = frida.get_local_device()
device.on('child-added', on_child_added)

# -----------------------------------------------------------------------------
# 2. COORDINATED SPAWN PHASE
# -----------------------------------------------------------------------------
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
CHROME_FLAGS = [
    CHROME_PATH,
    f"--remote-debugging-port={DEBUG_PORT}", 
    "--no-sandbox",
    "--disable-gpu",
    "--user-data-dir=C:\\Windows\\Temp\\AutomationProfile",
    "--no-first-run",
    "--disable-site-isolation-trials",
    "--disable-features=RendererCodeIntegrity",
    "--disable-dev-shm-usage",
    "--disable-extensions"
]

print("[*] Phase 1: Spawning browser in suspended state via Frida...")
root_pid = device.spawn(CHROME_FLAGS, child_gating=True)

root_session = device.attach(root_pid)
root_session.enable_child_gating()

root_script = root_session.create_script(JS_CODE)
root_script.on('message', on_message)
root_script.load()

device.resume(root_pid)
print(f"[+] Root browser running at PID {root_pid}. Telemetry active.")
time.sleep(2)

# -----------------------------------------------------------------------------
# 3. ASYNCHRONOUS SELENIUM WORKER
# -----------------------------------------------------------------------------
def run_selenium_automation():
    print(f"[*] Phase 2: Connecting Selenium WebDriver to port {DEBUG_PORT}...")
    
    chrome_options = Options()
    chrome_options.add_experimental_option("debuggerAddress", f"127.0.0.1:{DEBUG_PORT}")
    
    driver = None
    # Retry mechanism to ensure CDP port is fully open before connecting
    for attempt in range(5):
        try:
            driver = webdriver.Chrome(options=chrome_options)
            break
        except Exception:
            time.sleep(1)

    if not driver:
        print("[-] Failed to attach Selenium to the browser debugging port after 5 attempts.")
        print("[*] Continuing main execution loop for manual testing interaction...")
        return

    try:
        print("[+] Selenium successfully attached to the instrumented browser session.")
        print("="*80)

        target_urls = [
            "https://www.npr.org",
            "https://www.slashdot.org",
            "https://www.google.com",
            "https://www.github.com",
            "https://www.tiktok.com"
        ]

        for url in target_urls:
            print(f"[*] Driving browser to: {url}")
            driver.get(url)
            time.sleep(5) 
            
            try:
                if "google" in url:
                    search_box = driver.find_element(By.NAME, "q")
                    search_box.send_keys("Windows Internals Architecture")
                    search_box.submit()
                    time.sleep(3)
            except Exception:
                pass

        print("="*80)
        print("[*] Automation sequence complete.")

    except Exception as e:
        print(f"[-] Selenium Automation error: {e}")

    finally:
        print("[*] Cleaning up handles and closing driver...")
        try:
            driver.quit()
        except:
            pass
        print(f"[+] Automated profiling steps complete. Selenium detached.")
        print(f"[*] Control handed over to manual user interaction. Logging active...")

# Spin up Selenium in its own separate thread
selenium_thread = threading.Thread(target=run_selenium_automation)
selenium_thread.daemon = True
selenium_thread.start()

print("[*] Main Frida event loop listening. Press Ctrl+C to terminate manually.")

# Keep the main thread alive dynamically by checking if our specific root PID is still alive
try:
    while True:
        try:
            running_pids = [p.pid for p in device.enumerate_processes()]
            if root_pid not in running_pids:
                print("[*] Root browser process terminated by user. Cleaning up...")
                break
        except Exception as e:
            pass
        
        time.sleep(2)

except KeyboardInterrupt:
    print("\n[*] Script execution interrupted by user.")

print(f"[+] Profiling complete. Structured telemetry saved to {LOG_FILE}")