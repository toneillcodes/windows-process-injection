import sys
import time
import json
import frida
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By

# -----------------------------------------------------------------------------
# 1. FRIDA INSTRUMENTATION CONFIGURATION
# -----------------------------------------------------------------------------
LOG_FILE = "automated_telemetry.jsonl"
DEBUG_PORT = 9222

JS_CODE = """
const seenFunctions = new Set();
const moduleName = "uxtheme.dll"; // Change or expand this as needed

function instrumentModule() {
    try {
        const targetModule = Process.getModuleByName(moduleName);
        const exports = targetModule.enumerateExports();
        
        console.log(`[+] [Frida] Instrumenting ${exports.length} exports in ${moduleName}`);

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
                "pid": payload['process_id'],
                "module": payload['module_name'],
                "function": payload['function_name']
            }
            with open(LOG_FILE, "a", encoding="utf-8") as f:
                f.write(json.dumps(log_entry) + "\n")
            print(f"[TELEMETRY] {log_entry['module']}!{log_entry['function']}()")
    elif message['type'] == 'error':
        print(f"[-] [Frida Error]: {message['description']}")

def on_child_added(child):
    try:
        session = device.attach(child.pid)
        session.enable_child_gating()
        script = session.create_script(JS_CODE)
        script.on('message', on_message)
        script.load()
        device.resume(child.pid)
    except Exception as e:
        print(f"[-] Failed to instrument child PID {child.pid}: {e}")

# Initialize Frida Device
device = frida.get_local_device()
device.on('child-added', on_child_added)

# -----------------------------------------------------------------------------
# 2. COORDINATED SPAWN PHASE
# -----------------------------------------------------------------------------
CHROME_PATH = r"C:\Program Files\Google\Chrome\Application\chrome.exe"
CHROME_FLAGS = [
    CHROME_PATH,
    f"--remote-debugging-port={DEBUG_PORT}", # Opens the socket for Selenium
    "--no-sandbox",
    "--disable-gpu",
    "--user-data-dir=C:\\Windows\\Temp\\AutomationProfile",
    "--no-first-run"
]

print("[*] Phase 1: Spawning browser in suspended state via Frida...")
root_pid = device.spawn(CHROME_FLAGS, child_gating=True)

root_session = device.attach(root_pid)
root_session.enable_child_gating()

root_script = root_session.create_script(JS_CODE)
root_script.on('message', on_message)
root_script.load()

# Wake up the main browser engine
device.resume(root_pid)
print(f"[+] Root browser running at PID {root_pid}. Telemetry active.")

# Give the debugging port a brief second to initialize and listen
time.sleep(2)

# -----------------------------------------------------------------------------
# 3. SELENIUM ATTACH & AUTOMATION PHASE
# -----------------------------------------------------------------------------
print(f"[*] Phase 2: Connecting Selenium WebDriver to port {DEBUG_PORT}...")

chrome_options = Options()
chrome_options.add_experimental_option("debuggerAddress", f"127.0.0.1:{DEBUG_PORT}")

try:
    # Connects directly to the instance Frida just woke up
    driver = webdriver.Chrome(options=chrome_options)
    print("[+] Selenium successfully attached to the instrumented browser session.")
    print("="*80)

    # Define your automated user journey here
    target_urls = [
        "https://www.google.com",
        "https://www.wikipedia.org",
        "https://www.github.com"
    ]

    for url in target_urls:
        print(f"[*] Driving browser to: {url}")
        driver.get(url)
        time.sleep(3) # Let the page load completely to trigger resident code paths
        
        # Example interaction: find any input fields or lookups if necessary
        try:
            if "google" in url:
                search_box = driver.find_element(By.NAME, "q")
                search_box.send_keys("Windows Internals Architecture")
                search_box.submit()
                time.sleep(2)
        except Exception as inner_e:
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
    print(f"[+] Profiling complete. Structured telemetry saved to {LOG_FILE}")
    sys.exit(0)