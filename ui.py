import customtkinter as ctk
from tkinter import filedialog, messagebox
import requests
import os
import threading
import time 
import json 
import appdirs

# --- App Setup and Global Constants ---
ctk.set_appearance_mode("dark") 
ctk.set_default_color_theme("dark-blue")

# Default API Keys
CONFIG_VT_API_KEY = ""
CONFIG_HYBRID_API_KEY = ""
CONFIG_METADEFENDER_API_KEY = ""
CONFIG_ANYRUN_API_KEY = ""
CONFIG_THEME = "dark"

# Configuration Path for Auto-Save (Fixes Permission Denied Error)
APP_NAME = "BlueScannerApp"
APP_AUTHOR = "CodeGuru" 
CONFIG_DIR = appdirs.user_config_dir(APP_NAME, APP_AUTHOR) 
CONFIG_FILE_PATH = os.path.join(CONFIG_DIR, "blue_scanner_config.json") 

# External Service Endpoints 
VT_UPLOAD_URL = "https://www.virustotal.com/api/v3/files"
VT_REPORT_URL_BASE = "https://www.virustotal.com/api/v3/analyses/"
MD_BASE_URL = "https://api.metadefender.com/v4"
MD_UPLOAD_URL = f"{MD_BASE_URL}/file" 
MD_REPORT_URL_BASE = f"{MD_BASE_URL}/file/" 
HA_SUBMIT_URL = "https://www.hybrid-analysis.com/api/v2/submit/file" 
HA_REPORT_URL_BASE = "https://www.hybrid-analysis.com/api/v2/report/"
ANYRUN_SUBMIT_URL = "https://api.any.run/v1/analysis"
ANYRUN_REPORT_URL_BASE = "https://api.any.run/v1/tasks/" 

# --- Settings Window ---
class SettingsWindow(ctk.CTkToplevel):
    def __init__(self, parent_app):
        super().__init__(parent_app)
        self.parent_app = parent_app
        self.title("Settings - API Keys and Theme")
        self.geometry("550x450")
        self.transient(parent_app)
        self.resizable(False, False)
        self.grab_set() 
        self.setup_ui()

    def setup_ui(self):
        api_frame = ctk.CTkFrame(self)
        api_frame.pack(pady=10, padx=20, fill="x")

        ctk.CTkLabel(api_frame, text="VirusTotal API Key:", anchor="w").pack(pady=(10, 0), padx=10, fill="x")
        self.vt_key_entry = ctk.CTkEntry(api_frame, placeholder_text="VT Key", show='*')
        self.vt_key_entry.insert(0, self.parent_app.config_vt_api_key)
        self.vt_key_entry.pack(pady=(0, 5), padx=10, fill="x")
        
        ctk.CTkLabel(api_frame, text="Hybrid Analysis API Key:", anchor="w").pack(pady=(5, 0), padx=10, fill="x")
        self.hybrid_key_entry = ctk.CTkEntry(api_frame, placeholder_text="Hybrid Analysis Key", show='*')
        self.hybrid_key_entry.insert(0, self.parent_app.config_hybrid_api_key)
        self.hybrid_key_entry.pack(pady=(0, 5), padx=10, fill="x")

        ctk.CTkLabel(api_frame, text="MetaDefender API Key:", anchor="w").pack(pady=(5, 0), padx=10, fill="x")
        self.meta_key_entry = ctk.CTkEntry(api_frame, placeholder_text="MetaDefender Key", show='*')
        self.meta_key_entry.insert(0, self.parent_app.config_metadefender_api_key)
        self.meta_key_entry.pack(pady=(0, 5), padx=10, fill="x")

        ctk.CTkLabel(api_frame, text="ANY.RUN API Key:", anchor="w").pack(pady=(5, 0), padx=10, fill="x")
        self.anyrun_key_entry = ctk.CTkEntry(api_frame, placeholder_text="ANY.RUN Key", show='*')
        self.anyrun_key_entry.insert(0, self.parent_app.config_anyrun_api_key)
        self.anyrun_key_entry.pack(pady=(0, 10), padx=10, fill="x")

        theme_frame = ctk.CTkFrame(self)
        theme_frame.pack(pady=10, padx=20, fill="x")
        
        self.theme_switch_var = ctk.StringVar(value=self.parent_app.config_theme) 
        ctk.CTkLabel(theme_frame, text="UI Theme:").pack(side="left", padx=10)
        ctk.CTkRadioButton(theme_frame, text="Light Mode", variable=self.theme_switch_var, value="light").pack(side="left", padx=10)
        ctk.CTkRadioButton(theme_frame, text="Dark Mode", variable=self.theme_switch_var, value="dark").pack(side="left", padx=10)

        ctk.CTkButton(self, text="Save My Settings!", command=self.save_settings).pack(pady=10)

    def save_settings(self):
        self.parent_app.config_vt_api_key = self.vt_key_entry.get().strip()
        self.parent_app.config_hybrid_api_key = self.hybrid_key_entry.get().strip()
        self.parent_app.config_metadefender_api_key = self.meta_key_entry.get().strip()
        self.parent_app.config_anyrun_api_key = self.anyrun_key_entry.get().strip()
        
        self.parent_app.save_keys()
        
        new_theme = self.theme_switch_var.get()
        self.parent_app.log("Settings updated! Ready to roll.")
        
        if new_theme != self.parent_app.config_theme:
            ctk.set_appearance_mode(new_theme)
            self.parent_app.config_theme = new_theme
            self.parent_app.log(f"Switched to {new_theme.capitalize()} Theme. Looks snappy.")
        
        self.destroy()
        self.parent_app.focus_set()


# --- Main Application ---
class BlueScannerApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        self.title("Blue Scanner - The Multi-Tool File Checker")
        self.geometry("800x480") 
        
        # 1. Initialize config variables
        self.config_vt_api_key = CONFIG_VT_API_KEY
        self.config_hybrid_api_key = CONFIG_HYBRID_API_KEY
        self.config_metadefender_api_key = CONFIG_METADEFENDER_API_KEY
        self.config_anyrun_api_key = CONFIG_ANYRUN_API_KEY
        self.config_theme = CONFIG_THEME
        self.current_scanner = ctk.StringVar(value="VirusTotal") 

        # 2. CREATE THE UI (Must happen before calling self.log())
        self.setup_ui() 

        # 3. Load saved keys (This uses self.log(), which is now safe)
        self.load_keys() 
        
        # 4. Apply the loaded theme
        ctk.set_appearance_mode(self.config_theme)

        self.log("Welcome to Blue Scanner! Set your API keys in the Settings ⚙️.")

    # --- Configuration Persistence ---
    def load_keys(self):
        if not os.path.exists(CONFIG_FILE_PATH):
            return

        try:
            with open(CONFIG_FILE_PATH, 'r') as f:
                config = json.load(f)
                
                self.config_vt_api_key = config.get("vt_key", self.config_vt_api_key)
                self.config_hybrid_api_key = config.get("hybrid_key", self.config_hybrid_api_key)
                self.config_metadefender_api_key = config.get("metadefender_key", self.config_metadefender_api_key)
                self.config_anyrun_api_key = config.get("anyrun_key", self.config_anyrun_api_key)
                self.config_theme = config.get("theme", self.config_theme)

            self.log("Loaded API keys and settings from config file. 💾")
        except Exception as e:
            self.log(f"WARNING: Could not load config file. Error: {e}", is_error=True)

    def save_keys(self):
        try:
            os.makedirs(CONFIG_DIR, exist_ok=True) 
        except Exception as e:
             self.log(f"ERROR: Could not create config directory: {e}", is_error=True)
             return

        config = {
            "vt_key": self.config_vt_api_key,
            "hybrid_key": self.config_hybrid_api_key,
            "metadefender_key": self.config_metadefender_api_key,
            "anyrun_key": self.config_anyrun_api_key,
            "theme": self.config_theme
        }
        try:
            with open(CONFIG_FILE_PATH, 'w') as f:
                json.dump(config, f, indent=4)
        except Exception as e:
            self.log(f"FATAL ERROR: Could not save configuration file: {e}", is_error=True)
    
    # --- UI Setup ---
    def setup_ui(self):
        main_control_frame = ctk.CTkFrame(self, corner_radius=10)
        main_control_frame.pack(pady=10, padx=20, fill='x')
        main_control_frame.grid_columnconfigure((0, 1), weight=1)

        scanner_frame = ctk.CTkFrame(main_control_frame, corner_radius=10)
        scanner_frame.grid(row=0, column=0, padx=(10, 5), pady=10, sticky="nsew") 
        
        ctk.CTkLabel(scanner_frame, text="▶️ Choose Your Scanning Engine:", font=ctk.CTkFont(weight="bold")).pack(padx=10, pady=(10, 0))
        
        scanners = ["VirusTotal", "MetaDefender", "Hybrid Analysis", "ANY.RUN"]
        for scanner in scanners:
            rb = ctk.CTkRadioButton(scanner_frame, text=scanner, variable=self.current_scanner, value=scanner)
            rb.pack(padx=10, pady=2, anchor="w")

        button_frame = ctk.CTkFrame(main_control_frame, corner_radius=10)
        button_frame.grid(row=0, column=1, padx=(5, 10), pady=10, sticky="nsew") 
        
        self.scan_button = ctk.CTkButton(
            button_frame, 
            text="📁 Select File & START SCAN", 
            command=self.select_and_scan,
            height=60
        )
        self.scan_button.pack(padx=15, pady=(15, 5), fill="x")

        self.settings_button = ctk.CTkButton(
            button_frame, 
            text="⚙️ Setup API Keys", 
            command=self.open_settings,
            fg_color=("gray60", "gray30")
        )
        self.settings_button.pack(padx=15, pady=(5, 15), fill="x")
        
        ctk.CTkLabel(self, text="Console Output:", anchor="w").pack(padx=20, pady=(5, 0), fill="x")
        self.console = ctk.CTkTextbox(self, state='disabled', wrap='word', corner_radius=10)
        self.console.pack(padx=20, pady=(5, 20), fill='both', expand=True)
    
    # --- Utility Methods ---
    def log(self, message, is_error=False):
        time_str = time.strftime("%H:%M:%S")
        self.console.configure(state='normal')
        tag_name = "error_tag" if is_error else "normal_tag"
        color = "red" if is_error else "white" 
        if tag_name not in self.console.tag_names():
            self.console.tag_config(tag_name, foreground=color)
        self.console.insert("end", f"[{time_str}] {message}\n", tag_name)
        self.console.see("end")
        self.console.configure(state='disabled')

    def open_settings(self):
        SettingsWindow(self)

    def get_api_key(self, scanner_name):
        if scanner_name == "VirusTotal":
            return self.config_vt_api_key
        elif scanner_name == "Hybrid Analysis":
            return self.config_hybrid_api_key
        elif scanner_name == "MetaDefender":
            return self.config_metadefender_api_key
        elif scanner_name == "ANY.RUN":
            return self.config_anyrun_api_key
        return None

    # --- Scanning Dispatcher ---
    def select_and_scan(self):
        scanner_name = self.current_scanner.get()
        file_path = filedialog.askopenfilename(title="Pick a file to analyze")

        if not file_path:
            return

        api_key = self.get_api_key(scanner_name)
        if not api_key:
            messagebox.showerror("Key Missing", f"Please set the {scanner_name} API Key in Settings first. 🔑")
            self.log(f"ERROR: No key for {scanner_name}.", is_error=True)
            return

        self.log(f"Scanning '{os.path.basename(file_path)}' using **{scanner_name}**. ⏳")
        self.scan_button.configure(state="disabled", text=f"Scanning with {scanner_name}...")
        
        threading.Thread(target=self.scan_file_thread, args=(file_path, scanner_name), daemon=True).start()

    def scan_file_thread(self, file_path, scanner_name):
        try:
            if scanner_name == "VirusTotal":
                self.run_virustotal_scan(file_path)
            elif scanner_name == "MetaDefender":
                self.run_metadefender_scan(file_path)
            elif scanner_name == "Hybrid Analysis":
                self.run_hybrid_analysis_scan(file_path)
            elif scanner_name == "ANY.RUN":
                self.run_anyrun_scan(file_path)
        except Exception as e:
            self.log(f"A major error occurred: {e}", is_error=True)
            self.after(100, lambda: messagebox.showerror("Fatal Error", "The scan failed completely."))
        finally:
            self.after(100, lambda: self.scan_button.configure(state="normal", text="📁 Select File & START SCAN"))
    
    # =========================================================================
    # --- SCANNING LOGIC METHODS ---
    # =========================================================================

    def run_virustotal_scan(self, file_path):
        analysis_id = self.vt_initiate_scan(file_path)
        if analysis_id:
            self.vt_poll_for_scan_report(analysis_id)

    def vt_initiate_scan(self, file_path):
        if not os.path.exists(file_path):
            self.log(f"ERROR: File not found at {file_path}", is_error=True)
            return None

        headers = {"x-apikey": self.config_vt_api_key}
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(VT_UPLOAD_URL, headers=headers, files=files, timeout=60) 
                response.raise_for_status()

                data = response.json()
                analysis_id = data['data']['id']
                self.log(f"Upload successful. VT Analysis ID: {analysis_id}. Waiting for results...")
                return analysis_id

        except requests.exceptions.HTTPError as err:
            self.log(f"HTTP Error {err.response.status_code}: Rate limit or bad key?", is_error=True)
            return None
        except Exception as e:
            self.log(f"Unexpected error during VT upload: {e}", is_error=True)
            return None

    def vt_poll_for_scan_report(self, analysis_id):
        report_url = f"{VT_REPORT_URL_BASE}{analysis_id}"
        headers = {"x-apikey": self.config_vt_api_key}
        max_checks = 120 
        check_interval = 15 
        
        for i in range(1, max_checks + 1):
            self.log(f"Checking VT report (Attempt {i})...", is_error=False)
            try:
                response = requests.get(report_url, headers=headers, timeout=20)
                response.raise_for_status()
                report_data = response.json()
                attributes = report_data['data']['attributes']
                status = attributes.get('status', 'N/A')
                
                if status == 'completed':
                    self.vt_process_report(attributes)
                    return 
                elif status in ('queued', 'in-progress'):
                    self.log(f"Status: Still processing. Waiting {check_interval}s.")
                    time.sleep(check_interval) 
                else:
                    self.log(f"Analysis failed with status: {status}", is_error=True)
                    break
            except Exception as e:
                self.log(f"Error during VT report polling: {e}", is_error=True)
                break

        self.log("Gave up waiting for VirusTotal report.", is_error=True)

    def vt_process_report(self, attributes):
        stats = attributes.get('stats', {})
        malicious = stats.get('malicious', 0)
        undetected = stats.get('undetected', 0)
        
        self.log("--- FINAL VIRUSTOTAL REPORT ---")
        self.log(f"Analysis Status: 🎉 COMPLETED 🎉")
        self.log(f"Total Engines: {stats.get('harmless', 0) + malicious + undetected}")
        self.log(f"⚠️ MALICIOUS DETECTIONS: {malicious}", is_error=(malicious > 0))
        self.log(f"Clean/Undetected: {undetected}")
        
        if malicious > 0:
            self.after(100, lambda: messagebox.showwarning("DANGER ZONE", 
                                  f"🛑 This file is **MALICIOUS**! ({malicious} detections)"))
        else:
            self.after(100, lambda: messagebox.showinfo("ALL CLEAR", "✅ File looks clean."))


    def run_metadefender_scan(self, file_path):
        data_id = self.md_upload_file(file_path)
        if data_id:
            self.md_poll_for_scan_report(data_id)

    def md_upload_file(self, file_path):
        if not os.path.exists(file_path):
            self.log(f"ERROR: File not found at {file_path}", is_error=True)
            return None

        headers = {"apikey": self.config_metadefender_api_key,"Content-Type": "application/octet-stream"}
        try:
            with open(file_path, 'rb') as f:
                response = requests.post(MD_UPLOAD_URL, headers=headers, data=f, timeout=60)
                response.raise_for_status()

                data = response.json()
                data_id = data.get('data_id')
                
                if data_id:
                    self.log(f"Upload successful. MD Data ID: {data_id}. Waiting for scan...")
                    return data_id
                else:
                    self.log(f"MD upload failed. Response: {data}", is_error=True)
                    return None
        except requests.exceptions.HTTPError as err:
            self.log(f"HTTP Error {err.response.status_code}: Check MD API key or limits.", is_error=True)
            return None
        except Exception as e:
            self.log(f"Unexpected error during MD upload: {e}", is_error=True)
            return None

    def md_poll_for_scan_report(self, data_id):
        report_url = f"{MD_REPORT_URL_BASE}{data_id}"
        headers = {"apikey": self.config_metadefender_api_key}
        max_checks = 120 
        check_interval = 10 
        
        for i in range(1, max_checks + 1):
            self.log(f"Checking MD report status ({i})...", is_error=False)
            try:
                response = requests.get(report_url, headers=headers, timeout=20)
                response.raise_for_status()
                report_data = response.json()
                progress = report_data.get('progress_percentage', 0)
                
                if progress == 100:
                    self.md_process_report(report_data)
                    return 
                elif progress < 100:
                    self.log(f"Status: Still {progress}% done. Waiting {check_interval}s...")
                    time.sleep(check_interval) 
                else:
                    self.log(f"Analysis failed with unexpected progress: {progress}", is_error=True)
                    break
            except Exception as e:
                self.log(f"Error during MD report polling: {e}", is_error=True)
                break
        self.log("Gave up waiting for MetaDefender.", is_error=True)

    def md_process_report(self, report_data):
        scan_results = report_data.get('scan_results', {})
        overall_result = scan_results.get('scan_all_result_a', 'Not Scanned')
        malicious_count = scan_results.get('total_detected_msgs', 0)
        
        self.log("--- FINAL METADEFENDER REPORT ---")
        self.log(f"Overall Result: **{overall_result.upper()}**")
        self.log(f"⚠️ MALICIOUS DETECTIONS: {malicious_count}", is_error=(malicious_count > 0))
        
        if overall_result == "Clean" and malicious_count == 0:
            self.after(100, lambda: messagebox.showinfo("ALL CLEAR", "✅ File looks clean!"))
        elif overall_result == "Infected" or malicious_count > 0:
            self.after(100, lambda: messagebox.showwarning("DANGER ZONE", 
                                  f"🛑 This file is **{overall_result.upper()}**! ({malicious_count} detections)"))
        else:
            self.after(100, lambda: messagebox.showerror("WARNING", 
                                  f"❗ Scan finished, but the final verdict is unclear: {overall_result}"))


    def run_hybrid_analysis_scan(self, file_path):
        job_id = self.ha_upload_file(file_path)
        if job_id:
            self.ha_poll_for_scan_report(job_id)

    def ha_upload_file(self, file_path):
        if not os.path.exists(file_path):
            self.log(f"ERROR: File not found at {file_path}", is_error=True)
            return None

        headers = {"api-key": self.config_hybrid_api_key,"User-Agent": "BlueScannerApp_Client_1.0"}
        data = {'environment_id': 120, 'public': 'no','comment': 'Submitted via BlueScanner'}
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(HA_SUBMIT_URL, headers=headers, data=data, files=files, timeout=90)
                response.raise_for_status()

                data = response.json()
                job_id = data.get('job_id')
                
                if job_id:
                    self.log(f"Upload successful. HA Job ID: {job_id}. Waiting for sandbox run...")
                    return job_id
                else:
                    self.log(f"HA upload failed. Response: {data}", is_error=True)
                    return None
        except requests.exceptions.HTTPError as err:
            self.log(f"HTTP Error {err.response.status_code}: Check HA API key.", is_error=True)
            return None
        except Exception as e:
            self.log(f"Unexpected error during HA upload: {e}", is_error=True)
            return None

    def ha_poll_for_scan_report(self, job_id):
        HA_REPORT_URL = f"{HA_REPORT_URL_BASE}{job_id}/summary"
        headers = {"api-key": self.config_hybrid_api_key,"User-Agent": "BlueScannerApp_Client_1.0"}
        max_checks = 18 
        check_interval = 10 
        
        for i in range(1, max_checks + 1):
            self.log(f"Checking HA report status ({i})...", is_error=False)
            try:
                response = requests.get(HA_REPORT_URL, headers=headers, timeout=20)
                
                if response.status_code == 200:
                    report_data = response.json()
                    response_code = report_data.get('response_code')
                    
                    if response_code == 1: 
                        self.ha_process_report(report_data)
                        return
                    elif response_code == 0:
                        self.log(f"Status: Analysis not ready. Waiting {check_interval}s...")
                        time.sleep(check_interval) 
                    else:
                        self.log(f"HA poll received unexpected response code: {response_code}. Waiting {check_interval}s...")
                        time.sleep(check_interval) 

                elif response.status_code in (204, 404): 
                    self.log(f"Status: Processing... Waiting {check_interval}s...")
                    time.sleep(check_interval) 
                else:
                    response.raise_for_status()

            except Exception as e:
                self.log(f"Error during HA report polling: {e}", is_error=True)
                break

        self.log("Gave up waiting for Hybrid Analysis. Sandbox run may take longer.", is_error=True)

    def ha_process_report(self, report_data):
        summary = report_data.get('summary', {})
        threat_score = summary.get('threat_score', 0)
        verdict = summary.get('verdict', 'Unknown')
        
        self.log("--- FINAL HYBRID ANALYSIS REPORT ---")
        self.log(f"Final Verdict: **{verdict.upper()}**")
        self.log(f"Threat Score: {threat_score} / 100")
        
        if threat_score >= 80:
            self.after(100, lambda: messagebox.showwarning("MALICIOUS", 
                                  f"🛑 Verdict: **{verdict.upper()}**! (Score: {threat_score})"))
        elif threat_score >= 50:
            self.after(100, lambda: messagebox.showwarning("SUSPICIOUS", 
                                  f"⚠️ Verdict: **{verdict.upper()}**! (Score: {threat_score}). Needs review."))
        else:
            self.after(100, lambda: messagebox.showinfo("ALL CLEAR", "✅ File seems clean."))


    def run_anyrun_scan(self, file_path):
        task_id = self.anyrun_submit_task(file_path)
        if task_id:
            self.anyrun_poll_for_scan_report(task_id)

    def anyrun_submit_task(self, file_path):
        if not os.path.exists(file_path):
            self.log(f"ERROR: File not found at {file_path}", is_error=True)
            return None

        headers = {"Authorization": f"Bearer {self.config_anyrun_api_key}"}
        data = {'kind': 'file','public': 'false', 'script_automation': 'default'}
        
        try:
            with open(file_path, 'rb') as f:
                files = {'file': (os.path.basename(file_path), f)}
                response = requests.post(ANYRUN_SUBMIT_URL, headers=headers, data=data, files=files, timeout=90)
                response.raise_for_status()

                data = response.json()
                task_id = data.get('task_id')
                
                if task_id:
                    self.log(f"Task submitted. ANY.RUN Task ID: {task_id}. Sandbox starting...")
                    return task_id
                else:
                    self.log(f"ANY.RUN submission failed. Response: {data}", is_error=True)
                    return None
        except requests.exceptions.HTTPError as err:
            self.log(f"HTTP Error {err.response.status_code}: Check Bearer token.", is_error=True)
            return None
        except Exception as e:
            self.log(f"Unexpected error during ANY.RUN submission: {e}", is_error=True)
            return None


    def anyrun_poll_for_scan_report(self, task_id):
        ANYRUN_STATUS_URL = f"{ANYRUN_REPORT_URL_BASE}{task_id}/task_state"
        ANYRUN_REPORT_URL = f"{ANYRUN_REPORT_URL_BASE}{task_id}/report"
        headers = {"Authorization": f"Bearer {self.config_anyrun_api_key}"}
        max_checks = 36 
        check_interval = 10 
        
        for i in range(1, max_checks + 1):
            self.log(f"Checking ANY.RUN status ({i})...", is_error=False)
            try:
                status_response = requests.get(ANYRUN_STATUS_URL, headers=headers, timeout=20)
                status_response.raise_for_status()
                status_data = status_response.json()
                task_state = status_data.get('status', 'N/A')
                
                if task_state == 'finished':
                    self.log("Status: FINISHED. Fetching final report...")
                    report_response = requests.get(ANYRUN_REPORT_URL, headers=headers, timeout=20)
                    report_response.raise_for_status()
                    report_data = report_response.json()
                    self.anyrun_process_report(report_data)
                    return
                
                elif task_state in ('created', 'running', 'queued'):
                    self.log(f"Status: **{task_state.upper()}**. Waiting {check_interval}s...")
                    time.sleep(check_interval) 
                
                else:
                    self.log(f"Analysis failed with task state: {task_state}", is_error=True)
                    break
            
            except Exception as e:
                self.log(f"Error during ANY.RUN polling: {e}", is_error=True)
                break

        self.log("Gave up waiting for ANY.RUN.", is_error=True)

    def anyrun_process_report(self, report_data):
        verdict = report_data.get('verdict', 'Unknown')
        malicious_activity = report_data.get('verdict_description', 'No detailed description.')
        
        self.log("--- FINAL ANY.RUN REPORT ---")
        self.log(f"Final Verdict: **{verdict.upper()}**")
        self.log(f"Activity Summary: {malicious_activity}")
        
        if verdict in ['malicious', 'suspicious']:
            self.after(100, lambda: messagebox.showwarning("MALICIOUS / SUSPICIOUS", 
                                  f"🛑 Verdict: **{verdict.upper()}**! {malicious_activity}"))
        else:
            self.after(100, lambda: messagebox.showinfo("ALL CLEAR", "✅ File seems clean."))


if __name__ == "__main__":
    app = BlueScannerApp()
    app.mainloop()