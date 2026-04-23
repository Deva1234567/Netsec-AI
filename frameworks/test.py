

from modules.n8n_agent import trigger_critical_alert, N8N_API_KEY

analysis_result = {
    "domain": "malicious-example.com",
    "ip": "192.168.1.10",
    "prediction": "Malware",
    "threat_score": 85,
    "virustotal": "5/70"
}
print("loaded_api_key", N8N_API_KEY)
print(trigger_critical_alert(analysis_result))