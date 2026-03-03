import subprocess
import json
from google import genai
import re

# 1. Google Gemma API Yapılandırması
API_KEY = "API_KEY"

client = genai.Client(api_key=API_KEY)
MODEL_NAME = 'gemma-3-27b-it'  # Gemma 3 27B Instruct model

def run_nmap(command):
    print(f"[*] Çalıştırılıyor: {command}")
    process = subprocess.Popen(command.split(), stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    stdout, stderr = process.communicate()
    return stdout.decode()

def get_gateway():
    # Mac için ağ geçidini bulur
    cmd = "netstat -nr"
    output = subprocess.check_output(cmd.split()).decode()
    for line in output.split('\n'):
        if 'default' in line:
            return re.search(r'\d+\.\d+\.\d+\.\d+', line).group()
    return None

def analyze_with_gemma(prompt):
    """Gemma API ile analiz yapar"""
    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=prompt
        )
        return response.text.strip()
    except Exception as e:
        print(f"[-] Gemma analiz hatası: {str(e)}")
        return None

def main():
    gateway = get_gateway()
    if not gateway:
        print("[-] Ağ geçidi bulunamadı!")
        return
    
    network_range = gateway.rsplit('.', 1)[0] + ".0/24"
    print(f"[+] Ağ taraması başlatılıyor: {network_range}")

    # ADIM 1: İlk Keşif Taraması
    discovery_results = run_nmap(f"sudo nmap -sP {network_range}")

    # ADIM 2: Gemma'ya Cihazları Analiz Ettirme
    prompt = f"""
Aşağıdaki Nmap tarama sonuçlarını analiz et. Hangi IP adresleri gizli bir kamera 
veya şüpheli bir IoT cihazı (akıllı ev ürünü vb.) olabilir?
Sadece şüpheli IP'leri virgülle ayırarak listele.
Hiçbir açıklama, öneri veya ek bilgi yazma. Sadece IP listesi.

Sonuçlar:
{discovery_results}
"""
    
    suspicious_ips = analyze_with_gemma(prompt)
    if not suspicious_ips:
        print("[-] Gemma analizi başarısız oldu.")
        return
    
    suspicious_ips = suspicious_ips.strip()
    print(f"[!] Şüpheli bulunan cihazlar: {suspicious_ips}")

    if suspicious_ips and suspicious_ips.lower() != "hiçbiri" and suspicious_ips.lower() != "none":
        # ADIM 3: Derin Sorgulama (virgülleri boşlukla değiştir - nmap formatı)
        ip_list = suspicious_ips.replace(",", " ").split()
        ip_args = " ".join(ip.strip() for ip in ip_list)
        deep_scan = run_nmap(f"sudo nmap -sV -O --osscan-guess -p 80,443,554,8000,8080,37777 {ip_args}")
        
        # ADIM 4: Final Tahmini
        final_prompt = f"""
Aşağıdaki iki tarama sonucunu analiz et. Sadece gizli kamera OLMA İHTİMALİ olan cihazları listele.

--- KEŞİF TARAMASI ---
{discovery_results}

--- DERİN PORT TARAMASI ---
{deep_scan}

Sadece kamera olma ihtimali olan cihazları şu formatta listele:

IP: <ip>
MAC: <mac>
Üretici: <üretici>
Açık Portlar: <portlar>
Kamera Olma İhtimali: %<yüzde> (<Yüksek/Orta/Düşük>)
Sebep: <tek cümle, sadece teknik gerekçe>

KURALLAR:
- Kamera ihtimali olmayan cihazları YAZMA.
- Öneri, uyarı, açıklama YAZMA.
- Türkçe yaz.
- İhtimal hesabı: 554/8000/37777 açıksa Yüksek (>%70), Hikvision/Dahua/Reolink üreticisiyse +%20, 80/443 açıksa Orta (%40-70), port yoksa Düşük.
"""
        final_report = analyze_with_gemma(final_prompt)
        
        if final_report:
            print("\n=== FİNAL GÜVENLİK RAPORU ===\n")
            print(final_report)
        else:
            print("[-] Rapor oluşturma başarısız oldu.")
    else:
        print("[+] Şüpheli cihaz bulunamadı.")

if __name__ == "__main__":
    main()
