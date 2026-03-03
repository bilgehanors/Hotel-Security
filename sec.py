import os
import subprocess
import re
from google import genai

# --- YAPILANDIRMA ---
API_KEY = os.getenv("API_KEY", "API_KEY")
client = genai.Client(api_key=API_KEY)

# Teknik Model İsmi (404 hatasını önlemek için güncellendi)
MODEL_NAME = "gemini-2.5-flash" 

def run_command(cmd):
    try:
        # Nmap çıktılarını daha detaylı almak için -O ve -sV eklendi
        result = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)
        return result.decode('utf-8')
    except Exception as e:
        return f"Hata: {str(e)}"

def get_network_info():
    gateway_output = run_command("netstat -nr | grep default")
    gateway = re.search(r'\d+\.\d+\.\d+\.\d+', gateway_output).group()
    subnet = gateway.rsplit('.', 1)[0] + ".0/24"
    return gateway, subnet

def main():
    print("=== 🛡️ DETECTIVE V3: PROFESYONEL ANALİZ BAŞLATILDI ===")
    gateway, subnet = get_network_info()
    
    # ADIM 1: Genişletilmiş Keşif (Marka tespiti için sudo şart)
    print(f"[*] Cihaz listesi ve markalar çözümleniyor: {subnet}...")
    discovery = run_command(f"sudo nmap -sn {subnet}")

    # ADIM 2: Derin Servis Tespiti (Sadece açık portlar)
    print("[*] Yayın yapan servisler ve protokoller analiz ediliyor...")
    deep_scan = run_command(f"sudo nmap -sS -sV -Pn --open -p 80,443,554,3702,1935,8000,8080,37777 {subnet}")

    # ADIM 3: Akıllı Mantık (Gemma/Gemini Analizi)
    final_prompt = f"""
    Sen kıdemli bir siber güvenlik analistisin. Bir otel odası ağ taramasını raporluyorsun.
    
    KRİTİK BİLGİ:
    - Apple, Samsung, Xiaomi telefon, tablet ve MacBook'lar 'Kişisel Cihaz'dır.
    - Apple cihazlarda 5000/7000/554 portları AirPlay/AirTunes içindir, kamera DEĞİLDİR.
    - Sadece 'Open' (Açık) portları dikkate al.
    
    VERİLER:
    KEŞİF (Markalar): {discovery}
    DERİN TARAMA (Portlar): {deep_scan}

    GÖREV:
    1. Öneri veya tavsiye YAZMA.
    2. Sadece aşağıdaki sütunlara sahip Markdown tablosu oluştur:
    | IP Adresi | Üretici / Marka | Cihazın Gerçek Kimliği | Yayın Yapan Portlar | Kamera İhtimali (%) |
    
    3. Tablonun altına her cihaz için TEK CÜMLELİK teknik analiz ekle.
    4. Sadece Türkçe yaz.
    """
    
    try:
        response = client.models.generate_content(
            model=MODEL_NAME,
            contents=final_prompt
        )
        print("\n" + "="*70)
        print(response.text)
        print("="*70)
    except Exception as e:
        print(f"[-] API Hatası: {str(e)}")
        print("[!] Not: Model ismini 'gemini-1.5-flash' olarak değiştirmeyi deneyebilirsin.")

if __name__ == "__main__":
    main()