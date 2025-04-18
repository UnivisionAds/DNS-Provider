import streamlit as st
import smtplib
from email.message import EmailMessage
import dns.resolver
import logging
from datetime import datetime
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.common.by import By
from selenium.webdriver.chrome.options import Options
import time
import requests
import os
from PIL import Image
import io

# Cấu hình logging
logging.basicConfig(
    filename="abuse_log.txt",
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    filemode="a"
)
logger = logging.getLogger()

# Thư mục lưu screenshot
SCREENSHOT_DIR = "screenshots"
if not os.path.exists(SCREENSHOT_DIR):
    os.makedirs(SCREENSHOT_DIR)

# === Giao diện nhập liệu ===
st.set_page_config(page_title="Fake Website Takedown Tool", page_icon="🔒")
st.title("🔒 Fake Website Takedown Tool (Bulk)")

# Lấy danh sách tài khoản từ secrets
accounts = {}
try:
    accounts = {
        st.secrets["gmail"]["account1"]["sender_email"]: st.secrets["gmail"]["account1"]["password"],
        st.secrets["gmail"]["account2"]["sender_email"]: st.secrets["gmail"]["account2"]["password"],
        st.secrets["gmail"]["account3"]["sender_email"]: st.secrets["gmail"]["account3"]["password"]
    }
except KeyError as e:
    st.warning(f"⚠️ Lỗi cấu hình secrets: {e}. Sử dụng nhập thủ công.")

# Chọn hoặc nhập sender_email
if accounts:
    sender_email = st.selectbox("📧 Chọn Gmail để gửi", list(accounts.keys()))
    password = accounts[sender_email]
else:
    sender_email = st.text_input("📧 Nhập Gmail của bạn")
    password = st.text_input("🔑 Nhập App Password", type="password")

domains_input = st.text_area("🌐 Nhập danh sách tên miền giả mạo (mỗi dòng một domain)", height=100)
abuse_type = st.selectbox("🚨 Chọn loại vi phạm", ["Phishing", "Malware", "Botnet", "Spam", "Pharming", "Counterfeit"])
evidence = st.text_area("📎 Nhập bằng chứng bổ sung (URL, mô tả, v.v.)", height=100)
description = st.text_area("📝 Mô tả hành vi giả mạo", height=100)

# === Khi nhấn nút Xử lý ===
if st.button("⚔️ Xử lý hàng loạt"):
    # Kiểm tra các trường bắt buộc
    if not all([sender_email, password, domains_input, abuse_type, description]):
        st.error("⚠️ Vui lòng nhập đầy đủ các trường bắt buộc!")
    else:
        # Chia danh sách domain
        domains = [d.strip() for d in domains_input.split("\n") if d.strip()]
        if not domains:
            st.error("⚠️ Vui lòng nhập ít nhất một domain!")
            st.stop()

        results = []
        # Cấu hình Selenium
        chrome_options = Options()
        chrome_options.add_argument("--headless")
        driver = webdriver.Chrome(options=chrome_options)

        for domain in domains:
            # Lấy thông tin DNS provider từ NS records
            dns_provider = ""
            to_email = None
            try:
                answers = dns.resolver.resolve(domain, 'NS')
                ns_records = [str(rdata) for rdata in answers]
                for ns in ns_records:
                    if "cloudflare" in ns.lower():
                        dns_provider = "Cloudflare"
                        to_email = "registrar-abuse@cloudflare.com"
                        break
                if not to_email:
                    dns_provider = "Unknown"
                    to_email = "abuse@dnsprovider"
            except Exception as e:
                results.append(f"❌ Domain {domain}: Lỗi khi lấy NS records: {e}")
                logger.error(f"Domain={domain}, Error=Failed to get NS records: {e}")
                continue

            # Chụp screenshot website
            screenshot_path = os.path.join(SCREENSHOT_DIR, f"{domain}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.png")
            try:
                driver.get(f"http://{domain}")
                time.sleep(2)
                driver.save_screenshot(screenshot_path)
                screenshot_status = "Captured"
            except Exception as e:
                screenshot_status = f"Failed: {e}"
                screenshot_path = None

            # Tạo nội dung báo cáo
            report_body = f"""
Dear Sir/Madam,

I am reporting a fraudulent website: {domain}. The website is engaging in {abuse_type} activities, harming users and brand reputation.

Details:
- Abuse Type: {abuse_type}
- Domain: {domain}
- Description: {description}
- Evidence: {evidence if evidence else "No additional evidence provided"}
- Screenshot: {screenshot_path if screenshot_path else "Not available"}

Please investigate and take action to remove or block this website.

Sincerely,
[Your Name]
            """

            # Điền form online Cloudflare
            form_status = "Skipped"
            if dns_provider == "Cloudflare":
                try:
                    driver.get("https://www.cloudflare.com/abuse/")
                    time.sleep(2)
                    # Giả định cấu trúc form (cần kiểm tra thực tế)
                    driver.find_element(By.NAME, "domain").send_keys(domain)
                    driver.find_element(By.NAME, "abuse_type").send_keys(abuse_type)
                    driver.find_element(By.NAME, "description").send_keys(description)
                    if evidence:
                        driver.find_element(By.NAME, "evidence").send_keys(evidence)
                    if screenshot_path:
                        driver.find_element(By.NAME, "file").send_keys(screenshot_path)
                    driver.find_element(By.XPATH, "//button[@type='submit']").click()
                    time.sleep(2)
                    form_status = "Submitted"
                except Exception as e:
                    form_status = f"Failed: {e}"
                    logger.error(f"Domain={domain}, FormError=Failed to fill Cloudflare form: {e}")

            # Báo cáo Google Safe Browsing
            google_status = "Skipped"
            try:
                driver.get("https://safebrowsing.google.com/safebrowsing/report_phish/")
                time.sleep(2)
                driver.find_element(By.NAME, "url").send_keys(f"http://{domain}")
                driver.find_element(By.NAME, "details").send_keys(description)
                driver.find_element(By.XPATH, "//button[@type='submit']").click()
                time.sleep(2)
                google_status = "Submitted"
            except Exception as e:
                google_status = f"Failed: {e}"
                logger.error(f"Domain={domain}, GoogleError=Failed to report to Google: {e}")

            # Gửi email nếu form thất bại hoặc không phải Cloudflare
            email_status = "Skipped"
            if form_status.startswith("Failed") or dns_provider != "Cloudflare":
                try:
                    msg = EmailMessage()
                    msg['From'] = sender_email
                    msg['To'] = to_email
                    msg['Subject'] = f"Fraudulent Website Report – {domain}"
                    msg.set_content(report_body)
                    if screenshot_path:
                        with open(screenshot_path, 'rb') as f:
                            img_data = f.read()
                        msg.add_attachment(img_data, maintype='image', subtype='png', filename=os.path.basename(screenshot_path))

                    with smtplib.SMTP("smtp.gmail.com", 587) as server:
                        server.starttls()
                        server.login(sender_email, password)
                        server.send_message(msg)

                    email_status = "Sent"
                except Exception as e:
                    email_status = f"Failed: {e}"
                    logger.error(f"Domain={domain}, EmailError=Failed to send email: {e}")

            # Kiểm tra trạng thái domain
            domain_status = "Active"
            try:
                requests.get(f"http://{domain}", timeout=5)
            except requests.ConnectionError:
                domain_status = "Down"

            # Ghi log
            log_message = (
                f"Report processed: Domain={domain}, DNSProvider={dns_provider}, "
                f"To={to_email}, AbuseType={abuse_type}, Screenshot={screenshot_status}, "
                f"FormStatus={form_status}, GoogleStatus={google_status}, EmailStatus={email_status}, "
                f"DomainStatus={domain_status}, Evidence={evidence}, Description={description}, Content=\n{report_body}"
            )
            logger.info(log_message)
            results.append(
                f"✅ Domain {domain}: DNSProvider={dns_provider}, Screenshot={screenshot_status}, "
                f"Form={form_status}, Google={google_status}, Email={email_status}, Status={domain_status}"
            )

        driver.quit()
        # Hiển thị kết quả
        st.write("### Kết quả xử lý:")
        for result in results:
            st.write(result)
        if any("Cloudflare" in r for r in results):
            st.info("ℹ️ Kiểm tra form online của Cloudflare: https://www.cloudflare.com/abuse/")
        st.info("ℹ️ Gửi báo cáo thủ công tới NetBeacon: https://netbeacon.org")
