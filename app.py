import streamlit as st
import smtplib
from email.message import EmailMessage
import dns.resolver
import logging
from datetime import datetime
import requests

# Cấu hình logging
logging.basicConfig(
    filename="abuse_log.txt",
    level=logging.INFO,
    format="%(asctime)s | %(message)s",
    filemode="a"
)
logger = logging.getLogger()

# Mẫu email cho từng loại vấn đề
EMAIL_TEMPLATES = {
    "Phishing": """
Subject: Urgent: Phishing Website Takedown Request – {domain}

Dear Abuse Team,

We have identified {domain} as a phishing website actively targeting users to steal sensitive data, posing severe risks to online security. 

Details:
- Domain: {domain}
- Issue: Phishing
- Evidence: {evidence}
- Description: {description}

This malicious activity violates internet safety standards. We urgently request you investigate and take immediate action to disable this domain or block its DNS resolution to protect users.

Sincerely,
[Your Name]
    """,
    "Malware": """
Subject: Immediate Action Required: Malware Distribution – {domain}

Dear Abuse Team,

The domain {domain} is distributing malware, endangering users by infecting systems with harmful software. This is a critical threat to cybersecurity.

Details:
- Domain: {domain}
- Issue: Malware
- Evidence: {evidence}
- Description: {description}

We demand swift investigation and removal of this domain or its malicious content from your services to prevent further harm.

Sincerely,
[Your Name]
    """,
    "Botnet": """
Subject: Critical: Botnet Activity on {domain}

Dear Abuse Team,

We have detected {domain} engaging in botnet activities, orchestrating malicious operations that compromise user devices and networks.

Details:
- Domain: {domain}
- Issue: Botnet
- Evidence: {evidence}
- Description: {description}

This severe violation requires immediate action. Please investigate and disable this domain or block its DNS resolution to halt the botnet’s operations.

Sincerely,
[Your Name]
    """,
    "Spam": """
Subject: Urgent: Spam Originating from {domain}

Dear Abuse Team,

The domain {domain} is a source of abusive spam, flooding users with unsolicited and potentially harmful content, disrupting online trust.

Details:
- Domain: {domain}
- Issue: Spam
- Evidence: {evidence}
- Description: {description}

We request you promptly investigate and suspend this domain or its associated services to stop the spam activity.

Sincerely,
[Your Name]
    """,
    "Pharming": """
Subject: Immediate Takedown Required: Pharming Attack – {domain}

Dear Abuse Team,

The domain {domain} is conducting pharming attacks, redirecting users to malicious sites to steal sensitive information, posing a grave threat.

Details:
- Domain: {domain}
- Issue: Pharming
- Evidence: {evidence}
- Description: {description}

We urgently demand investigation and immediate disabling of this domain or its DNS resolution to protect users from this attack.

Sincerely,
[Your Name]
    """,
    "Counterfeit": """
Subject: Urgent: Counterfeit Website Takedown Request – {domain}

Dear Abuse Team,

The domain {domain} is operating a counterfeit website, fraudulently impersonating a legitimate brand to deceive users and cause financial harm.

Details:
- Domain: {domain}
- Issue: Counterfeit
- Evidence: {evidence}
- Description: {description}

This fraudulent activity violates intellectual property rights. We insist on immediate investigation and removal of this domain to prevent further deception.

Sincerely,
[Your Name]
    """
}

# Options mô tả cho từng loại vấn đề (bằng tiếng Anh)
DESCRIPTION_OPTIONS = {
    "Phishing": [
        "Impersonates a login page to steal user credentials.",
        "Creates fraudulent forms to collect sensitive data like passwords or credit cards.",
        "Mimics a trusted brand to trick users into sharing personal information.",
        "Sends fake emails linking to a credential-stealing website."
    ],
    "Malware": [
        "Distributes malicious software harming user devices.",
        "Automatically downloads malware upon website access.",
        "Spreads ransomware locking user data.",
        "Installs spyware tracking user activities."
    ],
    "Botnet": [
        "Controls a botnet for launching DDoS attacks.",
        "Recruits user devices into a botnet via malware.",
        "Uses the domain to manage and distribute botnet commands.",
        "Conducts malicious activities through a botnet."
    ],
    "Spam": [
        "Sends spam emails promoting fraudulent products/services.",
        "Distributes malicious links via spam emails or messages.",
        "Uses the domain for mass unsolicited email campaigns.",
        "Tricks users into clicking spam links to fake websites."
    ],
    "Pharming": [
        "Redirects users to fake websites to steal information.",
        "Alters DNS settings to lead users to malicious sites.",
        "Deceives users into accessing fake websites via DNS manipulation.",
        "Performs pharming attacks to harvest sensitive data."
    ],
    "Counterfeit": [
        "Sells counterfeit products, violating intellectual property rights.",
        "Impersonates a brand to scam users with fake goods.",
        "Uses fake logos/branding to deceive customers.",
        "Operates a fraudulent website mimicking an official store."
    ]
}

# === Giao diện nhập liệu ===
st.set_page_config(page_title="Fake Website Takedown Tool", page_icon="🔒")
st.title("🔒 Fake Website Takedown Tool (Bulk)")

# Lấy danh sách tài khoản từ secrets
accounts = {}
try:
    accounts = {
        st.secrets["gmail"]["account1"]["sender_email"]: st.secrets["gmail"]["account1"]["password"],
        st.secrets["gmail"]["account2"]["sender_email"]: st.secrets["gmail"]["account2"]["password"],
        st.secrets["gmail"]["account3"]["sender_email"]: st.secrets["gmail"]["account3"]["password"],
        st.secrets["gmail"]["account4"]["sender_email"]: st.secrets["gmail"]["account4"]["password"],
        st.secrets["gmail"]["account5"]["sender_email"]: st.secrets["gmail"]["account5"]["password"],
        st.secrets["gmail"]["account6"]["sender_email"]: st.secrets["gmail"]["account6"]["password"],
        st.secrets["gmail"]["account7"]["sender_email"]: st.secrets["gmail"]["account7"]["password"],
        st.secrets["gmail"]["account8"]["sender_email"]: st.secrets["gmail"]["account8"]["password"],
        st.secrets["gmail"]["account9"]["sender_email"]: st.secrets["gmail"]["account9"]["password"]
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
description = st.selectbox("📝 Chọn mô tả hành vi giả mạo", DESCRIPTION_OPTIONS[abuse_type])
custom_description = st.text_area("📝 (Tùy chọn) Nhập mô tả tùy chỉnh (bằng tiếng Anh)", height=100, placeholder="Để trống nếu dùng mô tả sẵn.")

# === Khi nhấn nút Xử lý ===
if st.button("⚔️ Xử lý hàng loạt"):
    # Kiểm tra các trường bắt buộc
    if not all([sender_email, password, domains_input, abuse_type]):
        st.error("⚠️ Vui lòng nhập đầy đủ các trường bắt buộc!")
    else:
        # Chia danh sách domain
        domains = [d.strip() for d in domains_input.split("\n") if d.strip()]
        if not domains:
            st.error("⚠️ Vui lòng nhập ít nhất một domain!")
            st.stop()

        # Dùng custom_description nếu có, nếu không thì dùng description từ dropdown
        final_description = custom_description if custom_description else description

        results = []
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

            # Tạo nội dung báo cáo từ mẫu
            report_body = EMAIL_TEMPLATES[abuse_type].format(
                domain=domain,
                evidence=evidence if evidence else "No additional evidence provided",
                description=final_description
            )

            # Gửi email báo cáo
            email_status = "Skipped"
            try:
                msg = EmailMessage()
                msg['From'] = sender_email
                msg['To'] = to_email
                msg['Subject'] = report_body.split('\n')[0].replace("Subject: ", "")
                msg.set_content(report_body)

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
                f"To={to_email}, AbuseType={abuse_type}, EmailStatus={email_status}, "
                f"DomainStatus={domain_status}, Evidence={evidence}, Description={final_description}, Content=\n{report_body}"
            )
            logger.info(log_message)
            results.append(
                f"✅ Domain {domain}: DNSProvider={dns_provider}, Email={email_status}, Status={domain_status}"
            )

        # Hiển thị kết quả
        st.write("### Kết quả xử lý:")
        for result in results:
            st.write(result)
        if any("Cloudflare" in r for r in results):
            st.info("ℹ️ Để gửi báo cáo nhanh, điền form online của Cloudflare: https://www.cloudflare.com/abuse/")
        if any("Phishing" in r for r in results):
            st.info("ℹ️ Báo cáo phishing tới Google Safe Browsing: https://safebrowsing.google.com/safebrowsing/report_phish/")
        st.info("ℹ️ Gửi báo cáo thủ công tới NetBeacon: https://netbeacon.org")
