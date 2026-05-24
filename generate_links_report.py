from fpdf import FPDF

class LinksReport(FPDF):
    def header(self):
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(40, 40, 40)
        self.cell(0, 10, 'CVE Mitigation Links - Valkey E-Commerce Demo', new_x="LMARGIN", new_y="NEXT", align='C')
        self.ln(2)

    def footer(self):
        self.set_y(-15)
        self.set_font('Helvetica', 'I', 8)
        self.set_text_color(128, 128, 128)
        self.cell(0, 10, f'Page {self.page_no()}/{{nb}}', new_x="RIGHT", new_y="TOP", align='C')

    def section_title(self, title):
        self.set_font('Helvetica', 'B', 13)
        self.set_text_color(20, 60, 120)
        self.ln(5)
        self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT", align='L')
        self.set_draw_color(20, 60, 120)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(4)

    def sub_title(self, title):
        self.set_font('Helvetica', 'B', 11)
        self.set_text_color(60, 60, 60)
        self.ln(3)
        self.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT", align='L')
        self.ln(1)

    def body_text(self, text):
        self.set_font('Helvetica', '', 9)
        self.set_text_color(50, 50, 50)
        self.multi_cell(0, 5, text)
        self.ln(2)

    def link_entry(self, label, url):
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(50, 50, 50)
        self.cell(40, 5, label + ":", new_x="END", new_y="TOP")
        self.set_font('Helvetica', '', 9)
        self.set_text_color(0, 80, 180)
        self.cell(0, 5, url, new_x="LMARGIN", new_y="NEXT", link=url)
        self.set_text_color(50, 50, 50)
        self.ln(1)

    def cve_block(self, cve_id, description, severity, nvd_url, advisory_url, advisory_label, mitigation):
        # CVE ID header
        self.set_font('Helvetica', 'B', 10)
        # Color by severity
        colors = {'HIGH': (180, 30, 30), 'MEDIUM': (200, 130, 0), 'LOW': (60, 140, 60)}
        r, g, b = colors.get(severity, (50, 50, 50))
        self.set_text_color(r, g, b)
        self.cell(0, 6, f"{cve_id} [{severity}]", new_x="LMARGIN", new_y="NEXT")
        self.set_text_color(50, 50, 50)

        # Description
        self.set_font('Helvetica', '', 9)
        self.multi_cell(0, 4.5, description)
        self.ln(1)

        # Links
        self.link_entry("NVD", nvd_url)
        self.link_entry(advisory_label, advisory_url)

        # Mitigation
        self.set_font('Helvetica', 'B', 9)
        self.set_text_color(20, 120, 20)
        self.cell(40, 5, "Mitigation:", new_x="END", new_y="TOP")
        self.set_font('Helvetica', '', 9)
        self.multi_cell(0, 4.5, mitigation)
        self.set_text_color(50, 50, 50)
        self.ln(4)


pdf = LinksReport()
pdf.alias_nb_pages()
pdf.add_page()

# Title
pdf.set_font('Helvetica', 'B', 20)
pdf.set_text_color(20, 60, 120)
pdf.ln(15)
pdf.cell(0, 12, 'CVE Mitigation Links Report', new_x="LMARGIN", new_y="NEXT", align='C')
pdf.set_font('Helvetica', '', 12)
pdf.set_text_color(80, 80, 80)
pdf.cell(0, 8, 'Valkey E-Commerce Demo Project', new_x="LMARGIN", new_y="NEXT", align='C')
pdf.ln(8)
pdf.set_font('Helvetica', '', 10)
pdf.cell(0, 6, 'Report Date: May 24, 2026', new_x="LMARGIN", new_y="NEXT", align='C')
pdf.cell(0, 6, 'Total CVEs Documented: 12', new_x="LMARGIN", new_y="NEXT", align='C')
pdf.ln(15)

pdf.set_font('Helvetica', '', 10)
pdf.set_text_color(60, 60, 60)
pdf.multi_cell(0, 5, (
    "This document provides the official NVD (National Vulnerability Database) links, "
    "GitHub Security Advisory links, and recommended mitigation steps for each CVE "
    "identified in the Valkey E-Commerce Demo project security audit."
))

# jQuery Section
pdf.add_page()
pdf.section_title('jQuery CVEs (documentation/js/jquery.js - v1.11.2)')

pdf.cve_block(
    'CVE-2015-9251',
    'jQuery before 3.0.0 is vulnerable to XSS attacks when a cross-domain Ajax request is performed without the dataType option, causing text/javascript responses to be executed.',
    'HIGH',
    'https://nvd.nist.gov/vuln/detail/CVE-2015-9251',
    'https://github.com/advisories/GHSA-rmxg-73gg-4p98',
    'GitHub Advisory',
    'Upgrade to jQuery >= 3.0.0 (project upgraded to 3.7.1)'
)

pdf.cve_block(
    'CVE-2019-11358',
    'jQuery before 3.4.0 mishandles jQuery.extend(true, {}, ...) because of Object.prototype pollution. An attacker can inject properties onto Object.prototype leading to denial of service, privilege escalation, or remote code execution.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/CVE-2019-11358',
    'https://github.com/advisories/GHSA-6c3j-c64m-qhgq',
    'GitHub Advisory',
    'Upgrade to jQuery >= 3.4.0 (project upgraded to 3.7.1)'
)

pdf.cve_block(
    'CVE-2020-11022',
    'In jQuery versions >= 1.2 and < 3.5.0, passing HTML from untrusted sources to jQuery DOM manipulation methods (.html(), .append(), etc.) may execute untrusted code.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/CVE-2020-11022',
    'https://github.com/advisories/GHSA-gxr4-xjj5-5px2',
    'GitHub Advisory',
    'Upgrade to jQuery >= 3.5.0 (project upgraded to 3.7.1)'
)

pdf.cve_block(
    'CVE-2020-11023',
    'In jQuery versions >= 1.0.3 and < 3.5.0, passing HTML containing <option> elements from untrusted sources to DOM manipulation methods can execute untrusted code even after sanitizing.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/CVE-2020-11023',
    'https://github.com/advisories/GHSA-gxr4-xjj5-5px2',
    'GitHub Advisory',
    'Upgrade to jQuery >= 3.5.0 (project upgraded to 3.7.1)'
)

# Bootstrap Section
pdf.add_page()
pdf.section_title('Bootstrap CVEs (documentation/js/bootstrap.min.js - v3.3.2)')

pdf.cve_block(
    'CVE-2016-10735',
    'In Bootstrap 3.x before 3.4.0 and 4.x-beta before 4.0.0-beta.2, XSS is possible in the data-target attribute.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/CVE-2016-10735',
    'https://github.com/advisories/GHSA-4p24-vmcr-4gqj',
    'GitHub Advisory',
    'Upgrade to Bootstrap >= 3.4.0 or >= 4.0.0-beta.2 (project upgraded to 5.3.3)'
)

pdf.cve_block(
    'CVE-2018-14040',
    'In Bootstrap before 3.4.0 and 4.x before 4.1.2, XSS is possible in the collapse plugin via crafted data attributes.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/CVE-2018-14040',
    'https://github.com/advisories/GHSA-3wqf-4x89-9g79',
    'GitHub Advisory',
    'Upgrade to Bootstrap >= 3.4.0 or >= 4.1.2 (project upgraded to 5.3.3)'
)

pdf.cve_block(
    'CVE-2018-14041',
    'In Bootstrap 4.x before 4.1.2, XSS is possible in the data-target property of scrollspy.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/CVE-2018-14041',
    'https://github.com/advisories/GHSA-pj7m-g53m-7638',
    'GitHub Advisory',
    'Upgrade to Bootstrap >= 4.1.2 (project upgraded to 5.3.3)'
)

pdf.cve_block(
    'CVE-2018-14042',
    'In Bootstrap before 3.4.0 and 4.x before 4.1.2, XSS is possible in the data-container property of tooltip.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/CVE-2018-14042',
    'https://github.com/advisories/GHSA-7mvr-5x2g-wfc8',
    'GitHub Advisory',
    'Upgrade to Bootstrap >= 3.4.0 or >= 4.1.2 (project upgraded to 5.3.3)'
)

pdf.cve_block(
    'CVE-2019-8331',
    'In Bootstrap before 3.4.1 and 4.x before 4.3.1, XSS is possible in the tooltip or popover data-template attribute.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/cve-2019-8331',
    'https://github.com/advisories/GHSA-9v3m-8fp8-mj99',
    'GitHub Advisory',
    'Upgrade to Bootstrap >= 3.4.1 or >= 4.3.1 (project upgraded to 5.3.3)'
)

# Redis/Valkey Section
pdf.add_page()
pdf.section_title('Redis/Valkey CVEs (Unprotected Instance Exposure)')

pdf.body_text(
    "These CVEs apply to Redis/Valkey instances exposed without authentication. "
    "The project's README instructed running Valkey on port 6379 bound to all interfaces "
    "with no password, making it vulnerable to these attacks from any network-adjacent attacker."
)

pdf.cve_block(
    'CVE-2022-24735',
    'Redis Lua scripting privilege escalation. A less privileged user can inject Lua code that executes later when a privileged user runs a Lua script. Requires network access to unprotected instance.',
    'HIGH',
    'https://nvd.nist.gov/vuln/detail/cve-2022-24735',
    'https://www.rapid7.com/db/vulnerabilities/redislabs-redis-cve-2022-24735/',
    'Rapid7 Advisory',
    'Upgrade Redis >= 7.0.0; use --requirepass; restrict with ACLs; bind to localhost'
)

pdf.cve_block(
    'CVE-2022-24736',
    'Redis NULL pointer dereference DoS. A specially crafted Lua script can crash the redis-server process.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/CVE-2022-24736',
    'https://www.ibm.com/support/pages/security-bulletin-vulnerabilities-redis-affect-ibm-event-streams-cve-2022-24736-cve-2022-24735',
    'IBM Advisory',
    'Upgrade Redis >= 7.0.0; bind to localhost; use --requirepass'
)

pdf.cve_block(
    'CVE-2023-28856',
    'Redis HINCRBYFLOAT command DoS. Authenticated users can create an invalid hash field that crashes Redis on access.',
    'MEDIUM',
    'https://nvd.nist.gov/vuln/detail/CVE-2023-28856',
    'https://security.netapp.com/advisory/ntap-20230601-0007/',
    'NetApp Advisory',
    'Upgrade Redis >= 7.0.11 / 6.2.12 / 6.0.19; use --requirepass to limit access'
)

# Additional References
pdf.add_page()
pdf.section_title('Additional Reference Links')

pdf.sub_title('Official Release Notes & Security Blogs')

links = [
    ('jQuery 3.5.0 Security Release', 'https://blog.jquery.com/2020/04/10/jquery-3-5-0-released/'),
    ('Bootstrap 3.4.0 Security Release', 'https://blog.getbootstrap.com/2018/12/13/bootstrap-3-4-0/'),
    ('Bootstrap 5.3.3 (Latest Stable)', 'https://blog.getbootstrap.com/2024/02/20/bootstrap-5-3-3/'),
    ('Redis Security Documentation', 'https://redis.io/docs/management/security/'),
]

for label, url in links:
    pdf.link_entry(label, url)

pdf.ln(5)
pdf.sub_title('Vulnerability Databases & Scanners')

vuln_links = [
    ('Snyk - jQuery Prototype Pollution', 'https://www.snyk.io/vuln/SNYK-JS-JQUERY-174006/'),
    ('Bootstrap XSS PoC Collection', 'https://gist.github.com/BlackFan/e968b5209637952cca1580dc8ffdfde6'),
    ('Rapid7 Redis CVE-2022-24735', 'https://www.rapid7.com/db/vulnerabilities/redislabs-redis-cve-2022-24735/'),
    ('SentinelOne Redis CVE-2023-28856', 'https://www.sentinelone.com/vulnerability-database/cve-2023-28856/'),
    ('NVD - National Vulnerability DB', 'https://nvd.nist.gov/'),
    ('GitHub Advisory Database', 'https://github.com/advisories'),
]

for label, url in vuln_links:
    pdf.link_entry(label, url)

pdf.ln(5)
pdf.sub_title('Vendor Security Bulletins')

vendor_links = [
    ('IBM - jQuery XSS Bulletin', 'https://www.ibm.com/support/pages/security-bulletin-api-connect-vulnerable-jquery-cross-site-scripting-xss-and-other-vulnerabilities-cve-2012-6708-cve-2015-9251-cve-2019-11358-cve-2020-11022-cve-2020-11023'),
    ('IBM - Redis Vulnerabilities', 'https://www.ibm.com/support/pages/security-bulletin-vulnerabilities-redis-affect-ibm-event-streams-cve-2022-24736-cve-2022-24735'),
    ('Ubuntu - CVE-2015-9251', 'https://ubuntu.com/security/CVE-2015-9251'),
    ('Ubuntu - CVE-2019-11358', 'https://ubuntu.com/security/CVE-2019-11358'),
    ('NetApp - CVE-2023-28856', 'https://security.netapp.com/advisory/ntap-20230601-0007/'),
]

for label, url in vendor_links:
    pdf.link_entry(label, url)

# Summary page
pdf.add_page()
pdf.section_title('Quick Reference Summary')

pdf.set_font('Helvetica', 'B', 10)
pdf.set_text_color(50, 50, 50)
pdf.ln(3)

# Table
pdf.set_fill_color(230, 235, 245)
pdf.set_font('Helvetica', 'B', 8)
col_w = [28, 55, 18, 89]
headers = ['CVE ID', 'NVD Link', 'Severity', 'Fix Applied']
for i, h in enumerate(headers):
    pdf.cell(col_w[i], 7, h, 1, align='C', fill=True, new_x="END", new_y="TOP")
pdf.ln()

rows = [
    ('CVE-2015-9251', 'nvd.nist.gov/vuln/detail/CVE-2015-9251', 'HIGH', 'jQuery upgraded to 3.7.1'),
    ('CVE-2019-11358', 'nvd.nist.gov/vuln/detail/CVE-2019-11358', 'MEDIUM', 'jQuery upgraded to 3.7.1'),
    ('CVE-2020-11022', 'nvd.nist.gov/vuln/detail/CVE-2020-11022', 'MEDIUM', 'jQuery upgraded to 3.7.1'),
    ('CVE-2020-11023', 'nvd.nist.gov/vuln/detail/CVE-2020-11023', 'MEDIUM', 'jQuery upgraded to 3.7.1'),
    ('CVE-2016-10735', 'nvd.nist.gov/vuln/detail/CVE-2016-10735', 'MEDIUM', 'Bootstrap upgraded to 5.3.3'),
    ('CVE-2018-14040', 'nvd.nist.gov/vuln/detail/CVE-2018-14040', 'MEDIUM', 'Bootstrap upgraded to 5.3.3'),
    ('CVE-2018-14041', 'nvd.nist.gov/vuln/detail/CVE-2018-14041', 'MEDIUM', 'Bootstrap upgraded to 5.3.3'),
    ('CVE-2018-14042', 'nvd.nist.gov/vuln/detail/CVE-2018-14042', 'MEDIUM', 'Bootstrap upgraded to 5.3.3'),
    ('CVE-2019-8331', 'nvd.nist.gov/vuln/detail/CVE-2019-8331', 'MEDIUM', 'Bootstrap upgraded to 5.3.3'),
    ('CVE-2022-24735', 'nvd.nist.gov/vuln/detail/CVE-2022-24735', 'HIGH', 'Added --requirepass + localhost'),
    ('CVE-2022-24736', 'nvd.nist.gov/vuln/detail/CVE-2022-24736', 'MEDIUM', 'Added --requirepass + localhost'),
    ('CVE-2023-28856', 'nvd.nist.gov/vuln/detail/CVE-2023-28856', 'MEDIUM', 'Added --requirepass + localhost'),
]

pdf.set_font('Helvetica', '', 7)
for row in rows:
    colors = {'HIGH': (180, 30, 30), 'MEDIUM': (180, 120, 0), 'LOW': (60, 140, 60)}
    for i, cell in enumerate(row):
        if i == 2:
            r, g, b = colors.get(cell, (50, 50, 50))
            pdf.set_text_color(r, g, b)
            pdf.set_font('Helvetica', 'B', 7)
        else:
            pdf.set_text_color(50, 50, 50)
            pdf.set_font('Helvetica', '', 7)
        pdf.cell(col_w[i], 6, cell, 1, new_x="END", new_y="TOP")
    pdf.ln()

pdf.set_text_color(50, 50, 50)
pdf.ln(10)
pdf.set_font('Helvetica', 'I', 9)
pdf.multi_cell(0, 5, (
    "Note: All links in this PDF are clickable. Open in a PDF reader that supports "
    "hyperlinks to navigate directly to the NVD entries and GitHub advisories."
))

# Output
output_path = r'c:\Users\areya\Downloads\valkey-ecommerce-demo-main\valkey-ecommerce-demo-main\CVE_Mitigation_Links.pdf'
pdf.output(output_path)
print(f"PDF generated successfully: {output_path}")
