import os
from fpdf import FPDF

class PDF(FPDF):
    def header(self):
        self.set_font("Helvetica", "B", 18)
        self.cell(0, 10, "WarSOC: End-to-End Production Deployment Guide", ln=True, align="C")
        self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font("Helvetica", "I", 8)
        self.cell(0, 10, f"Page {self.page_no()}/{{nb}} | WarSOC Enterprise Architecture", 0, 0, "C")

    def chapter_title(self, num, label):
        self.set_font("Helvetica", "B", 14)
        self.set_fill_color(200, 220, 255)
        self.cell(0, 10, f"Step {num}: {label}", ln=True, fill=True)
        self.ln(4)

    def chapter_body(self, text):
        self.set_font("Helvetica", "", 11)
        self.multi_cell(0, 7, text)
        self.ln(4)

def create_runbook():
    pdf = PDF()
    pdf.alias_nb_pages()
    pdf.add_page()
    
    # Intro
    pdf.set_font("Helvetica", "", 12)
    intro_text = (
        "Congratulations! The WarSOC architecture has been completely audited, sealed, "
        "and pushed to the remote repository. The system is 100% production-ready. "
        "Below is the exact step-by-step roadmap to get the platform live for customers."
    )
    pdf.multi_cell(0, 7, intro_text)
    pdf.ln(10)

    # Step 1
    pdf.chapter_title(1, "Domain & DNS Configuration")
    step1 = (
        "You need to route your web traffic so the frontend and backend are cleanly separated.\n\n"
        "- Frontend (warsoc.tech): This will point to Vercel. Vercel will provide you with a CNAME or A-Record during setup.\n"
        "- Backend (api.warsoc.tech): This will point to the public IPv4 address of your Linux Virtual Private Server (VPS)."
    )
    pdf.chapter_body(step1)

    # Step 2
    pdf.chapter_title(2, "Server Provisioning & Backend Deployment")
    step2 = (
        "1. Rent a Linux VPS (Ubuntu 22.04 LTS is recommended) from AWS, DigitalOcean, or Azure. Ensure it has at least 4GB of RAM.\n"
        "2. SSH into the server and install Docker and Docker Compose.\n"
        "3. Clone your remote Git repository: git clone https://github.com/SHADABMUSHTAQ/Startup.git\n"
        "4. Switch to the backend branch: git checkout backend\n"
        "5. Create a '.env' file in the Startup-backend directory. Paste the exact contents of your local '.env.prod' file into it.\n"
        "6. Boot the system: docker-compose -f docker-compose.prod.yml up -d --build\n"
        "7. The backend API, MongoDB, Redis, and workers are now live."
    )
    pdf.chapter_body(step2)

    # Step 3
    pdf.chapter_title(3, "Frontend Vercel Deployment")
    step3 = (
        "1. Log into Vercel (or Netlify) and click 'Add New Project'.\n"
        "2. Import your GitHub repository (the 'main' branch, which holds the Startup-main folder).\n"
        "3. In the Vercel Environment Variables settings, add:\n"
        "   Key: VITE_API_BASE_URL\n"
        "   Value: https://api.warsoc.tech\n"
        "4. Click 'Deploy'. Vercel will automatically build the React app and issue an SSL certificate."
    )
    pdf.chapter_body(step3)

    # Step 4
    pdf.chapter_title(4, "Azure Blob Storage (Windows Agent CDN)")
    step4 = (
        "1. Go to the Microsoft Azure Portal and create a new Storage Account.\n"
        "2. Inside the Storage Account, create a container named 'agent-downloads'. Set the Access Level to 'Blob (anonymous read access for blobs only)'.\n"
        "3. Upload your compiled 'warsoc_installer.exe' into this container.\n"
        "4. Copy the public URL of the uploaded file.\n"
        "5. SSH back into your Linux server, open your '.env' file, and update AGENT_CDN_URL to match the Azure URL.\n"
        "6. Restart the backend: docker-compose restart backend"
    )
    pdf.chapter_body(step4)
    
    # Conclusion
    pdf.ln(5)
    pdf.set_font("Helvetica", "B", 12)
    pdf.multi_cell(0, 7, "Your platform is now fully deployed, secure, and ready to ingest telemetry from enterprise clients globally.")

    # Ensure output directory exists
    os.makedirs("downloads", exist_ok=True)
    pdf_path = os.path.join(os.getcwd(), "downloads", "WarSOC_Deployment_Runbook.pdf")
    pdf.output(pdf_path)
    print(f"PDF successfully generated at: {pdf_path}")

if __name__ == "__main__":
    create_runbook()
