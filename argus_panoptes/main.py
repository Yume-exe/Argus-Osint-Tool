import customtkinter as ctk
import whois
import requests
from tkinter import filedialog
from PIL import Image
from PIL.ExifTags import TAGS
from PyPDF2 import PdfReader
import os

ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("dark-blue")

root = ctk.CTk()
root.title("Argus OSINT Tool")
root.geometry("780x620")
root.resizable(False, False)

try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
    icon_path = os.path.join(script_dir, "searching.ico")
    root.iconbitmap(icon_path)
except:
    pass

highlight_color = "#00ffd5"
accent_color = "#00aaff"
background_color = "#121212"
frame_color = "#1a1a1a"
text_color = "#eeeeee"
secondary_text = "#888888"

root.configure(bg=background_color)

title_label = ctk.CTkLabel(
    root,
    text="ARGUS OSINT TOOL",
    font=("Orbitron", 28, "bold"),
    text_color=highlight_color
)
title_label.pack(pady=(25, 15))

nav_frame = ctk.CTkFrame(root, fg_color=frame_color, corner_radius=10)
nav_frame.pack(pady=10)

content_frame = ctk.CTkFrame(root, fg_color=background_color)
content_frame.pack(pady=(0, 10))

output_box = ctk.CTkTextbox(
    root,
    width=720,
    height=220,
    wrap="word",
    font=("Consolas", 12),
    fg_color=frame_color,
    text_color=text_color,
    corner_radius=10,
    border_width=1,
    border_color=highlight_color
)
output_box.pack(pady=10)

# WHOIS Frame
whois_frame = ctk.CTkFrame(content_frame, fg_color=frame_color, corner_radius=10)
entry_domain = ctk.CTkEntry(whois_frame, placeholder_text="Enter domain", width=400, text_color=highlight_color)
entry_domain.pack(pady=5)
ctk.CTkButton(whois_frame, text="Lookup WHOIS", command=lambda: whois_lookup(), fg_color=accent_color, text_color="white").pack(pady=5)

entry_ip = ctk.CTkEntry(whois_frame, placeholder_text="Enter IP address", width=400, text_color=highlight_color)
entry_ip.pack(pady=5)
ctk.CTkButton(whois_frame, text="IP Geolocation", command=lambda: ip_geolocation(), fg_color=accent_color, text_color="white").pack(pady=5)

# URL Frame
url_frame = ctk.CTkFrame(content_frame, fg_color=frame_color, corner_radius=10)
entry_url = ctk.CTkEntry(url_frame, placeholder_text="Enter URL", width=400, text_color=highlight_color)
entry_url.pack(pady=10)
ctk.CTkButton(url_frame, text="Check URL Redirection", command=lambda: check_url_redirect(), fg_color=accent_color, text_color="white").pack(pady=5)

# Metadata Frame
metadata_frame = ctk.CTkFrame(content_frame, fg_color=frame_color, corner_radius=10)
ctk.CTkLabel(metadata_frame, text="Supported formats: JPG, JPEG, PNG, TIFF, BMP, PDF", text_color=secondary_text).pack(pady=5)
ctk.CTkButton(metadata_frame, text="Choose File", command=lambda: extract_metadata(), fg_color=accent_color, text_color="white").pack(pady=10)

# Frame control
current_frame = None

def show_frame(frame):
    global current_frame
    if current_frame:
        current_frame.pack_forget()
    output_box.delete("0.0", "end")
    frame.pack(pady=10)
    current_frame = frame

# Functions

def whois_lookup():
    domain = entry_domain.get().strip()
    output_box.delete("0.0", "end")
    if not domain:
        output_box.insert("end", "Please enter a domain.\n")
        return
    try:
        w = whois.whois(domain)
        result = f"Domain: {w.get('domain_name', 'N/A')}\nRegistrar: {w.get('registrar', 'N/A')}\nCreated: {w.get('creation_date', 'N/A')}\nExpires: {w.get('expiration_date', 'N/A')}\nName Servers: {w.get('name_servers', 'N/A')}"
    except Exception as e:
        result = f"Error: {e}"
    output_box.insert("end", result)

def ip_geolocation():
    ip = entry_ip.get().strip()
    output_box.delete("0.0", "end")
    if not ip:
        output_box.insert("end", "Please enter an IP address.\n")
        return
    try:
        response = requests.get(f"https://ipinfo.io/{ip}/json", timeout=5)
        data = response.json()
        result = f"IP: {data.get('ip')}\nCity: {data.get('city')}\nRegion: {data.get('region')}\nCountry: {data.get('country')}\nISP: {data.get('org')}"
    except Exception as e:
        result = f"Error: {e}"
    output_box.insert("end", result)

def extract_metadata():
    file_path = filedialog.askopenfilename(title="Select a File", filetypes=[("Image/PDF Files", "*.jpg;*.jpeg;*.png;*.tiff;*.bmp;*.pdf")])
    if not file_path:
        return
    output_box.delete("0.0", "end")
    output_box.insert("end", f"File: {file_path}\n\n")
    try:
        if file_path.lower().endswith(".pdf"):
            reader = PdfReader(file_path)
            metadata = reader.metadata
            if metadata:
                for key, value in metadata.items():
                    output_box.insert("end", f"{key}: {value}\n")
            else:
                output_box.insert("end", "No metadata found in PDF.\n")
        else:
            image = Image.open(file_path)
            exif_data = image._getexif()
            if exif_data:
                for tag, value in exif_data.items():
                    tag_name = TAGS.get(tag, tag)
                    output_box.insert("end", f"{tag_name}: {value}\n")
            else:
                output_box.insert("end", "No EXIF metadata found in image.\n")
    except Exception as e:
        output_box.insert("end", f"Error: {e}")

def check_url_redirect():
    url = entry_url.get().strip()
    output_box.delete("0.0", "end")
    if not url.startswith("http"):
        url = "http://" + url
    output_box.insert("end", f"Checking URL: {url}\n\n")
    try:
        response = requests.get(url, allow_redirects=True)
        redirects = response.history
        if redirects:
            output_box.insert("end", "Redirects Found:\n")
            for r in redirects:
                output_box.insert("end", f"➡ {r.url} (Status: {r.status_code})\n")
        else:
            output_box.insert("end", "No redirects detected.\n")
        output_box.insert("end", f"Final Destination: {response.url}\n")
    except Exception as e:
        output_box.insert("end", f"Error: {e}")

# Nav buttons
ctk.CTkButton(nav_frame, text="WHOIS & IP Lookup", command=lambda: show_frame(whois_frame), width=200, fg_color=highlight_color, text_color="black", corner_radius=8).pack(side="left", padx=10, pady=5)
ctk.CTkButton(nav_frame, text="File Metadata", command=lambda: show_frame(metadata_frame), width=200, fg_color=highlight_color, text_color="black", corner_radius=8).pack(side="left", padx=10, pady=5)
ctk.CTkButton(nav_frame, text="URL Redirection", command=lambda: show_frame(url_frame), width=200, fg_color=highlight_color, text_color="black", corner_radius=8).pack(side="left", padx=10, pady=5)

# Initial Frame
show_frame(whois_frame)

root.mainloop()
