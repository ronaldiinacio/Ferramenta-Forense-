import os
import sqlite3
import base64
import hashlib
import requests
import threading
import queue
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
from datetime import datetime, timedelta, timezone

# Bibliotecas de Criptografia
from cryptography.hazmat.primitives import hashes, hmac, padding
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

class ExtratorWhatsAppApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Recuperador Forense - Visualização Única WhatsApp")
        self.root.geometry("850x550")
        
        self.db_path = tk.StringVar()
        self.output_path = tk.StringVar()
        self.log_queue = queue.Queue()
        
        self.setup_ui()
        self.processar_logs() # Inicia o loop de leitura da fila de logs

    def setup_ui(self):
        frame_top = tk.Frame(self.root, pady=10, padx=10)
        frame_top.pack(fill=tk.X)

        tk.Label(frame_top, text="Banco de Dados (msgstore.db):").grid(row=0, column=0, sticky=tk.W, pady=5)
        tk.Entry(frame_top, textvariable=self.db_path, width=60, state='readonly').grid(row=0, column=1, padx=5)
        tk.Button(frame_top, text="Procurar...", command=self.selecionar_db).grid(row=0, column=2)

        tk.Label(frame_top, text="Pasta de Destino (Caso):").grid(row=1, column=0, sticky=tk.W, pady=5)
        tk.Entry(frame_top, textvariable=self.output_path, width=60, state='readonly').grid(row=1, column=1, padx=5)
        tk.Button(frame_top, text="Selecionar...", command=self.selecionar_destino).grid(row=1, column=2)

        self.btn_iniciar = tk.Button(self.root, text="INICIAR EXTRAÇÃO FORENSE", bg="#4CAF50", fg="white", font=("Arial", 12, "bold"), command=self.iniciar_extracao)
        self.btn_iniciar.pack(pady=10)

        self.log_area = scrolledtext.ScrolledText(self.root, wrap=tk.WORD, state='disabled', bg="black", fg="lime", font=("Consolas", 10))
        self.log_area.pack(expand=True, fill=tk.BOTH, padx=10, pady=10)

    def log(self, mensagem):
        # Despacha a mensagem para a fila (Thread-safe)
        self.log_queue.put(mensagem)

    def processar_logs(self):
        # Consome a fila de logs na Thread Principal (Tkinter safe)
        while not self.log_queue.empty():
            msg = self.log_queue.get()
            self.log_area.config(state='normal')
            self.log_area.insert(tk.END, msg + "\n")
            self.log_area.see(tk.END)
            self.log_area.config(state='disabled')
        self.root.after(100, self.processar_logs)

    def selecionar_db(self):
        arquivo = filedialog.askopenfilename(title="Selecione o msgstore.db", filetypes=[("SQLite DB", "*.db")])
        if arquivo: self.db_path.set(arquivo)

    def selecionar_destino(self):
        pasta = filedialog.askdirectory(title="Selecione a pasta de destino")
        if pasta: self.output_path.set(pasta)

    def calcular_hash(self, caminho_arquivo):
        sha256_hash = hashlib.sha256()
        try:
            with open(caminho_arquivo, "rb") as f:
                for byte_block in iter(lambda: f.read(4096), b""):
                    sha256_hash.update(byte_block)
            return sha256_hash.hexdigest()
        except: 
            return "N/A"

    def extrair_dados_db(self):
        db_file = self.db_path.get()
        conn = sqlite3.connect(f"file:{db_file}?mode=ro", uri=True)
        cursor = conn.cursor()
        
        # Query Forense corrigida (sender_jid isolado para grupos, tradução de LID e filtro view_mode)
        query = """
        SELECT 
            m._id,
            COALESCE(j_real.raw_string, sender_jid.raw_string, chat_jid.raw_string) as jid,
            mm.message_url,
            mm.media_key,
            mm.mime_type,
            m.timestamp
        FROM message_media mm
        JOIN message m ON mm.message_row_id = m._id
        JOIN chat c ON m.chat_row_id = c._id
        JOIN jid chat_jid ON c.jid_row_id = chat_jid._id
        LEFT JOIN jid sender_jid ON m.sender_jid_row_id = sender_jid._id
        LEFT JOIN jid_map jm ON jm.lid_row_id = COALESCE(sender_jid._id, chat_jid._id)
        LEFT JOIN jid j_real ON j_real._id = jm.jid_row_id
        WHERE mm.message_url IS NOT NULL 
          AND mm.media_key IS NOT NULL 
          AND mm.mime_type IS NOT NULL
          AND m.view_mode = 2
        """
        
        cursor.execute(query)
        resultados = cursor.fetchall()
        conn.close()
        return resultados

    def formatar_data(self, timestamp_ms):
        try:
            ts_segundos = int(timestamp_ms) / 1000.0
            dt_utc = datetime.fromtimestamp(ts_segundos, timezone.utc)
            dt_br = dt_utc - timedelta(hours=3)
            return dt_br.strftime("%d/%m/%Y %H:%M:%S")
        except: 
            return "Data Desconhecida"

    def identificar_app_info(self, mime_type):
        mime = mime_type.lower()
        if 'image' in mime: return b"WhatsApp Image Keys", ".jpg"
        elif 'video' in mime: return b"WhatsApp Video Keys", ".mp4"
        elif 'audio' in mime or 'ogg' in mime: return b"WhatsApp Audio Keys", ".ogg"
        else: return b"WhatsApp Document Keys", ".bin"

    def processar_midias(self):
        self.btn_iniciar.config(state=tk.DISABLED)
        self.log("[*] Iniciando processo forense (Motor Seguro)...")
        dest_dir = self.output_path.get()
        relatorio_dados = {}
        
        try:
            self.log("[*] Analisando banco de dados (Buscando Evidências view_mode=2)...")
            registros = self.extrair_dados_db()
            self.log(f"[+] Encontrados {len(registros)} registros confirmados de Visualização Única.")

            for i, (msg_id, jid, url, media_key, mime_type, timestamp) in enumerate(registros):
                numero_contato = jid.split('@')[0] if jid else "Desconhecido"
                data_br = self.formatar_data(timestamp)
                app_info, extensao = self.identificar_app_info(mime_type)
                
                # Nome do arquivo seguro e imune a colisões
                nome_arquivo_final = f"{timestamp}_{msg_id}{extensao}"
                
                self.log(f"\n--- Processando {i+1}/{len(registros)} | Autor: {numero_contato} ---")
                
                pasta_contato = os.path.join(dest_dir, f"Autor_{numero_contato}")
                pasta_enc = os.path.join(pasta_contato, "criptografados")
                pasta_dec = os.path.join(pasta_contato, "recuperados")
                os.makedirs(pasta_enc, exist_ok=True)
                os.makedirs(pasta_dec, exist_ok=True)
                
                if numero_contato not in relatorio_dados:
                    relatorio_dados[numero_contato] = []

                dados_relatorio = {
                    "data": data_br,
                    "tipo_arquivo": extensao.upper().replace(".", ""),
                    "nome_arquivo": nome_arquivo_final,
                    "status_download": "FALHA",
                    "status_dec": "FALHA",
                    "hash_enc": "-",
                    "hash_dec": "-",
                    "caminho_relativo": "-"
                }

                arq_enc = os.path.join(pasta_enc, f"{timestamp}_{msg_id}.enc")
                self.log(f"[*] Baixando da CDN da Meta...")
                try:
                    # Timeout robusto: 10s pra conectar, 30s pra baixar blocos
                    res = requests.get(url, stream=True, timeout=(10, 30))
                    if res.status_code == 200:
                        with open(arq_enc, 'wb') as f:
                            for chunk in res.iter_content(8192): f.write(chunk)
                        dados_relatorio["status_download"] = "SUCESSO"
                        dados_relatorio["hash_enc"] = self.calcular_hash(arq_enc)
                        self.log("[+] Download concluído.")
                    else:
                        self.log(f"[-] Erro HTTP {res.status_code}. Arquivo expirou do servidor.")
                except Exception as e:
                    self.log(f"[-] Erro na conexão: {e}")

                if dados_relatorio["status_download"] == "SUCESSO":
                    self.log("[*] Verificando Autenticidade (HMAC) e Descriptografando...")
                    try:
                        # Resiliência BLOB/Base64
                        media_key_bytes = base64.b64decode(media_key) if isinstance(media_key, str) else media_key
                        
                        hkdf = HKDF(algorithm=hashes.SHA256(), length=112, salt=None, info=app_info, backend=default_backend())
                        expanded_key = hkdf.derive(media_key_bytes)
                        
                        iv = expanded_key[0:16]
                        cipher_key = expanded_key[16:48]
                        mac_key = expanded_key[48:80]
                        
                        with open(arq_enc, 'rb') as f: dados_cripto = f.read()
                        
                        if len(dados_cripto) < 10:
                            raise ValueError("Arquivo corrompido: tamanho menor que a assinatura MAC.")
                            
                        ciphertext = dados_cripto[:-10]
                        file_mac = dados_cripto[-10:]
                        
                        # Validação MAC Criptográfica
                        h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
                        h.update(iv + ciphertext)
                        calculated_mac = h.finalize()[:10]
                        
                        if file_mac != calculated_mac:
                            raise ValueError("Falha de Integridade (MAC). A evidência foi corrompida ou a chave é inválida.")
                        
                        # Decifragem
                        cipher = Cipher(algorithms.AES(cipher_key), modes.CBC(iv), backend=default_backend())
                        decryptor = cipher.decryptor()
                        dados_claros_com_lixo = decryptor.update(ciphertext) + decryptor.finalize()
                        
                        # Limpeza (Remoção do Padding PKCS7)
                        unpadder = padding.PKCS7(128).unpadder()
                        dados_claros_limpos = unpadder.update(dados_claros_com_lixo) + unpadder.finalize()
                        
                        arq_dec = os.path.join(pasta_dec, nome_arquivo_final)
                        with open(arq_dec, 'wb') as f: f.write(dados_claros_limpos)
                        
                        dados_relatorio["status_dec"] = "SUCESSO"
                        dados_relatorio["hash_dec"] = self.calcular_hash(arq_dec)
                        dados_relatorio["caminho_relativo"] = f"./Autor_{numero_contato}/recuperados/{nome_arquivo_final}"
                        self.log("[+] Extração e validação concluídas com sucesso!")
                        
                    except ValueError as ve:
                        # Captura especificamente falhas de Padding ou MAC
                        self.log(f"[-] ERRO FORENSE (Integridade): {ve}")
                    except Exception as e:
                        self.log(f"[-] Erro inesperado ao decifrar: {e}")

                relatorio_dados[numero_contato].append(dados_relatorio)

            self.log("\n[*] Gerando Relatório Consolidado HTML...")
            self.gerar_html(dest_dir, relatorio_dados)
            self.log("[!] TAREFA FINALIZADA.")
            # Repassa o aviso para a thread principal (Tkinter) via função lambda
            self.root.after(0, lambda: messagebox.showinfo("Sucesso", "Extração forense e relatório concluídos!"))

        except Exception as e:
            self.log(f"\n[!] ERRO CRÍTICO: {e}")
            self.root.after(0, lambda e=e: messagebox.showerror("Erro", f"Ocorreu um erro: {str(e)}"))
        finally:
            self.root.after(0, lambda: self.btn_iniciar.config(state=tk.NORMAL))

    def gerar_html(self, dest_dir, dados):
        html = """
        <!DOCTYPE html>
        <html lang="pt-BR">
        <head>
            <meta charset="UTF-8">
            <title>Relatório - Recuperador de Mensagens de Visualização Única</title>
            <style>
                body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #f0f2f5; margin: 30px; color: #333; }
                h1 { color: #1c1e21; text-align: center; margin-bottom: 30px; font-size: 28px; }
                .chat-box { background: white; padding: 20px; margin-bottom: 30px; border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.1); }
                h2 { color: #25D366; border-bottom: 2px solid #25D366; padding-bottom: 10px; margin-top: 0; }
                table { width: 100%; border-collapse: collapse; margin-top: 15px; font-size: 13px; }
                th, td { border: 1px solid #e0e0e0; padding: 12px; text-align: center; vertical-align: middle; }
                th { background-color: #f8f9fa; color: #555; font-weight: bold; }
                .sucesso { color: #155724; background-color: #d4edda; font-weight: bold; border-radius: 4px; }
                .falha { color: #721c24; background-color: #f8d7da; font-weight: bold; border-radius: 4px; }
                .hash-cell { font-family: 'Courier New', Courier, monospace; font-size: 11px; word-break: break-all; max-width: 150px; text-align: left; }
                .media-preview img { max-width: 150px; max-height: 150px; border-radius: 5px; cursor: pointer; border: 1px solid #ddd; transition: 0.3s; }
                .media-preview img:hover { opacity: 0.8; }
                .media-preview audio { width: 220px; height: 35px; }
                .media-preview video { max-width: 220px; max-height: 150px; border-radius: 5px; }
            </style>
        </head>
        <body>
        <h1>🛡️ Relatório de Evidências - Visualização Única</h1>
        """
        for numero, items in dados.items():
            html += f"<div class='chat-box'><h2>👤 Autoria Identificada: {numero}</h2><table>"
            html += "<tr><th>Data/Hora Original (UTC-3)</th><th>Tipo</th><th>Arquivo Salvo</th><th>Download (CDN)</th><th>Decifragem & Integridade (MAC)</th><th>Hash Original (Encrypted)</th><th>Hash Recuperado (Clear)</th><th>Pré-visualização da Evidência</th></tr>"
            
            for item in items:
                cor_down = "sucesso" if item['status_download'] == "SUCESSO" else "falha"
                cor_dec = "sucesso" if item['status_dec'] == "SUCESSO" else "falha"
                
                preview_html = "N/A"
                if item['status_dec'] == "SUCESSO":
                    src = item['caminho_relativo']
                    ext = item['tipo_arquivo']
                    
                    if ext == "JPG":
                        preview_html = f"<a href='{src}' target='_blank'><img src='{src}' alt='Imagem Recuperada'></a>"
                    elif ext == "OGG":
                        preview_html = f"<audio controls><source src='{src}' type='audio/ogg'>Seu navegador não suporta áudio.</audio>"
                    elif ext == "MP4":
                        preview_html = f"<video controls><source src='{src}' type='video/mp4'>Seu navegador não suporta vídeo.</video>"
                    else:
                        preview_html = f"<a href='{src}' target='_blank'>Abrir Arquivo</a>"

                html += f"""<tr>
                    <td>{item['data']}</td>
                    <td><strong>{item['tipo_arquivo']}</strong></td>
                    <td style='font-family: monospace;'>{item['nome_arquivo']}</td>
                    <td class='{cor_down}'>{item['status_download']}</td>
                    <td class='{cor_dec}'>{item['status_dec']}</td>
                    <td class='hash-cell'>{item['hash_enc']}</td>
                    <td class='hash-cell'>{item['hash_dec']}</td>
                    <td class='media-preview'>{preview_html}</td>
                </tr>"""
            html += "</table></div>"
            
        html += "</body></html>"
        
        with open(os.path.join(dest_dir, "Relatorio_Consolidado.html"), "w", encoding="utf-8") as f:
            f.write(html)

    def iniciar_extracao(self):
        if not self.db_path.get() or not self.output_path.get():
            messagebox.showwarning("Atenção", "Selecione o banco de dados e a pasta de destino.")
            return
        threading.Thread(target=self.processar_midias, daemon=True).start()

if __name__ == "__main__":
    root = tk.Tk()
    app = ExtratorWhatsAppApp(root)
    root.mainloop()
