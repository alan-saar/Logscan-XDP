"""
@file scanner.py
@brief Motor algorítmico do Logscan (TF-IDF e DBSCAN).

Responsável por receber os lotes de logs (batches) provenientes da janela
temporal do Control Plane, agrupar os logs, processar extração de templates
e definir se um novo cluster formado representa uma anomalia.
"""

import re
import logging
from sklearn.feature_extraction.text import TfidfVectorizer

# Configura o logger para a classe scanner
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

class LogScanner:
    """
    Classe contendo a lógica de machine learning e clustering.
    """
    
    def __init__(self):
        """
        Inicializa o scanner e o vetorizador TF-IDF.
        """
        # Inicializa o TF-IDF ignorando "stop words" comuns do inglês se desejar,
        # ou limitando o número de features para melhor performance.
        self.vectorizer = TfidfVectorizer(max_features=5000)

    def _preprocess_log(self, line: str) -> str:
        """
        Limpa uma linha de log crua, removendo partes mutáveis (como timestamps e IPs).
        Isso ajuda a isolar o 'template' comportamental do evento para o TF-IDF.
        
        :param line: Linha de log bruta.
        :return: String limpa representando o template do log.
        """
        # 1. Remove um timestamp típico do syslog (Ex: "Jan 12 10:00:01")
        # Pode variar dependendo do padrão de log.
        clean_line = re.sub(r'^[A-Z][a-z]{2}\s+\d+\s\d{2}:\d{2}:\d{2}\s+', '', line)
        
        # 2. Substitui IPs IPv4 por um placeholder 'IP'
        clean_line = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 'IP', clean_line)
        
        # 3. Substitui PIDs, por exemplo 'sshd[1234]', para 'sshd[PID]'
        clean_line = re.sub(r'\[\d+\]', '[PID]', clean_line)
        
        # 4. (Opcional) Poderia substituir hexadecimais grandes
        clean_line = re.sub(r'\b0x[0-9a-fA-F]+\b', 'HEX', clean_line)
        
        return clean_line

    def process_window(self, log_lines: list) -> set:
        """
        Ingere um lote de linhas de log, extrai as matrizes TF-IDF e,
        futuramente, aplicará a clusterização.
        
        :param log_lines: Lista de strings contendo as linhas da janela atual.
        :return: Um conjunto (set) contendo os IPs identificados como anômalos.
        """
        if not log_lines:
            return set()

        # Etapa 1: Pré-processamento e extração de Templates
        cleaned_logs = [self._preprocess_log(line) for line in log_lines]
        
        # Etapa 2: Vetorização (TF-IDF)
        try:
            # fit_transform gera a Matriz Esparsa
            feature_matrix = self.vectorizer.fit_transform(cleaned_logs)
            logging.info(f"[ML] TF-IDF extraiu feature matrix com shape: {feature_matrix.shape}")
            # Em breve, a feature_matrix será passada para o DBSCAN
        except ValueError as e:
            # Em caso de log_lines totalmente vazios ou sem vocabulário
            logging.warning(f"[ML] Aviso na vetorização TF-IDF: {e}")

        # --- Lógica de Mock de IP Temporária ---
        # Mantemos o Mock do Regex apenas para não quebrar a lógica de bloqueios já existente
        # até que o DBSCAN seja plugado na próxima iteração e passe a rotear os verdadeiros IPs.
        anomalous_ips = set()
        for log_line in log_lines:
            if "Failed password" in log_line or "Anomalia" in log_line:
                ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_line)
                if ip_match:
                    anomalous_ips.add(ip_match.group(0))
                
        return anomalous_ips
