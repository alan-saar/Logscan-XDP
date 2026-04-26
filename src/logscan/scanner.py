"""
@file scanner.py
@brief Motor algorítmico do Logscan (TF-IDF e DBSCAN).

Responsável por agrupar os logs, processar extração de templates
e definir se um novo cluster formado representa uma anomalia.
"""

import re

class LogScanner:
    """
    Classe contendo a lógica de machine learning e clustering.
    """
    
    def __init__(self):
        """
        Inicializa o scanner e suas estruturas de estado.
        """
        self.logs_buffer = []

    def process_log_line(self, log_line: str):
        """
        Ingere uma nova linha de log e aplica a clusterização.
        
        Neste esqueleto inicial, faremos apenas um mock simples de regex
        para simular a identificação de um IP anômalo.
        
        :param log_line: A linha de log extraída.
        :return: (bool, str) Tupla indicando (Se é anômalo, IP de origem).
        """
        self.logs_buffer.append(log_line)
        
        # --- Lógica de Clusterização Omitida (Mock) ---
        # Simula a detecção de anomalia baseada em uma string específica
        if "Failed password" in log_line or "Anomalia" in log_line:
            # Extrai o IP (Regex simples para IPs IPv4)
            ip_match = re.search(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', log_line)
            if ip_match:
                return True, ip_match.group(0)
                
        return False, None
