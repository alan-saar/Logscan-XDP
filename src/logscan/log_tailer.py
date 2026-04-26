"""
@file log_tailer.py
@brief Módulo de leitura contínua de logs.

Este módulo imita o comportamento do comando 'tail -f', lendo
linhas de um arquivo e retornando-as usando generators.
"""

import os

class LogTailer:
    """
    Classe responsável por ler um arquivo de log indefinidamente.
    """
    
    def __init__(self, filepath):
        """
        Inicializa o leitor de logs.
        
        :param filepath: Caminho absoluto ou relativo do arquivo de log.
        """
        self.filepath = filepath

    def tail(self):
        """
        Generator que produz novas linhas adicionadas ao arquivo.
        
        :yield: String contendo a nova linha do log ou None caso não haja novidade.
        """
        with open(self.filepath, "r") as file:
            # Pula para o fim do arquivo no início da execução
            file.seek(0, os.SEEK_END)
            
            while True:
                line = file.readline()
                if not line:
                    yield None
                else:
                    yield line.strip()
