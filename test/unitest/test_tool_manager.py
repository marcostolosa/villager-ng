"""
Teste do gerenciador de ferramentas
AVISO DE SEGURANÇA: Este arquivo testa funções extremamente perigosas como pyeval() e os_execute_cmd()
Use APENAS em ambiente isolado para fins educacionais
"""

import random

from scheduler.core.tools.common_tool import pyeval, os_execute_cmd
from scheduler.toolschain.tools_manager import ToolsManager, extract_json_with_positions


def test_ToolsManager():
    """
    Testar o gerenciador de ferramentas com funções perigosas.

    AVISO: Este teste utiliza pyeval() que executa código Python arbitrário
    e os_execute_cmd() que executa comandos shell sem validação.
    """
    puzzle = ""
    p1 = random.randint(-100, 100)
    p2 = random.randint(-100, 100)
    correct_res = p1 * p2
    puzzle = f"{p1}*{p2}"

    # Inicializar gerenciador de ferramentas
    TM = ToolsManager()

    # PERIGO: Registrar funções que permitem execução arbitrária
    TM.register_func(pyeval)  # Execução de código Python sem restrições
    TM.register_func(os_execute_cmd)  # Execução de comandos shell diretos

    # Extrair comandos JSON do texto
    jsons = extract_json_with_positions(
        """
        huh?%%%%{
        "name": "pyeval",
    "parameters": {
        "python_codeblock": "%s"
    }
}%%%%
        """ % puzzle)

    assert len(jsons) > 0

    # Executar comandos extraídos - PERIGOSO!
    for it in jsons:
        res = TM.NLP_unserialize(it[0])
        print("Resultado: %s" % res)
        assert res == correct_res
