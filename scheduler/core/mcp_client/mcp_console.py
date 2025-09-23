class McpConsole:
    def __init__(self, base_url: str = None):
        """
        Inicializar cliente de console MCP com configuração dinâmica.

        Args:
            base_url: URL base do servidor MCP. Se None, usa configuração do config.py
        """
        if base_url is None:
            from config import MCP
            base_url = MCP['server']['console']
        self.base_url = base_url
    def get_terminal(self):
        return