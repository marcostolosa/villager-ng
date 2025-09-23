"""
Módulo de automação de navegador baseado em Playwright
Este módulo fornece capacidades avançadas de web scraping, reconnaissance web
e automação de navegador para operações de pentest automatizado.

PROPÓSITO TÉCNICO:
- Web scraping automatizado de aplicações alvo
- Reconnaissance de aplicações web e tecnologias
- Bypass de proteções JavaScript e SPAs
- Coleta de informações sensíveis em páginas web

FUNCIONALIDADES:
- Renderização completa de JavaScript via Chromium
- Múltiplos estados de espera (load, networkidle, domcontentloaded)
- Filtragem automática de tipos de arquivo desnecessários
- Extração de conteúdo HTML e texto limpo
- Base para crawling de domínios específicos

APLICAÇÃO NO VILLAGER-NG:
- Enumeração automática de endpoints web
- Coleta de tokens e informações sensíveis
- Mapeamento de estrutura de aplicações
- Descoberta de funcionalidades ocultas
- Bypass de proteções anti-scraping

DEPENDÊNCIAS:
- playwright: Motor de automação de navegador
- loguru: Sistema de logging estruturado

ALVOS IDENTIFICADOS:
- IP hardcoded: 100.64.0.33 (exemplo no código)
- Usado para reconnaissance de alvos específicos

CONSIDERAÇÕES DE SEGURANÇA:
- Executa JavaScript de páginas alvo (risco de RCE)
- Pode ser detectado por sistemas anti-bot
- Deixa rastros nos logs de acesso dos alvos
"""

from enum import Enum
from typing import List, Dict, Optional, Set
import time
import re
import urllib.parse

import loguru
from playwright.sync_api import sync_playwright, Playwright, Browser, Page


class WaitUntilState(Enum):
    """Estados de espera para carregamento de página."""
    LOAD = 'load'                    # Evento load disparado
    DOM_CONTENT_LOADED = 'domcontentloaded'  # DOM completamente carregado
    NETWORK_IDLE = 'networkidle'     # Sem requisições de rede por 500ms
    COMMIT = 'commit'                # Navegação commitada


class FILE_TYPE(Enum):
    """Tipos de arquivo para filtragem durante crawling."""
    JPG: str = 'jpg'
    PNG: str = 'png'
    GIF: str = 'gif'
    PDF: str = 'pdf'
    DOC: str = 'doc'
    DOCX: str = 'docx'
    XLS: str = 'xls'
    XLSX: str = 'xlsx'
    PPT: str = 'ppt'
    PPTX: str = 'pptx'
    TXT: str = 'txt'
    ZIP: str = 'zip'
    RAR: str = 'rar'
    GZ: str = 'gz'
    TAR: str = 'tar'
    BZ2: str = 'bz2'
    Z: str = 'z'
    TARGZ: str = 'tar.gz'


class CrawlerBase:
    """Classe base para configuração de crawler."""
    history_urls: List[str] = []
    thread_count: int = 1

    # Lista de tipos de arquivo a serem ignorados durante crawling
    black_list_file_type: List[FILE_TYPE] = [
        FILE_TYPE.JPG, FILE_TYPE.PNG, FILE_TYPE.GIF, FILE_TYPE.PDF,
        FILE_TYPE.DOC, FILE_TYPE.DOCX, FILE_TYPE.XLS, FILE_TYPE.XLSX,
        FILE_TYPE.PPT, FILE_TYPE.PPTX, FILE_TYPE.TXT, FILE_TYPE.ZIP,
        FILE_TYPE.RAR, FILE_TYPE.GZ, FILE_TYPE.TAR, FILE_TYPE.BZ2,
        FILE_TYPE.Z, FILE_TYPE.TARGZ
    ]


class Crawler(CrawlerBase):
    """
    Crawler web avançado baseado em Playwright para reconnaissance automatizado.

    Fornece capacidades de scraping com renderização JavaScript completa,
    ideal para análise de aplicações web modernas e SPAs.
    """

    def __init__(self, url: str, headless: bool = True, user_agent: str = None):
        """
        Inicializar crawler com URL alvo.

        Args:
            url (str): URL alvo para análise
            headless (bool): Executar navegador em modo headless (padrão: True)
            user_agent (str): User agent customizado (opcional)
        """
        self.url = url
        self.headless = headless
        self.user_agent = user_agent or self._get_default_user_agent()

        # Inicializar playwright
        self.playwright = sync_playwright().start()

        # Configurações de segurança e evasão
        self.browser_args = [
            '--no-sandbox',
            '--disable-setuid-sandbox',
            '--disable-dev-shm-usage',
            '--disable-accelerated-2d-canvas',
            '--no-first-run',
            '--no-zygote',
            '--disable-gpu'
        ]

        loguru.logger.info(f"Crawler inicializado para URL: {url}")

    def _get_default_user_agent(self) -> str:
        """Obter user agent padrão para evasão."""
        return "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

    def _create_browser_context(self) -> tuple[Browser, Page]:
        """
        Criar contexto de navegador com configurações de evasão.

        Returns:
            tuple: (Browser, Page) configurados
        """
        browser = self.playwright.chromium.launch(
            headless=self.headless,
            args=self.browser_args
        )

        # Configurar contexto com evasão de detecção
        context = browser.new_context(
            user_agent=self.user_agent,
            viewport={'width': 1920, 'height': 1080},
            locale='en-US',
            timezone_id='America/New_York'
        )

        # Injetar scripts de evasão
        context.add_init_script("""
            // Mascarar propriedades do webdriver
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});

            // Mascarar chrome automation
            window.chrome = {runtime: {}};

            // Mascarar plugins
            Object.defineProperty(navigator, 'plugins', {
                get: () => [1, 2, 3, 4, 5].map(() => 'Plugin')
            });
        """)

        page = context.new_page()
        return browser, page

    def get_page_content(self, wait_until: str = "networkidle", timeout: int = 30000) -> str:
        """
        Obter conteúdo HTML completo da página após renderização JavaScript.

        Args:
            wait_until (str): Estado de espera ('load', 'domcontentloaded', 'networkidle')
            timeout (int): Timeout em milissegundos (padrão: 30s)

        Returns:
            str: Conteúdo HTML completo da página

        Raises:
            Exception: Para erros de navegação ou timeout
        """
        loguru.logger.debug(f"Obtendo conteúdo da página: {self.url}")

        browser, page = self._create_browser_context()

        try:
            # Navegar para a página
            response = page.goto(
                self.url,
                wait_until=wait_until,
                timeout=timeout
            )

            # Verificar se a navegação foi bem-sucedida
            if response and response.status >= 400:
                loguru.logger.warning(f"Status HTTP {response.status} para {self.url}")

            # Aguardar renderização adicional se necessário
            page.wait_for_load_state("networkidle", timeout=5000)

            # Extrair conteúdo
            content = page.content()

            loguru.logger.debug(f"Conteúdo obtido: {len(content)} caracteres")
            return content

        except Exception as e:
            loguru.logger.error(f"Erro ao obter conteúdo de {self.url}: {e}")
            raise
        finally:
            browser.close()

    def get_page_text(self, wait_until: str = "networkidle", timeout: int = 30000) -> str:
        """
        Obter texto limpo da página (sem tags HTML).

        Args:
            wait_until (str): Estado de espera
            timeout (int): Timeout em milissegundos

        Returns:
            str: Texto limpo da página
        """
        loguru.logger.debug(f"Extraindo texto da página: {self.url}")

        browser, page = self._create_browser_context()

        try:
            page.goto(self.url, wait_until=wait_until, timeout=timeout)
            page.wait_for_load_state("networkidle", timeout=5000)

            # Extrair texto do body
            text_content = page.inner_text('body')

            loguru.logger.debug(f"Texto extraído: {len(text_content)} caracteres")
            return text_content

        except Exception as e:
            loguru.logger.error(f"Erro ao extrair texto de {self.url}: {e}")
            raise
        finally:
            browser.close()

    def extract_links(self, domain_filter: List[str] = None) -> List[str]:
        """
        Extrair todos os links da página com filtragem opcional por domínio.

        Args:
            domain_filter (List[str]): Lista de domínios permitidos (opcional)

        Returns:
            List[str]: Lista de URLs encontradas
        """
        loguru.logger.debug(f"Extraindo links de: {self.url}")

        browser, page = self._create_browser_context()

        try:
            page.goto(self.url, wait_until="networkidle")

            # Extrair todos os links
            links = page.query_selector_all('a[href]')
            urls = []

            for link in links:
                href = link.get_attribute('href')
                if href:
                    # Resolver URL relativa
                    absolute_url = urllib.parse.urljoin(self.url, href)

                    # Filtrar por domínio se especificado
                    if domain_filter:
                        parsed_url = urllib.parse.urlparse(absolute_url)
                        if not any(domain in parsed_url.netloc for domain in domain_filter):
                            continue

                    # Filtrar tipos de arquivo na blacklist
                    if not self._is_blacklisted_file(absolute_url):
                        urls.append(absolute_url)

            # Remover duplicatas mantendo ordem
            unique_urls = list(dict.fromkeys(urls))

            loguru.logger.info(f"Encontrados {len(unique_urls)} links únicos")
            return unique_urls

        except Exception as e:
            loguru.logger.error(f"Erro ao extrair links de {self.url}: {e}")
            return []
        finally:
            browser.close()

    def _is_blacklisted_file(self, url: str) -> bool:
        """
        Verificar se URL aponta para tipo de arquivo na blacklist.

        Args:
            url (str): URL para verificação

        Returns:
            bool: True se for arquivo blacklisted
        """
        parsed_url = urllib.parse.urlparse(url)
        path = parsed_url.path.lower()

        for file_type in self.black_list_file_type:
            if path.endswith(f'.{file_type.value}'):
                return True

        return False

    def extract_forms(self) -> List[Dict]:
        """
        Extrair informações de formulários da página.

        Returns:
            List[Dict]: Lista de informações de formulários
        """
        loguru.logger.debug(f"Extraindo formulários de: {self.url}")

        browser, page = self._create_browser_context()

        try:
            page.goto(self.url, wait_until="networkidle")

            # Extrair formulários
            forms = page.query_selector_all('form')
            form_data = []

            for i, form in enumerate(forms):
                form_info = {
                    'id': form.get_attribute('id') or f'form_{i}',
                    'action': form.get_attribute('action') or '',
                    'method': form.get_attribute('method') or 'GET',
                    'inputs': []
                }

                # Extrair campos de input
                inputs = form.query_selector_all('input, textarea, select')
                for input_elem in inputs:
                    input_info = {
                        'name': input_elem.get_attribute('name') or '',
                        'type': input_elem.get_attribute('type') or 'text',
                        'id': input_elem.get_attribute('id') or '',
                        'placeholder': input_elem.get_attribute('placeholder') or '',
                        'value': input_elem.get_attribute('value') or ''
                    }
                    form_info['inputs'].append(input_info)

                form_data.append(form_info)

            loguru.logger.info(f"Encontrados {len(form_data)} formulários")
            return form_data

        except Exception as e:
            loguru.logger.error(f"Erro ao extrair formulários de {self.url}: {e}")
            return []
        finally:
            browser.close()

    def take_screenshot(self, filepath: str, full_page: bool = True) -> bool:
        """
        Capturar screenshot da página.

        Args:
            filepath (str): Caminho para salvar o screenshot
            full_page (bool): Capturar página completa (padrão: True)

        Returns:
            bool: True se bem-sucedido
        """
        loguru.logger.debug(f"Capturando screenshot de: {self.url}")

        browser, page = self._create_browser_context()

        try:
            page.goto(self.url, wait_until="networkidle")

            page.screenshot(
                path=filepath,
                full_page=full_page
            )

            loguru.logger.info(f"Screenshot salvo em: {filepath}")
            return True

        except Exception as e:
            loguru.logger.error(f"Erro ao capturar screenshot: {e}")
            return False
        finally:
            browser.close()

    def crawler_for_domain(self, domain_list: List[str], max_depth: int = 3, max_pages: int = 100) -> Dict:
        """
        Realizar crawling completo de domínios especificados.

        Args:
            domain_list (List[str]): Lista de domínios para crawl
            max_depth (int): Profundidade máxima de crawling
            max_pages (int): Número máximo de páginas

        Returns:
            Dict: Resultados do crawling
        """
        loguru.logger.info(f"Iniciando crawling de domínios: {domain_list}")

        visited_urls: Set[str] = set()
        to_visit: List[tuple[str, int]] = [(self.url, 0)]  # (url, depth)
        results = {
            'pages': [],
            'links': [],
            'forms': [],
            'errors': []
        }

        while to_visit and len(visited_urls) < max_pages:
            current_url, depth = to_visit.pop(0)

            if current_url in visited_urls or depth > max_depth:
                continue

            try:
                # Atualizar URL do crawler
                old_url = self.url
                self.url = current_url

                # Extrair informações da página
                page_info = {
                    'url': current_url,
                    'depth': depth,
                    'timestamp': time.time()
                }

                # Extrair conteúdo
                try:
                    content = self.get_page_content()
                    page_info['content_length'] = len(content)
                    page_info['title'] = self._extract_title(content)
                except Exception as e:
                    page_info['error'] = str(e)
                    results['errors'].append({'url': current_url, 'error': str(e)})

                # Extrair links se não estiver na profundidade máxima
                if depth < max_depth:
                    try:
                        links = self.extract_links(domain_filter=domain_list)
                        for link in links:
                            if link not in visited_urls:
                                to_visit.append((link, depth + 1))
                        page_info['links_found'] = len(links)
                        results['links'].extend(links)
                    except Exception as e:
                        loguru.logger.warning(f"Erro ao extrair links de {current_url}: {e}")

                # Extrair formulários
                try:
                    forms = self.extract_forms()
                    page_info['forms_found'] = len(forms)
                    results['forms'].extend(forms)
                except Exception as e:
                    loguru.logger.warning(f"Erro ao extrair formulários de {current_url}: {e}")

                results['pages'].append(page_info)
                visited_urls.add(current_url)

                loguru.logger.info(f"Processada página {len(visited_urls)}: {current_url}")

                # Restaurar URL original
                self.url = old_url

                # Delay para evitar rate limiting
                time.sleep(1)

            except Exception as e:
                loguru.logger.error(f"Erro ao processar {current_url}: {e}")
                results['errors'].append({'url': current_url, 'error': str(e)})

        loguru.logger.info(f"Crawling concluído: {len(visited_urls)} páginas processadas")
        return results

    def _extract_title(self, html_content: str) -> str:
        """
        Extrair título da página do conteúdo HTML.

        Args:
            html_content (str): Conteúdo HTML

        Returns:
            str: Título da página
        """
        title_match = re.search(r'<title[^>]*>(.*?)</title>', html_content, re.IGNORECASE | re.DOTALL)
        if title_match:
            return title_match.group(1).strip()
        return ""

    def cleanup(self):
        """Limpar recursos do playwright."""
        try:
            self.playwright.stop()
            loguru.logger.debug("Playwright cleanup concluído")
        except Exception as e:
            loguru.logger.error(f"Erro durante cleanup: {e}")

    def __del__(self):
        """Destructor para garantir cleanup."""
        try:
            self.cleanup()
        except:
            pass


if __name__ == '__main__':
    # Teste de funcionalidade com IP hardcoded do sistema
    target_url = "http://100.64.0.33"

    loguru.logger.info(f"Iniciando teste de crawler para: {target_url}")

    try:
        # Criar instância do crawler
        crawler = Crawler(target_url, headless=True)

        # Teste 1: Obter conteúdo da página
        print("=== Teste 1: Conteúdo da página ===")
        content = crawler.get_page_content(wait_until="networkidle")
        print(f"Conteúdo obtido: {len(content)} caracteres")

        # Teste 2: Extrair texto limpo
        print("\n=== Teste 2: Texto da página ===")
        text = crawler.get_page_text()
        print(f"Texto extraído: {len(text)} caracteres")
        print(f"Primeiros 200 caracteres: {text[:200]}...")

        # Teste 3: Extrair links
        print("\n=== Teste 3: Links encontrados ===")
        links = crawler.extract_links()
        print(f"Links encontrados: {len(links)}")
        for i, link in enumerate(links[:5]):  # Mostrar apenas os primeiros 5
            print(f"  {i+1}: {link}")

        # Teste 4: Extrair formulários
        print("\n=== Teste 4: Formulários ===")
        forms = crawler.extract_forms()
        print(f"Formulários encontrados: {len(forms)}")
        for i, form in enumerate(forms):
            print(f"  Form {i+1}: {form['method']} -> {form['action']}")
            print(f"    Inputs: {len(form['inputs'])}")

        # Cleanup
        crawler.cleanup()

    except Exception as e:
        loguru.logger.error(f"Erro durante teste: {e}")
        print(f"Erro durante teste: {e}")

    print("\nTeste concluído.")
