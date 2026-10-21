from octopusjar.http_client import HttpClient
from octopusjar.scope import Scope
from octopusjar.checks.cors import CorsCheck
from octopusjar.checks.headers import SecurityHeadersCheck
from octopusjar.checks.information_disclosure import InformationDisclosureCheck
from octopusjar.checks.methods import HttpMethodsCheck
from octopusjar.checks.redirects import OpenRedirectCheck
from octopusjar.reporting import Reporting

def auditoria_api_completa():
    # Endpoint específico da API alvo a ser auditada
    url_api = "https://api.exemplo.com/v1/recurso"
    
    # 1. Definir o escopo restrito ao endpoint ou domínio da API[span_2](start_span)[span_2](end_span)
    escopo = Scope(allowed_targets=[url_api])
    
    # 2. Configurar o cliente HTTP com cabeçalhos personalizados para a API
    # (por exemplo, tokens de autenticação Bearer e tipos de conteúdo)[span_3](start_span)[span_3](end_span)
    cabecalhos_api = {
        "Authorization": "Bearer o_seu_token_jwt_aqui",
        "Accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": "OctopusJar-APISecurityScanner/1.0"
    }
    
    http_client = HttpClient(
        scope=escopo, 
        default_headers=cabecalhos_api,
        timeout=10
    )
    
    # Validar se o alvo cumpre as regras de escopo[span_4](start_span)[span_4](end_span)
    if not escopo.is_allowed(url_api):
        print(f"Aviso: O alvo {url_api} está fora do escopo de segurança definido.")
        return

    print(f"A iniciar a auditoria de segurança completa na API: {url_api}\n")
    
    # 3. Instanciar todas as verificações de segurança do projeto[span_5](start_span)[span_5](end_span)
    checks = [
        CorsCheck(http_client=http_client),
        SecurityHeadersCheck(http_client=http_client),
        InformationDisclosureCheck(http_client=http_client),
        HttpMethodsCheck(http_client=http_client),
        OpenRedirectCheck(http_client=http_client)
    ]
    
    todos_os_resultados = []

    # 4. Executar cada verificação contra o endpoint da API[span_6](start_span)[span_6](end_span)
    for check in checks:
        nome_verificacao = check.__class__.__name__
        print(f"A executar o módulo: {nome_verificacao}...")
        try:
            # O módulo analisa o endpoint utilizando o cliente HTTP configurado[span_7](start_span)[span_7](end_span)
            resultados = check.run(url_api)
            if resultados:
                todos_os_resultados.extend(resultados)
                print(f" -> Encontradas {len(resultados)} ocorrências/avisos.")
            else:
                print(" -> Nenhuma vulnerabilidade detetada por este módulo.")
        except Exception as erro:
            print(f" -> Erro ao executar {nome_verificacao}: {erro}")

    # 5. Consolidar os dados e exportar para um relatório estruturado[span_8](start_span)[span_8](end_span)
    nome_ficheiro = "relatorio_auditoria_api.json"
    relatorio = Reporting(todos_os_resultados)
    relatorio.save_to_json(nome_ficheiro)
    
    print("\n--- Resumo da Auditoria da API ---")
    print(f"Total de ocorrências registadas: {len(todos_os_resultados)}")
    print(f"Relatório detalhado guardado com sucesso em: {nome_ficheiro}")

if __name__ == "__main__":
    auditoria_api_completa()
