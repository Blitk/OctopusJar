from octopusjar.http_client import HttpClient
from octopusjar.scope import Scope
from octopusjar.checks.cors import CorsCheck
from octopusjar.checks.headers import SecurityHeadersCheck
from octopusjar.checks.information_disclosure import InformationDisclosureCheck
from octopusjar.checks.methods import HttpMethodsCheck
from octopusjar.checks.redirects import OpenRedirectCheck
from octopusjar.reporting import Reporting

def executar_todos_os_checks():
    alvo = "https://exemplo.com"
    
    # 1. Configurar o escopo e o cliente HTTP
    escopo = Scope(allowed_targets=[alvo])
    http_client = HttpClient(scope=escopo)
    
    if not escopo.is_allowed(alvo):
        print(f"O alvo {alvo} não é permitido pelo escopo.")
        return

    print(f"Iniciando a execução de todos os checks de segurança para: {alvo}\n")
    
    # 2. Instanciar todas as verificações disponíveis no projeto
    checks = [
        CorsCheck(http_client=http_client),
        SecurityHeadersCheck(http_client=http_client),
        InformationDisclosureCheck(http_client=http_client),
        HttpMethodsCheck(http_client=http_client),
        OpenRedirectCheck(http_client=http_client)
    ]
    
    resultados_totais = []

    # 3. Executar cada check individualmente sobre o alvo
    for check in checks:
        nome_check = check.__class__.__name__
        print(f"Executando: {nome_check}...")
        try:
            # Cada check analisa o alvo e retorna as vulnerabilidades ou avisos encontrados
            resultados = check.run(alvo)
            resultados_totais.extend(resultados)
        except Exception as e:
            print(f"Erro ao executar {nome_check}: {e}")

    # 4. Consolidar e exportar os resultados utilizando o reporting
    relatorio = Reporting(resultados_totais)
    relatorio.save_to_json("relatorio_completo_checks.json")
    
    print("\nVarredura com todos os checks concluída com sucesso!")
    print(f"Total de ocorrências/achados registados: {len(resultados_totais)}")
    print("Relatório guardado em: relatorio_completo_checks.json")

if __name__ == "__main__":
    executar_todos_os_checks()
