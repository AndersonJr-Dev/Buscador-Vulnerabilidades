import os
import json
import datetime
import csv
from jinja2 import Template

class ReportGenerator:
    def __init__(self):
        self.templates_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
        
        # Criar diretório de templates se não existir
        os.makedirs(self.templates_dir, exist_ok=True)
        
        # Criar template HTML padrão se não existir
        self.create_default_templates()
        
    def create_default_templates(self):
        # Template HTML padrão
        html_template = """<!DOCTYPE html>
<html lang="pt-br">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Vulnerabilidades - {{ target }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            margin: 0;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            margin-bottom: 20px;
        }
        h1, h2, h3 {
            margin-top: 0;
        }
        .summary {
            background-color: #f8f9fa;
            padding: 15px;
            margin-bottom: 20px;
            border-radius: 5px;
        }
        .vulnerability {
            background-color: #fff;
            border: 1px solid #ddd;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 5px;
        }
        .critical {
            border-left: 5px solid #dc3545;
        }
        .high {
            border-left: 5px solid #fd7e14;
        }
        .medium {
            border-left: 5px solid #ffc107;
        }
        .low {
            border-left: 5px solid #20c997;
        }
        .info {
            border-left: 5px solid #17a2b8;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin-bottom: 20px;
        }
        table, th, td {
            border: 1px solid #ddd;
        }
        th, td {
            padding: 12px;
            text-align: left;
        }
        th {
            background-color: #f8f9fa;
        }
        .footer {
            margin-top: 30px;
            text-align: center;
            font-size: 0.8em;
            color: #6c757d;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>Relatório de Vulnerabilidades</h1>
            <p>Alvo: {{ target }}</p>
            <p>Data: {{ date }}</p>
        </header>
        
        <section class="summary">
            <h2>Resumo</h2>
            <p>Total de vulnerabilidades encontradas: {{ vulnerabilities|length }}</p>
            <table>
                <tr>
                    <th>Severidade</th>
                    <th>Quantidade</th>
                </tr>
                <tr>
                    <td>Crítica</td>
                    <td>{{ critical_count }}</td>
                </tr>
                <tr>
                    <td>Alta</td>
                    <td>{{ high_count }}</td>
                </tr>
                <tr>
                    <td>Média</td>
                    <td>{{ medium_count }}</td>
                </tr>
                <tr>
                    <td>Baixa</td>
                    <td>{{ low_count }}</td>
                </tr>
                <tr>
                    <td>Informativa</td>
                    <td>{{ info_count }}</td>
                </tr>
            </table>
        </section>
        
        <section>
            <h2>Vulnerabilidades Encontradas</h2>
            {% for vuln in vulnerabilities %}
            <div class="vulnerability {{ vuln.risk_level|lower }}">
                <h3>{{ vuln.type }}</h3>
                <p><strong>Severidade:</strong> {{ vuln.risk_level }}</p>
                <p><strong>URL:</strong> {{ vuln.url }}</p>
                <p><strong>Descrição:</strong> {{ vuln.description }}</p>
                {% if vuln.details %}
                <div>
                    <h4>Detalhes Técnicos:</h4>
                    <pre>{{ vuln.details|tojson(indent=4) }}</pre>
                </div>
                {% endif %}
            </div>
            {% endfor %}
        </section>
        
        <section>
            <h2>Recomendações</h2>
            <p>As seguintes recomendações são fornecidas para mitigar as vulnerabilidades encontradas:</p>
            <ul>
                {% if has_sql_injection %}
                <li><strong>SQL Injection:</strong> Utilize consultas parametrizadas ou prepared statements. Nunca concatene entradas do usuário diretamente em consultas SQL.</li>
                {% endif %}
                
                {% if has_xss %}
                <li><strong>Cross-Site Scripting (XSS):</strong> Sanitize todas as entradas de usuário. Utilize bibliotecas de escape HTML e implemente Content-Security-Policy.</li>
                {% endif %}
                
                {% if has_csrf %}
                <li><strong>Cross-Site Request Forgery (CSRF):</strong> Implemente tokens anti-CSRF em todos os formulários e requisições que alteram estado.</li>
                {% endif %}
                
                {% if has_open_redirect %}
                <li><strong>Redirecionamento Aberto:</strong> Valide todos os redirecionamentos contra uma lista de URLs permitidos ou use IDs que mapeiam para URLs internos.</li>
                {% endif %}
                
                {% if has_directory_traversal %}
                <li><strong>Directory Traversal:</strong> Não use entradas do usuário diretamente em operações de sistema de arquivos. Valide e sanitize caminhos de arquivo.</li>
                {% endif %}
                
                {% if has_file_inclusion %}
                <li><strong>File Inclusion:</strong> Desative inclusão remota de arquivos se não for necessária. Valide rigorosamente todos os caminhos de arquivo.</li>
                {% endif %}
                
                {% if has_information_disclosure %}
                <li><strong>Divulgação de Informações:</strong> Remova comentários desnecessários, mensagens de erro detalhadas e cabeçalhos que revelam informações sobre a infraestrutura.</li>
                {% endif %}
                
                {% if has_insecure_headers %}
                <li><strong>Cabeçalhos Inseguros:</strong> Implemente cabeçalhos de segurança como Content-Security-Policy, X-Frame-Options, X-XSS-Protection e Strict-Transport-Security.</li>
                {% endif %}
                
                {% if has_ssl_tls %}
                <li><strong>SSL/TLS:</strong> Configure HTTPS em todo o site, implemente HSTS e use apenas protocolos e cifras seguros.</li>
                {% endif %}
                
                {% if has_brute_force %}
                <li><strong>Força Bruta:</strong> Implemente limitação de taxa, CAPTCHA e bloqueio temporário de conta após múltiplas tentativas falhas.</li>
                {% endif %}
            </ul>
        </section>
        
        <div class="footer">
            <p>Relatório gerado por Scanner de Vulnerabilidades Web - Hacker Ético</p>
            <p>{{ date }}</p>
        </div>
    </div>
</body>
</html>"""
        
        html_template_path = os.path.join(self.templates_dir, "html_template.html")
        if not os.path.exists(html_template_path):
            with open(html_template_path, "w", encoding="utf-8") as f:
                f.write(html_template)
    
    def generate(self, vulnerabilities, format="html", target="", output_dir=""):
        # Criar diretório de saída se não existir
        if not output_dir:
            output_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports")
        
        os.makedirs(output_dir, exist_ok=True)
        
        # Nome do arquivo baseado na data e alvo
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        target_name = target.replace("https://", "").replace("http://", "").replace("/", "_").replace(":", "_")
        if not target_name:
            target_name = "unknown_target"
            
        filename = f"vulnerability_report_{target_name}_{timestamp}"
        
        # Gerar relatório no formato especificado
        if format.lower() == "html":
            return self.generate_html(vulnerabilities, target, filename, output_dir)
        elif format.lower() == "pdf":
            return self.generate_pdf(vulnerabilities, target, filename, output_dir)
        elif format.lower() == "json":
            return self.generate_json(vulnerabilities, target, filename, output_dir)
        elif format.lower() == "csv":
            return self.generate_csv(vulnerabilities, target, filename, output_dir)
        else:
            raise ValueError(f"Formato de relatório não suportado: {format}")
    
    def generate_html(self, vulnerabilities, target, filename, output_dir):
        # Carregar template HTML
        template_path = os.path.join(self.templates_dir, "html_template.html")
        with open(template_path, "r", encoding="utf-8") as f:
            template_content = f.read()
        
        template = Template(template_content)
        
        # Contar vulnerabilidades por severidade
        severity_counts = {
            "critical_count": 0,
            "high_count": 0,
            "medium_count": 0,
            "low_count": 0,
            "info_count": 0
        }
        
        # Verificar tipos de vulnerabilidades presentes
        vuln_types = {
            "has_sql_injection": False,
            "has_xss": False,
            "has_csrf": False,
            "has_open_redirect": False,
            "has_directory_traversal": False,
            "has_file_inclusion": False,
            "has_information_disclosure": False,
            "has_insecure_headers": False,
            "has_ssl_tls": False,
            "has_brute_force": False
        }
        
        for vuln in vulnerabilities:
            # Contar por severidade
            if vuln["risk_level"] == "Crítica":
                severity_counts["critical_count"] += 1
            elif vuln["risk_level"] == "Alta":
                severity_counts["high_count"] += 1
            elif vuln["risk_level"] == "Média":
                severity_counts["medium_count"] += 1
            elif vuln["risk_level"] == "Baixa":
                severity_counts["low_count"] += 1
            elif vuln["risk_level"] == "Informativa":
                severity_counts["info_count"] += 1
            
            # Marcar tipos de vulnerabilidades
            vuln_type = vuln["type"].lower()
            if "sql" in vuln_type:
                vuln_types["has_sql_injection"] = True
            elif "xss" in vuln_type:
                vuln_types["has_xss"] = True
            elif "csrf" in vuln_type:
                vuln_types["has_csrf"] = True
            elif "redirect" in vuln_type:
                vuln_types["has_open_redirect"] = True
            elif "directory" in vuln_type or "traversal" in vuln_type:
                vuln_types["has_directory_traversal"] = True
            elif "inclusion" in vuln_type:
                vuln_types["has_file_inclusion"] = True
            elif "information" in vuln_type or "disclosure" in vuln_type:
                vuln_types["has_information_disclosure"] = True
            elif "header" in vuln_type:
                vuln_types["has_insecure_headers"] = True
            elif "ssl" in vuln_type or "tls" in vuln_type:
                vuln_types["has_ssl_tls"] = True
            elif "brute" in vuln_type or "força" in vuln_type:
                vuln_types["has_brute_force"] = True
        
        # Renderizar template
        html_content = template.render(
            target=target,
            date=datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S"),
            vulnerabilities=vulnerabilities,
            **severity_counts,
            **vuln_types
        )
        
        # Salvar arquivo HTML
        output_path = os.path.join(output_dir, f"{filename}.html")
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(html_content)
        
        return output_path
    
    def generate_pdf(self, vulnerabilities, target, filename, output_dir):
        # Primeiro gerar HTML
        html_path = self.generate_html(vulnerabilities, target, filename, output_dir)
        
        try:
            # Tentar converter HTML para PDF usando pdfkit (requer wkhtmltopdf instalado)
            import pdfkit
            
            output_path = os.path.join(output_dir, f"{filename}.pdf")
            pdfkit.from_file(html_path, output_path)
            
            return output_path
        except ImportError:
            # Se pdfkit não estiver disponível, retornar o HTML
            return html_path
    
    def generate_json(self, vulnerabilities, target, filename, output_dir):
        # Preparar dados para JSON
        report_data = {
            "target": target,
            "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "vulnerabilities": vulnerabilities,
            "summary": {
                "total": len(vulnerabilities),
                "by_severity": {
                    "critical": len([v for v in vulnerabilities if v["risk_level"] == "Crítica"]),
                    "high": len([v for v in vulnerabilities if v["risk_level"] == "Alta"]),
                    "medium": len([v for v in vulnerabilities if v["risk_level"] == "Média"]),
                    "low": len([v for v in vulnerabilities if v["risk_level"] == "Baixa"]),
                    "info": len([v for v in vulnerabilities if v["risk_level"] == "Informativa"])
                }
            }
        }
        
        # Salvar arquivo JSON
        output_path = os.path.join(output_dir, f"{filename}.json")
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report_data, f, indent=4, ensure_ascii=False)
        
        return output_path
    
    def generate_csv(self, vulnerabilities, target, filename, output_dir):
        # Salvar arquivo CSV
        output_path = os.path.join(output_dir, f"{filename}.csv")
        
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            
            # Cabeçalho
            writer.writerow(["Tipo de Vulnerabilidade", "Severidade", "URL", "Descrição", "Detalhes"])
            
            # Dados
            for vuln in vulnerabilities:
                writer.writerow([
                    vuln["type"],
                    vuln["risk_level"],
                    vuln["url"],
                    vuln["description"],
                    json.dumps(vuln.get("details", {}), ensure_ascii=False)
                ])
        
        return output_path