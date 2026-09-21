import xml.etree.ElementTree as ET
import re

def parse_nmap_xml(xml_content):
    """Parse nmap XML output into a structured dictionary"""
    try:
        # Parse XML content
        root = ET.fromstring(xml_content)
        
        # Extract scan info
        scan_info = {
            'scanner': root.attrib.get('scanner', 'nmap'),
            'args': root.attrib.get('args', ''),
            'start_time': root.attrib.get('start', ''),
            'version': root.attrib.get('version', '')
        }
        
        # Initialize results structure
        results = {
            'scan_info': scan_info,
            'hosts': []
        }
        
        # Process each host
        for host_elem in root.findall('./host'):
            host = {
                'status': host_elem.find('./status').attrib.get('state', 'unknown'),
                'addresses': [],
                'hostnames': [],
                'ports': [],
                'os_matches': [],
                'scripts': []
            }
            
            # Extract addresses
            for addr_elem in host_elem.findall('./address'):
                host['addresses'].append({
                    'addr': addr_elem.attrib.get('addr', ''),
                    'addrtype': addr_elem.attrib.get('addrtype', ''),
                    'vendor': addr_elem.attrib.get('vendor', '')
                })
            
            # Extract hostnames
            hostnames_elem = host_elem.find('./hostnames')
            if hostnames_elem is not None:
                for hostname_elem in hostnames_elem.findall('./hostname'):
                    host['hostnames'].append({
                        'name': hostname_elem.attrib.get('name', ''),
                        'type': hostname_elem.attrib.get('type', '')
                    })
            
            # Extract ports and services
            ports_elem = host_elem.find('./ports')
            if ports_elem is not None:
                for port_elem in ports_elem.findall('./port'):
                    port = {
                        'protocol': port_elem.attrib.get('protocol', ''),
                        'portid': port_elem.attrib.get('portid', ''),
                        'state': {},
                        'service': {},
                        'scripts': []
                    }
                    
                    # Port state
                    state_elem = port_elem.find('./state')
                    if state_elem is not None:
                        port['state'] = {
                            'state': state_elem.attrib.get('state', ''),
                            'reason': state_elem.attrib.get('reason', ''),
                            'reason_ttl': state_elem.attrib.get('reason_ttl', '')
                        }
                    
                    # Service info
                    service_elem = port_elem.find('./service')
                    if service_elem is not None:
                        port['service'] = {
                            'name': service_elem.attrib.get('name', ''),
                            'product': service_elem.attrib.get('product', ''),
                            'version': service_elem.attrib.get('version', ''),
                            'extrainfo': service_elem.attrib.get('extrainfo', ''),
                            'ostype': service_elem.attrib.get('ostype', '')
                        }
                    
                    # Port scripts
                    for script_elem in port_elem.findall('./script'):
                        script = {
                            'id': script_elem.attrib.get('id', ''),
                            'output': script_elem.attrib.get('output', ''),
                            'tables': []
                        }
                        
                        # Extract script tables (for vulnerability data)
                        for table_elem in script_elem.findall('./table'):
                            table = {
                                'key': table_elem.attrib.get('key', ''),
                                'elements': {}
                            }
                            
                            # Process table elements
                            for elem in table_elem.findall('./elem'):
                                key = elem.attrib.get('key', '')
                                value = elem.text if elem.text else ''
                                table['elements'][key] = value
                            
                            script['tables'].append(table)
                        
                        port['scripts'].append(script)
                    
                    host['ports'].append(port)
            
            # Extract OS detection results
            os_elem = host_elem.find('./os')
            if os_elem is not None:
                for osmatch_elem in os_elem.findall('./osmatch'):
                    osmatch = {
                        'name': osmatch_elem.attrib.get('name', ''),
                        'accuracy': osmatch_elem.attrib.get('accuracy', ''),
                        'osclasses': []
                    }
                    
                    for osclass_elem in osmatch_elem.findall('./osclass'):
                        osmatch['osclasses'].append({
                            'type': osclass_elem.attrib.get('type', ''),
                            'vendor': osclass_elem.attrib.get('vendor', ''),
                            'osfamily': osclass_elem.attrib.get('osfamily', ''),
                            'osgen': osclass_elem.attrib.get('osgen', '')
                        })
                    
                    host['os_matches'].append(osmatch)
            
            # Extract host scripts
            for script_elem in host_elem.findall('./hostscript/script'):
                script = {
                    'id': script_elem.attrib.get('id', ''),
                    'output': script_elem.attrib.get('output', '')
                }
                host['scripts'].append(script)
            
            results['hosts'].append(host)
        
        # Process scan vulnerabilities
        vulnerabilities = extract_vulnerabilities(results)
        if vulnerabilities:
            results['vulnerabilities'] = vulnerabilities
            
        return results
        
    except Exception as e:
        # Return error information
        return {
            'error': str(e),
            'valid': False
        }

def extract_vulnerabilities(scan_results):
    """Extract vulnerability information from scan results"""
    vulnerabilities = []
    
    for host in scan_results.get('hosts', []):
        for port in host.get('ports', []):
            for script in port.get('scripts', []):
                # Check if script is related to vulnerability detection
                script_id = script.get('id', '')
                if 'vuln' in script_id or 'cve' in script_id.lower():
                    # Basic vulnerability info
                    vuln = {
                        'port': port.get('portid', 'N/A'),
                        'protocol': port.get('protocol', 'tcp'),
                        'service': port.get('service', {}).get('name', 'unknown'),
                        'name': script_id,
                        'output': script.get('output', ''),
                        'severity': 'medium',  # Default severity
                        'cve': 'N/A'
                    }
                    
                    # Extract CVE IDs from script output
                    cve_match = re.search(r'(CVE-\d{4}-\d{4,7})', script.get('output', ''))
                    if cve_match:
                        vuln['cve'] = cve_match.group(1)
                    
                    # Try to determine severity from script output
                    output = script.get('output', '').lower()
                    if any(x in output for x in ['critical', 'high risk']):
                        vuln['severity'] = 'critical'
                    elif 'high' in output:
                        vuln['severity'] = 'high'
                    elif any(x in output for x in ['medium', 'moderate']):
                        vuln['severity'] = 'medium'
                    elif any(x in output for x in ['low', 'minor']):
                        vuln['severity'] = 'low'
                    
                    # Extract more detailed information from script tables
                    for table in script.get('tables', []):
                        elements = table.get('elements', {})
                        
                        # Check for explicit severity
                        if 'severity' in elements:
                            vuln['severity'] = elements['severity']
                        
                        # Check for CVE
                        if 'id' in elements and 'CVE' in elements['id']:
                            vuln['cve'] = elements['id']
                            
                        # Extract other useful information
                        for key in ['description', 'title', 'state', 'solution']:
                            if key in elements:
                                vuln[key] = elements[key]
                    
                    vulnerabilities.append(vuln)
    
    return vulnerabilities