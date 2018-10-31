import yattag

def scanParse(nmapOutput, fileName):
    log = open(fileName, 'wb')
	doc,tag,text = yattag.Doc().tagtext()
	doc.asis('<!DOCTYPE html>') 

	with tag('html', lang ='en')
		with tag('head'):
			doc.asis('<meta charset="utf-8">')
			doc.asis('<meta name="viewport" content="width=device-width, initial-scale=1">')
			doc.asis('<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">')
	
		with tag('body'):

			with tag('div', id='NMAP'):
				line('h2', 'NMAP')	
				line('h3', 'Status')
				line('p', 'Status: ' + nmapOutput['status']['state'])
				line('p', 'Reason: ' + nmapOutput['status']['reason'])
				
				line('h3', 'Uptime')
				line('p', 'Seconds: " + nmapOutput['uptime']['seconds']')
				line('p', 'Last Boot: " + nmapOutput['uptime']['lastboot']')

				line('h3', 'Adresses')
				line('p', 'Mac: " + nmapOutput['addresses']['mac']')
				line('p', 'Ipv4: " + nmapOutput['addresses']['ipv4']')

				line('h3', 'Host Vulnerabilities')
 				for vuln in nmapOutput['hostscript']:
					line('p','vuln['output']')
				
				line('h3', 'Ports') 
				with tag('table')
					with tag('tr')
						line('td', 'Port Number')
						line('td', 'Service')
						line('td', 'Version')
					
					with tag('tr') # TODO fix
						for port in nmapOutput['tcp']:
	        				line('td', 'str(port)')
	        				line('td', nmapOutput['tcp'][port]['name'])

	        				if len(nmapOutput['tcp'][port]['name']) < 8:
	            				log.write("\t") # Wat?
	        					log.write("\t")
	        				try:
	            				for vuln in nmapOutput['tcp'][port]['script']:
	                				if 'VULNERABLE' in nmapOutput['tcp'][port]['script'][vuln]:
	                    				log.write(vuln + ":" + "\n")
	                    				log.write(nmapOutput['tcp'][port]['script'][vuln] + "\n")
	        				except:
	            				pass
	
			
		
def scanParse(nmapOutput, fileName):
	# Depricated function. This is being used as a template for html above
	# log.write == data to be added to html

    log.write("\n")
    log.write("Host Vulnerabilities: " + "\n")
    for vuln in nmapOutput['hostscript']:
        log.write(vuln['output'] + "\n")

    log.write("\n")
    log.write("Ports:" + "\n")
    for port in nmapOutput['tcp']:
        log.write(str(port))
        log.write("\t")
        log.write(nmapOutput['tcp'][port]['name'])
        if len(nmapOutput['tcp'][port]['name']) < 8:
            log.write("\t")
        log.write("\t")
        try:
            for vuln in nmapOutput['tcp'][port]['script']:
                if 'VULNERABLE' in nmapOutput['tcp'][port]['script'][vuln]:
                    log.write(vuln + ":" + "\n")
                    log.write(nmapOutput['tcp'][port]['script'][vuln] + "\n")
        except:
            pass
        log.write("\n")
    
    log.write("\n")
    log.write("Hostnames:" + "\n")
    for hostname in nmapOutput['hostnames']:
