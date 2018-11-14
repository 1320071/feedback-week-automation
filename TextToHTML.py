# *** Created by Mairi McQueer, Ben Gilmour & Sam Heney *** #

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
				line('p', 'Seconds: ' + nmapOutput['uptime']['seconds']')
				line('p', 'Last Boot: ' + nmapOutput['uptime']['lastboot']')

				line('h3', 'Adresses')
				line('p', 'Mac: ' + nmapOutput['addresses']['mac']')
				line('p', 'Ipv4: ' + nmapOutput['addresses']['ipv4']')

				line('h3', 'Host Vulnerabilities')
 				for vuln in nmapOutput['hostscript']:
					line('p',vuln['output'])
				
				line('h3', 'Ports') 
				with tag('table') 
					with tag('tr') # TODO test - does Yattag allow for python loops/statements to be intergrated like this?
						for port in nmapOutput['tcp']:
	        				line('td', 'str(port)')
	        				line('td', nmapOutput['tcp'][port]['name'])
	        				
							if len(nmapOutput['tcp'][port]['name']) < 8:
	            				# Need two tabs here so trying <pre> but not sure it will work...
								line('pre','    ') 
								line('pre','    ')
	        				try:
	            				for vuln in nmapOutput['tcp'][port]['script']:
	                				if 'VULNERABLE' in nmapOutput['tcp'][port]['script'][vuln]:
	                    				line('p',vuln + ":" )
	                    				line('p',nmapOutput['tcp'][port]['script'][vuln])
	        				except:
	            				pass
				
				line('h3','Hostnames')
				for hostname in nmapOutput['hostnames']: 
					if hostname['type']:
						line('p', 'Type: ' + hostname['type'])
						line('p', 'Name: ' + hostname['name'])
				
				line('h3','OS Match')
				for osmatch in scan['osmatch']:
					line('p','----------')
					line('p','Family: ' + osclass['osfamily'])
					line('p','Vendor: ' + osclass['vendor']))
					line('p','Type: ' + osclass['type'])
					line('p','OS Generation' + osclass['osgen'])
					line('p','Accuracy' + osclass['accuracy'])
					
	 log.write(doc.getvalue())
					
						
