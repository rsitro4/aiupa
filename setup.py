from setuptools import setup, find_packages 

with open('requirements.txt') as f: 
	requirements = f.readlines() 

long_description = "Create a report to view all AWS IAM user permissions in your account." 

setup( 
		name ='aiupa', 
		version ='1.0.0', 
		author ='Rob Sitro', 
		author_email ='rob.sitro@chainalysis.com', 
		long_description = long_description, 
		long_description_content_type ="text/markdown", 
		license ='MIT', 
		packages = find_packages(), 
		entry_points ={ 
			'console_scripts': [ 
				'aiupa = aiupa.main:main'
			] 
		}, 
		classifiers =( 
			"Programming Language :: Python :: 3", 
			"License :: OSI Approved :: MIT License", 
			"Operating System :: OS Independent", 
		), 
		keywords ='aws aiupa auditor iam', 
		install_requires = requirements,
        zip_safe = False
    ) 
