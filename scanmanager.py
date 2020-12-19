import os

from PIL import Image

# Threat Levels
#
# 0: None
# 1-10: Minimal
# 11-20: Low
# 21-30: Moderate
# 31-40: High

# File Type Attributes
# 
# These are useful bits of info about the file type
#
# 'container': is the file type a container (e.g. compressed archives)
# 'multiple-extensions': can the file type have multiple extensions in the file name, e.g. 'tar.gz'
# 'executable': binary file containing executable code 
# 'installer': can the file be used to install software. Implies container=True
# 'disable-previews': don't allow previews for the type
# 'macros': file can contain macros -- a data file containing executable code
# 'script': file contains programming code, e.g. Bash, Python, and PowerShell scripts
# 'hidden-info': File can be used to store data for malware, such as a metadata section

class FileType:
	'''Class to encapsulate information about a file type'''
	
	def __init__(self):

		# Friendly name of the file type
		self.name = ''

		# List of extensions the file type can have
		self.extensions = list()

		# Starting threat level of the file
		self.threat_base = 0

		# Flags for the file type
		self.attributes = list()

		# If the file is specific to a platform. For example, '.deb' == Linux
		self.platform = ''
	
	def check_requirements(self) -> str:
		'''Method for child classes to ensure that requirements have been met. Returns an error 
		message on failure.'''
		return ''
	
	def check_format(self, filepath: str) -> str:	# pylint: disable=unused-argument
		'''Method for child classes to validate the file format. If anything is amiss, an error 
		string is returned'''
		return ''

	def generate_preview(self, filepath: str) -> (str, str):	# pylint: disable=unused-argument
		'''Method for child classes to implement to create a preview. It returns a tuple containing 
		two strings: the first is an error string which is empty on success, and the second is the 
		path to the file containing the preview. It is empty if there is an error. The file must be 
		deleted by the caller.'''
		return ('unimplemented', '')


class PlainTextType(FileType):
	'''File type representing plain text files'''
	
	def __init__(self):
		super().__init__()
		self.name = 'Plain text'
		self.extensions = [ 'adoc', 'config', 'ini', 'md', 'txt' ]

	def check_format(self, filepath: str) -> str:
		'''Checks the file to see if it contains non-displayable characters. Expects ASCII or UTF-8'''
		
		rawdata = None
		with open(filepath, 'rb') as f:
			rawdata = f.read()
		
		try:
			rawdata.decode()
		except:
			return 'File contains unrecognized characters'
		return ''


class ScriptType(FileType):
	'''Scripting languages, such as Bash, Ruby, and PowerShell'''
	
	def __init__(self):
		super().__init__()
		self.name = 'Programming script'
		self.extensions = [ 'c', 'cpp', 'css', 'h', 'hpp', 'js', 'php', 'ps1', 'py', 'rb', 'rs', 
			'sh' ]
		self.attributes = [ 'script' ]
		self.threat_base = 1

	def check_format(self, filepath: str) -> str:
		'''Checks the file to see if it contains non-displayable characters. Expects ASCII or UTF-8'''
		
		rawdata = None
		with open(filepath, 'rb') as f:
			rawdata = f.read()
		
		try:
			rawdata.decode()
		except:
			return 'File contains unrecognized characters'
		return ''


class JPEGType(FileType):
	'''JPEG photos'''
	
	def __init__(self):
		super().__init__()
		self.name = 'JPEG Photo'
		self.extensions = [ 'jpg', 'jpeg' ]
		self.attributes = [ 'hidden-info' ]
		self.threat_base = 1

	def check_format(self, filepath: str) -> str:
		'''Attempts to load file'''
		try:
			with Image.open(filepath) as im:
				if im.format != 'JPEG':
					return 'File is not a JPEG photo'
		except OSError:
			return "Corrupted file contents"
		
		return ''

	def generate_preview(self, filepath: str) -> (str, str):
		'''A file preview for JPEG is itself. :)'''
		return ('', filepath)

class PDFType(FileType):
	'''PDF documents'''
	
	def __init__(self):
		super().__init__()
		self.name = 'Adobe PDF Document'
		self.extensions = [ 'pdf' ]
		self.attributes = [ 'macros', 'hidden-info' ]
		self.threat_base = 3


class WordType(FileType):
	'''Microsoft Word Documents'''
	
	def __init__(self):
		super().__init__()
		self.name = 'Microsoft Word Document'
		self.extensions = [ 'doc', 'docx' ]
		self.attributes = [ 'macros', 'hidden-info' ]
		self.threat_base = 3


class ScanManager:
	'''Object which manages the file scan information and associated code'''

	def __init__(self):
		self.types = list()
		self._load_types()
	
	def _load_types(self):
		'''Loads the file type objects needed for scanning'''
		self.types.append(PlainTextType())
		self.types.append(ScriptType())
		self.types.append(JPEGType())
		self.types.append(PDFType())
		self.types.append(WordType())
	
	def get_type(self, filepath: str) -> FileType:
		'''Checks to see if the file given is supported by the manager'''
		ext = os.path.splitext(filepath)[1].casefold()
		if ext[0] == '.':
			ext = ext[1:]
		
		for ftype in self.types:
			if ext in ftype.extensions:
				return ftype
		return None
	
	def scan(self, filepath: str) -> dict:
		'''Scans a file for threat level'''
		out = { 'name' : filepath }
		ftype = self.get_type(filepath)
		if ftype:
			out['supported'] = True
			out['description'] = ftype.name
		
		threat_level = ftype.threat_base

		if threat_level > 30:
			out['danger'] = 'High'
		elif threat_level > 20:
			out['danger'] = 'Moderate'
		elif threat_level > 10:
			out['danger'] = 'Low'
		elif threat_level > 0:
			out['danger'] = 'Minimal'
		else:
			out['danger'] = 'None'
		
		return out
