####################################################################################
# tracer.py
# 		Performs code coverage analysis and produces a listing of each basic
# block that is hit while processing a given set of input.  Currently only 
# designed to work with applications receiving files as input, this could easily
# be adapted to work with network protocol based coverage as well.  
#
# 		Execution will take an input directory with the target files to trace, 
# and produce trace files in an output directory with a name corrisponding to 
# each given input file.  
####################################################################################
# Dependencies:
# 		- psutil python library (http://code.google.com/p/psutil/)
# 		- pywin32 python library (http://sourceforge.net/projects/pywin32/)
#		- Intel's PIN Binary Instrumentation Tool 
#			(http://software.intel.com/en-us/articles/pin-a-dynamic-binary-instrumentation-tool)
# 		- The Grugq's RunTrace Pintool (https://github.com/grugq/RunTracer)
#		- window_killer python library 
####################################################################################
# Usage:
Usage = '''
python tracer.py [options] [target application]
options:

-b [path to base directory]
	path to directory containing input files to be traced
	Default: "downloads"
-o [path to output directory]
	path to directory where trace files should be written to
	Default: "traced"
-t [path to pintool]
	path to the installation of PIN
	Default: "pintool"
-r [report interval]
	number of test cases to report progress, progress only reported if -v 
	is also specified
	Default: 100
-m [time in seconds]
	max amount of time to allow for each trace
	Default: 120 seconds
-c 
	Create a base file (open application and trace with no file input)
-k 
	Enable an embedded window_killer to attempt to automatically deal with 
	dialog boxes spawned by the program.  This window_killer is spawned
	for each instance of the target application that is spawned and only 
	deals with windows belonging to the target's PID
-p 
	Parallel Mode.  Meant to be run if multiple instances of the tracer
	are pulling from the same source file list and writing to the same 
	output directory.
	When used with -s, files with size 0 are skipped as well
-d 
	Delete base files after they have been successfully traced
-f
	Delete base files that have failed to open and close correctly
	Only works when the -e option is also supplied.
-s 
	Skip base files that already have a trace file present with file size 
	greater than 0
-e 
	Test each file without using PIN before running the trace.  Used to 
	weed out files that may cause issues with the target application before
	running the trace.
-v 
	Verbose Mode, includes progress updates and error messages
-h 
	Print the usage message and exit
'''
####################################################################################
# Imports:
import subprocess, os, time, sys, getopt, random
import psutil, win32gui, win32api, win32con, win32process
####################################################################################
# Global Variables:
baseFiles = []
baseDir = "downloads"
outputDir = "traced"
traceNameAppend = "-trace.txt"
pinDir = "pintool"
target = ""
reportEvery = 100
cpu_usage_sample = 0.5
max_time = 120
createBaseFile = False
baseTrace = "base.txt"
kill_windows = False
parallel = False
deleteTraced = False
deleteFailed = False
skipTraced = False
testEach = False
verbose = False
####################################################################################
# Functions

# Iterates through the active windows looking for windows belonging to the target
# process (PID specified by lparam) and sends the WM_CLOSE message to any 
# corisponding window objects.
def FindMainAndClose(hwnd, lparam):
	if win32process.GetWindowThreadProcessId(hwnd)[1] == lparam:
		try:
			win32api.PostMessage(hwnd, win32con.WM_CLOSE, 0, 0)
		except:
			pass

# Initialize the base file set and the base file directory (if specified)		
def InitializeBaseList(sourcePath=None):
	global baseFiles
	global baseDir
	global outputDir
	global traceNameAppend
	global parallel
	global skipTraced
	global verbose
	
	if sourcePath != None:
		baseDir = sourcePath
	startingSet = os.listdir(baseDir)
	baseFiles = []
	
	for file in startingSet:
		outFile = outputDir + os.sep + file + traceNameAppend
		if not ((parallel and os.path.exists(outFile)) or (skipTraced and os.path.exists(outFile) and int(os.path.getsize(outFile)) > 0)):
			baseFiles += [file]
	
	if parallel:
		random.shuffle(baseFiles)
	
	if verbose:
		print "Base Files Initialized... Tracing " + str(len(baseFiles)) + " Files..."

# Run a trace on the specified file, assumes all globals have been 
# properly initilized
def TraceFile(baseFile, outFile):
	global traceNameAppend
	global baseDir
	global target
	global pinDir
	global outputDir
	global max_time
	global kill_windows
	global deleteTraced
	global deleteFailed
	global testEach
	global verbose
	
	if not baseFile == "" and not os.path.exists(baseFile):
		return
	
	if not os.path.exists(outputDir):
		os.makedirs(outputDir)
	
	proc = None
	windowKiller = None
	
	if kill_windows:
		import window_killer
	
	if testEach:
		try:
			proc = psutil.Process(subprocess.Popen("\"" + target + "\" \"" + baseFile + "\"").pid)
			time.sleep(1)
			timeout = 0
			
			if kill_windows:
				windowKiller = window_killer.MultithreadedWindowKiller(proc.pid)
				windowKiller.start()
			
			try:
				testTimeout = 3
				if max_time / 8 < testTimeout:
					testTimeout = max_time / 8
				while proc.status != psutil.STATUS_DEAD and proc.get_cpu_percent(interval=cpu_usage_sample) < 1 and timeout < testTimeout:
					time.sleep(1)
					timeout += 1
				while proc.status != psutil.STATUS_DEAD and proc.get_cpu_percent(interval=cpu_usage_sample) > 1 and timeout < (max_time / 2):
					time.sleep(1)
					timeout += 1
				timeout = 0
				while proc.status != psutil.STATUS_DEAD and timeout < (testTimeout / 3):
					win32gui.EnumWindows(FindMainAndClose, proc.pid)
					time.sleep(1)
					timeout += 1
				if proc.status != psutil.STATUS_DEAD:
					proc.kill()
					if verbose:
						print "TEST FAILED: " + baseFile[baseFile.rfind("\\") + 1:]
					time.sleep(1)
					if deleteFailed:
						if verbose:
							print "REMOVING FAILED FILE"
						os.remove(baseFile)
					return
			except KeyboardInterrupt:
				if windowKiller != None:
					windowKiller.start_halt()
				raise KeyboardInterrupt()
			except:
				pass
		except KeyboardInterrupt:
			try:
				if proc != None:
					proc.kill()
			except:
				pass
			if windowKiller != None:
				windowKiller.start_halt()
			raise KeyboardInterrupt()
		if windowKiller != None:
			windowKiller.start_halt()	
	proc = pin = None
	try:
		proc = pin = psutil.Process(subprocess.Popen(pinDir + "\\ia32\\bin\\pin.exe -t " + pinDir + "\\source\\tools\\RunTracer\\obj-ia32\\ccovtrace.dll -o \"" + outFile + "\" -- \"" + target + "\" \"" + baseFile + "\"").pid)
		time.sleep(1)
		timeout = 0
		while timeout < 5:
			for p in psutil.process_iter():
				if p.name.lower() == target[target.rfind(os.sep) + 1:].lower():
					proc = p
					break
			if proc.name.lower() == target[target.rfind(os.sep) + 1:].lower():
				break
			time.sleep(1)
			timeout += 1
		if kill_windows:
			windowKiller = window_killer.MultithreadedWindowKiller(proc.pid)
			windowKiller.start()
		timeout = 0
		try:
			while proc.status != psutil.STATUS_DEAD and proc.get_cpu_percent(interval=cpu_usage_sample) > 1 and timeout < max_time:
				time.sleep(1)
				timeout += 1
			
			timeout = 0
			while proc.status != psutil.STATUS_DEAD and timeout < max_time:
				win32gui.EnumWindows(FindMainAndClose, proc.pid)
				time.sleep(1)
				timeout += 1
			
			if proc.status != psutil.STATUS_DEAD:
				pin.kill()
				proc.kill()
				if verbose:
					print "FAILED ON FILE: " + baseFile[baseFile.rfind("\\") + 1:]
				time.sleep(5)
			else:
				if os.path.exists(outFile) and int(os.path.getsize(outFile)) > 0:
					if deleteTraced:
						os.remove(baseFile)
				else:
					if verbose:
						print "FAILED ON FILE: " + baseFile[baseFile.rfind("\\") + 1:]
		except KeyboardInterrupt:
			if windowKiller != None:
				windowKiller.start_halt()
			raise KeyboardInterrupt()
		except:
			pass
	except KeyboardInterrupt:
		try:
			if proc != None:
				proc.kill()
		except:
			pass
		try:
			if pin != None:
				pin.kill()
		except:
			pass
		if windowKiller != None:
			windowKiller.start_halt()	
		raise KeyboardInterrupt()
	if windowKiller != None:
		windowKiller.start_halt()		
	
# calls TraceFile on each item in the baseFiles list, assumes all globals 
# initialized properly.  Progress is reported here according to the 
# reportEvery global variable
def TraceFiles():
	global baseFiles
	global reportEvery
	global skipTraced
	global verbose
	
	count = 1

	for baseFile in baseFiles:
		if not os.path.exists(baseDir + os.sep + baseFile):
			# if another instance is deleting files, precentage will not be reported correctly
			continue
		outFile = outputDir + os.sep + baseFile + traceNameAppend
		
		# Reports the progress of the tracer.  mod equal to 1 if reporting less than once per file, mod equal to 0 otherwise 
		if verbose and ((reportEvery > 1 and count % reportEvery == 1) or (reportEvery == 1 and count % reportEvery == 0)):
			print "Working on file " + str(count) + " of " + str(len(baseFiles)) + " (" + ("%0.2f" % (count * 100.0 / len(baseFiles))) + "%)" 

		# Run trace on a file
		# We need to check first if the trace should be run, these exact checks
		# are performed if the base file list is initialized using the 
		# InitializeBaseList funciton, but in the case where multiple tracers are being 
		# run, these checks need to be performed agian.
		if not ((parallel and os.path.exists(outFile)) or (skipTraced and os.path.exists(outFile) and int(os.path.getsize(outFile)) > 0)):
			TraceFile(baseDir + os.sep + baseFile, outFile)
		
		# remove the traced file
		if deleteTraced and os.path.exists(outFile) and int(os.path.getsize(outFile)) > 0 and os.path.exists(baseDir + os.sep + baseFile):
			os.remove(baseDir + os.sep + baseFile)
		
		count += 1

# Prints the command line usage if run as stand alone application.
def PrintUsage():
	global Usage
	print Usage
####################################################################################
# Main
def main(args):
	global baseDir
	global outputDir
	global pinDir
	global reportEvery
	global target
	global reportEvery
	global max_time
	global createBaseFile
	global baseTrace
	global kill_windows
	global parallel
	global deleteTraced
	global deleteFailed
	global skipTraced
	global testEach
	global verbose
	
	if len(args) < 2:
		PrintUsage()
		exit()
	
	optlist, argv = getopt.getopt(args[1:], 'b:o:t:r:m:ckpdfsevh')
	for opt in optlist:
		if opt[0] == '-b':
			baseDir = opt[1]
		elif opt[0] == '-o':
			outputDir = opt[1]
		elif opt[0] == '-t':
			pinDir = opt[1]
		elif opt[0] == '-r':
			reportEvery = int(opt[1])
		elif opt[0] == '-m':
			max_time = int(opt[1])
		elif opt[0] == '-c':
			createBaseFile = True
		elif opt[0] == '-k':
			kill_windows = True
		elif opt[0] == '-p':
			parallel = True
		elif opt[0] == '-d':
			deleteTraced = True
		elif opt[0] == '-f':
			deleteFailed = True
		elif opt[0] == '-s':
			skipTraced = True
		elif opt[0] == '-e':
			testEach = True
		elif opt[0] == '-v':
			verbose = True
		elif opt[0] == '-h':
			PrintUsage()
			exit()
	
	if len(argv) < 1:
		PrintUsage()
		exit()
	target = argv[0]
	
	try:
		if verbose:
			print "Initializing Tracer..."
		InitializeBaseList()
		
		if createBaseFile:
			if verbose:
				print "Creating Base File [base.txt]"
			TraceFile("", outputDir + os.sep + baseTrace)
			if verbose:
				print "Base File Created"
				
		if verbose:
			print "Starting Trace..."
		TraceFiles()
	except KeyboardInterrupt:
		print "Ctrl-C Detected - Ending Trace..."
####################################################################################
if __name__=="__main__":
	main(sys.argv)
####################################################################################