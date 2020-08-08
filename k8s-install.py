#!/usr/bin/env python3

# k8s-install is a script to install 3 nodes kubernetes cluster on VMware Fusion or workstation.
#
# Authored by Mohanad Elamin (melamin@paloaltonetworks.com)
#

__author__ = "Mohanad Elamin @mohanadelamin"
__version__ = "1.0"
__license__ = "MIT"

import os
import os.path
import sys
import requests
import time
from platform import system
from subprocess import call
from paramiko.client import SSHClient as SSH_Client
from paramiko.ssh_exception import \
	BadHostKeyException as SSH_BadHostKeyException, \
	AuthenticationException as SSH_AuthenticationException, \
	SSHException as SSH_SSHException
from socket import error as socket_error

from argparse import ArgumentParser
from datetime import datetime as dt
from configparser import ConfigParser
from logging import basicConfig as logging_basicConfig, \
	addLevelName as logging_addLevelName, \
	getLogger as logging_getLogger, \
	log as logging_log, \
	DEBUG   as logging_level_DEBUG, \
	INFO    as logging_level_INFO, \
	WARN    as logging_level_WARN, \
	ERROR   as logging_level_ERROR, \
	debug   as debug, \
	info    as info, \
	warn    as warn, \
	error   as error
from re import search as re_search, sub as re_sub
from signal import signal as signal_set_handler, SIGINT as signal_SIGINT

K8S_INSTALL_DESCRIPTION = """
	k8s-install is a script to deploy 3 nodes kubernetes cluster on VMware Fusion or Workstation.
	
	Requirements:
		python >= 3
		
"""

LOGGING_LEVELS = {
	'ERROR' : {
		'level' : logging_level_ERROR,
		'name'  : 'ERROR',
		'xterm' : '31m',
		'256color': '38;5;196m',
	},
	'NORMAL' : {
		'level' : 35,
		'name'  : 'CAD',
		'xterm' : '37m',
		'256color': '38;5;255m',
	},
	'WARNING' : {
		'level' : logging_level_WARN,
		'name'  : 'WARNING',
		'xterm' : '33m',
		'256color': '38;5;227m',
	},
	'INFO' : {
		'level' : logging_level_INFO,
		'name'  : 'INFO',
		'xterm' : '36m',
		'256color': '38;5;45m',
	},
	'DEBUG' : {
		'level' : logging_level_DEBUG,
		'name'  : 'DEBUG',
		'xterm' : '35m',
		'256color': '38;5;135m',
	},
}


#
# We allow the log level to be specified on the command-line or in the
# config by name (string/keyword), but we need to convert these to the
# numeric value:
#
LOGGING_LEVELS_MAP = {
	'NORMAL'    : LOGGING_LEVELS['NORMAL']['level'],
	'ERROR'     : logging_level_ERROR,
	'WARN'      : logging_level_WARN,
	'INFO'      : logging_level_INFO,
	'DEBUG'     : logging_level_DEBUG,
	'normal'    : LOGGING_LEVELS['NORMAL']['level'],
	'error'     : logging_level_ERROR,
	'warn'      : logging_level_WARN,
	'info'      : logging_level_INFO,
	'debug'     : logging_level_DEBUG
}

LAB_INFO = {
	'k8s-vm'	: {
		'name'	: 'k8s-lab',
		'ova'	: 'k8s-lab.ova',
		'user'	: 'root',
		'pass'	: 'PaloAlto!123',
		'ip'	: '192.168.55.144'
	},
	'ova_repo'	: 'https://www.github.com',
	'windows'	: {
		'vm_dir': 'Documents\Virtual Machines',
		'ovftool': 'c:\Program Files (x86)\VMware\VMware Workstation\OVFTool\ovftool.exe'
	},
	'macos'		: {
		'vm_dir': 'Virtual Machines.localized',
		'ovftool': '/Applications/VMware Fusion.app/Contents/Library/VMware OVF Tool/ovftool',
		'vmrun'	: '/Applications/VMware Fusion.app/Contents/Library/vmrun'
	}
}

def ssh_login(host, username, password):

	r = SSH_Client()
	r.load_system_host_keys()

	info("Trying to open a SSH connection to {}".format(host))

	try:
		r.connect(host, username=username, password=password)
	except SSH_BadHostKeyException as errstr:
		error("SSH host key for {0} could not be verified: {1}".format(host, errstr))
		return None
	except SSH_AuthenticationException:
		error("SSH authentication failed for {}".format(host))
		return None
	except SSH_SSHException as errstr:
		error("Unknown SSH error while connecting to {0}: {1}".format(host, errstr))
		return None
	except OSError as err:
		error("Can't connect to SSH server {0}: '{1}'".format(host, err))
		return None
	except:
		error("Unknown error encountered while connecting to SSH server {}".format(host))
		return None

	info("SSH connection to {} opened successfully".format(host))
	return r


def download_file(file_url, dir, file_name):
	with open(dir + file_name, 'wb') as f:
		info("Downloading {} from {}".format(file_name, file_url))
		response = requests.get(file_url, stream=True, verify=False)
		total_length = response.headers.get('content-length')
		if total_length is None:  # no content length header
			f.write(response.content)
		else:
			dl = 0
			total_length = int(total_length)
			for data in response.iter_content(chunk_size=4096):
				dl += len(data)
				f.write(data)
				done = int(50 * dl / total_length)
				sys.stdout.write("\r[%s%s]" %
								 ('*' * done, ' ' * (50 - done)))
				sys.stdout.flush()
		print('\n')
		info("Download done!")


def get_user_home():
	user_home = os.path.expanduser("~")
	return user_home


def find_ova(ova_name):
	user_home = get_user_home()
	for base, dirs, files, in os.walk(user_home):
		if ova_name in files:
			return os.path.join(base, ova_name)


def deploy_ova(ova_name):
	# try:
		info('Searching for the ova file {}'.format(ova_name))
		ova_path = find_ova(ova_name)
		if ova_path:
			info('OVA file found at {}'.format(ova_path))
		else:
			error('OVA file {} is not found. Please download it from {}'.format(ova_name, LAB_INFO['ova_repo']))
			return False

		if system() == 'Darwin':
			info('I am working on a MacOS')
			vm_dir = get_user_home() + os.sep + LAB_INFO['macos']['vm_dir']
			ovftool = LAB_INFO['macos']['ovftool']
			vmrun = LAB_INFO['macos']['vmrun']
			vmname = LAB_INFO['k8s-vm']['name']
			info('unpacking {} to {}'.format(ova_name, vm_dir))
			call([ovftool, ova_path, vm_dir])
			info('OVA Unpacking completed!')
			info('starting the VM')
			call([vmrun, 'start', vm_dir + os.sep + vmname + '.vmwarevm'])
		else:
			info('I am working on a Windows')

		for x in range(10):
			ssh_conn = ssh_login(LAB_INFO['k8s-vm']['ip'],LAB_INFO['k8s-vm']['user'],LAB_INFO['k8s-vm']['pass'])
			if ssh_conn:
				break
			else:
				info("Trying SSH connection again, retry #{}".format(x+1))

		if ssh_conn:
			stdin, stdout, stderr = ssh_conn.exec_command("hostname")
			info(stdout.read().decode())
			ssh_error = stderr.read().decode()
			if ssh_error:
				error(ssh_error)
	# except:
	# 	error("Sorry I can not deploy this ova image!")



def main():
	fmt_str = '%(asctime)s %(levelname)s: %(message)s'
	out_dev_istty = getattr(sys.stdout, 'isatty', None)

	if (out_dev_istty is not None) and (out_dev_istty()):
		if '256color' in os.environ['TERM']:
			for lvl in LOGGING_LEVELS.keys():
				logging_addLevelName(
					LOGGING_LEVELS[lvl]['level'],
					"\033[{0}{1}".format(
						LOGGING_LEVELS[lvl]['256color'],
						LOGGING_LEVELS[lvl]['name'])
				)
			fmt_str = '\033[38;5;250m%(asctime)s\033[0m %(levelname)s: ' \
				'%(message)s\033[0m'
		elif 'xterm' in os.environ['TERM']:
			for lvl in LOGGING_LEVELS.keys():
				logging_addLevelName(
					LOGGING_LEVELS[lvl]['level'],
					"\033[{0}{1}".format(
						LOGGING_LEVELS[lvl]['xterm'],
						LOGGING_LEVELS[lvl]['name'])
				)
			fmt_str = '\033[37m%(asctime)s\033[0m %(levelname)s: ' \
				'%(message)s\033[0m'
		else:
			logging_addLevelName(
				LOGGING_LEVELS['NORMAL']['level'],
				LOGGING_LEVELS['NORMAL']['name'])

	logging_basicConfig(
		format=fmt_str, level=logging_level_INFO,
		stream=sys.stdout)

	platform_check = system()

	# url='http://mirror.seedvps.com/CentOS/7.8.2003/isos/x86_64/CentOS-7-x86_64-Minimal-2003.iso'
	# dir_n='/Users/melamin/Data/scripts/k8siab/'
	# filename='CentOS-7-x86_64-Minimal-2003.iso'
	# download_file(url,dir_n,filename)

	deploy_ova(LAB_INFO['k8s-vm']['ova'])


if __name__ == "__main__":
	main()
	exit()