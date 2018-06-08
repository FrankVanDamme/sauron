#! /usr/bin/python3

####################################
# LIBRARIES
####################################
# parse cli arguments
import argparse
# caclulate a md5sum
import hashlib
# date, time
import datetime
# read the json file
import json
# status codes
#import requests
# read dirs and files
import os.path
# create a unique identifier per session
import uuid
# monkey
import random
# regular expressions
import re
# send mails
import smtplib
# get the hostname, network connection
import socket
# system calls
import sys
# ssh
import subprocess
# move files to other dirs
import shutil
# http requests:
# $ apt install python3-urllib3
#import urllib3
# yaml supprt
import yaml

# include 3d party libraries: add the lib/ dir to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))
# progress bar
from progress.bar import Bar
####################################
# MAIN VARIABLES
####################################
app_version = "2.0"
app_name = "sauron"
app_nickname = app_name + app_version.split('.')[0]

session = {}
session['dir'] = os.path.dirname(__file__)
session['id'] = str(uuid.uuid4())
session['hash'] = hashlib.md5('.'.join(sys.argv[1:]).encode('utf-8')).hexdigest()
####################################
# DATE AND TIME
####################################
date_stamp = str(datetime.datetime.now().date())
format = '%Y-%m-%d_%H%M%S'
datetime_stamp = str(datetime.datetime.now().strftime(format))

####################################
# PARSE ARGUMENTS
####################################
parser = argparse.ArgumentParser(description=app_name + app_version)
parser.add_argument('-s', '--servicesfile', help='Services json or yaml file', required=True)
parser.add_argument('-c', '--configfile', help='Config json or yaml file', required=False, default=os.path.join(session['dir'], 'config/default.config.yaml'))
# flag without arguments
parser.add_argument('-d', '--debugmode', help='debug mode', required=False, default=False, action='store_true')
#parser.add_argument('-v', '--verbose', help='verbose', required=False, default=False, action='store_true')
parser.add_argument('-m', '--monkey', help='mokey mode', required=False, default=False, action='store_true')
#parser.add_argument('-t', '--tag', help='tag, e.g. server name', required=False, default=False)
args = parser.parse_args()

####################################
# DEBUGMODE
####################################
if args.debugmode:
    debugmode = True
else:
    debugmode = False

####################################
# MONKEY
####################################
if args.monkey:
    monkey = True
else:
    monkey = False

for services_log_file_path in [args.configfile, args.servicesfile]:
    if not os.path.isfile(services_log_file_path) and not os.path.islink(services_log_file_path):
        print('Abort! {} is not a file!'.format(services_log_file_path))
        exit(1)

####################################
# CONFIGURATION
####################################
cli_params = {}
cli_params['services'] = args.servicesfile
cli_params['global_config'] = args.configfile

for type, file_path in cli_params.items():
    if not os.path.isfile(file_path):
        print('{} file not found!'.format(type))
        exit(1)

    with open(file_path) as file:
        if re.search('.+\.json$', file_path):
            session[type] = json.load(file)
        elif re.search('.+\.ya?ml$', file_path):
            session[type] = yaml.load(file)
        else:
            print('{} file not supported!'.format(type))
            exit(1)

    # sort the files
    cli_config_tmp = {}
    keys = sorted(list(session[type].keys()))
    for k in keys:
        cli_config_tmp[k] = session[type][k]
    session[type] = cli_config_tmp

####################################
# VALIDATE APP CONFIG
####################################
for type in ['log', 'tmp']:
    try:
        dir = os.path.expanduser(session['global_config']["dirs"][type])
    except:
        print('Abort! Directive dir:{} not set??'.format(type))
        exit(1)
    # use expanduser to deal with a tilda
    if os.path.isdir(dir) != True:
        print("Abort! {} dir {} not found!".format(type, dir))
        exit(1)

# set the variables
log_dir = os.path.normpath(os.path.expanduser(session['global_config']["dirs"]["log"]))
tmp_dir = os.path.normpath(os.path.expanduser(session['global_config']["dirs"]["tmp"]))

print()
print('{} {} ID {}'.format(app_name, app_version, session['id']))
print()

####################################
# FUNCTIONS
####################################

# notifications for the desktop
def desktop_notify(messages):

    print()
    print('Notify desktop...')

    # sudo apt install python3-notify2
    import notify2

    try:
        notify2.init(app_name + app_version)
        n = notify2.Notification(app_name.capitalize() + ' ' + app_version + ' warning', "\n".join(messages))
        n.show()
    except Exception as e:
        # the first one is usually the message.
        print('Could not notify desktop. Package python3-notify2 installed? {}'.format(e.args[1]))
        exit(1)

####################################
# ITERATE SERVICES
####################################
messages=[]
connectivity_checked = False

# write status in tmp file
statuses = []

# actual list of warnings
warnings = {}

# setup warning levels
warning_levels = ['critical', 'warning', 'notice', 'info']

warning_level_max = ''

warning_level_weights = {}
w = 0
for level in warning_levels:
    warning_level_weights[level] = w
    w -= 1

# file paths
services_tmp_file_path = os.path.join(tmp_dir, app_nickname + '.' + session['hash'] + '.' + datetime_stamp + '.' + session['id'] + '.services.tmp')
services_log_file_path = os.path.join(log_dir, app_nickname + '.' + date_stamp + '.services.log')

# failed ssh connections
failed_connections = []

# ignored mounts
ignored_mounts = []

if monkey:
    services = list(session['services'].keys())
    random_service =  random.choice(services)
    print('--> Monkey deleted service {} :)'.format(random_service))
    session['services'].pop(random_service, None)
    print()


# create the progress bar
number_of_services = len(session['services'].items())
bar = Bar('Scanning...', max=number_of_services)

print('Check {} services...'.format(len(session['services'].items())))
print()

# request the urls
for service, service_config in session['services'].items():

    # # check connectivity
    # if not connectivity_checked:
    #     connectivity_checked = True
    #     domain = service.split('//')[-1].split('/')[0].split('?')[0]
    #     try:
    #         # print('Connectivity check. Try {}... '.format(domain))
    #         resolved = socket.gethostbyname(domain)
    #     except OSError as e:
    #         print('Network connection failed! Cannot resolve {}. Error: "{}"...'.format(domain, e.args[1]))
    #         exit(1)
    if debugmode:
        print('+ + Connect to service {} + +'.format(service))

    # Ports are handled in ~/.ssh/config since we use OpenSSH
    COMMAND = "df -Ph | grep -E '^/dev' | tr -s ' ' "

    timeout = str(session['global_config']['ssh_timeout'])
    ssh = subprocess.Popen(["ssh", '-o BatchMode=yes', '-o ConnectTimeout='+timeout, "%s" % service, COMMAND], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    result = []
    output = ssh.stdout.readlines()
    for o in output:
        result.append((o.decode()))

    if len(result) == 0:
        error = ssh.stderr.readlines()
        if debugmode:
            print('Failed! Write connection error for {} to log file... {}'.format(service, services_log_file_path))
        services_log_file = open(services_log_file_path, 'a')
        line = "{};{};error;{} {}\n".format(datetime_stamp, session['id'], service, error[0].decode().rstrip())
        failed_connections.append(line)
        services_log_file.write(line)
        services_log_file.close()
        continue

    if debugmode:
        print()
        print('>>>>>>>>>>>>>>> {} >>>>>>>>>>>>>>>'.format(service))
        print(result)
        print()
        print('service config:')
        print(service_config)
        print('session config:')
        print(session['global_config']['thresholds'])

    for line in result:
        if debugmode:
            print(line)
        pieces = line.split(' ')
        mount = pieces[5].strip()
        usage = int(pieces[4].strip('%'))

        if debugmode:
            print()
            print('>>>')
            print('Checking mount {}, usage: {}'.format(mount, usage))

        thresholds = {}
        ####################################
        # CHECK CONFIG
        ####################################
        # ignored mounts
        skip_mount = False
        # the service config overrides the global config
        for resource in [service_config, session['global_config']]:
            # is there a key "ignored" and of so, does it contain the mount?
            if 'ignored' in resource:
                # check if trailing slash
                for m in resource['ignored']:
                    if re.search('^\/.+\/$', m):
                        print('Trailing slash in config not allowed: {}'.format(m))
                        exit(1)
                # check for mount in config
                if mount in resource['ignored']:
                    if debugmode:
                        print('Skipping ignored mount: "{}"'.format(mount))
                    line = '{};{};ignored;{} {} {}%'.format(datetime_stamp, session['id'], service, mount, usage)
                    ignored_mounts.append(line)
                    skip_mount = True
                break

        #  ignore the mount
        if skip_mount:
            continue

        # threshold overriding
        for level in warning_levels:
            # global defaults
            if not level in session['global_config']['thresholds']['default']:
                print('Must have default thresholds in global config file! Missing level {}'.format(level))
                exit(1)
            else:
                thresholds[level] = session['global_config']['thresholds']['default'][level]
            # global override
            if mount in session['global_config']['thresholds']:
                if level in session['global_config']['thresholds'][mount]:
                    thresholds[level] = session['global_config']['thresholds'][mount][level]
            # service override
            if 'thresholds' in service_config:
                if 'default' in service_config['thresholds']:
                    if level in service_config['thresholds']['default']:
                        thresholds[level] = service_config['thresholds']['default'][level]
                # mount override
                if mount in service_config['thresholds']:
                    if level in service_config['thresholds'][mount]:
                        thresholds[level] = service_config['thresholds'][mount][level]

        # print('thresholds calculated')
        # print(thresholds)

        warning_level = ''
        for level in warning_levels:
            if usage >= thresholds[level]:
                warning_level = level
                break

        # compare with highest level
        if warning_level == '':
            warning_level = 'OK'
        else:
            # add this mount to the log
            if level not in warnings:
                warnings[level] = []
            line = '{} {} {}%'.format(service, mount, usage)
            warnings[level].append(line)
            # set the maximum
            if warning_level_max == '':
                warning_level_max = warning_level
            else:
                if warning_level_weights[warning_level] > warning_level_weights[warning_level_max]:
                    warning_level_max = warning_level

        # store the status in tmp
        line = "{};{};{}\n".format(service, mount, warning_level)
        statuses.append(line)

    bar.next()

bar.finish()
print()

####################################
# SERVICES TMP AND LOG FILES
####################################
services_tmp_file = open(services_tmp_file_path, 'w')

print('Write log file... {}'.format(services_log_file_path))
services_log_file = open(services_log_file_path, 'a')

# store status
for status in statuses:
    services_tmp_file.write(status)

# log warnings
if len(warnings):
    # log file
    for level, messages in warnings.items():
        for message in messages:
            line = "{};{};{};{}\n".format(datetime_stamp, session['id'], level, message)
            services_log_file.write(line)
else:
    line = "{};{};OK".format(datetime_stamp, session['id'])

# close files
services_tmp_file.close()
services_log_file.close()

####################################
# STATUS LOG FILE
####################################
print()
# print final status
if len(warnings) == 0:
    global_status = 'OK!'
else:
    global_status = 'NOT OK'
    print('MAX WARNING LEVEL: {}'.format(warning_level_max.upper()))

print('SERVICES GLOBAL STATUS: {}!'.format(global_status, warning_level_max.upper()))

####################################
# STORE STATUSES
####################################
# get a list of all files in tmp dir
tmp_files = os.listdir(tmp_dir)

# add all the service tmp files to a list
service_tmp_files = []
for file in tmp_files:
    if re.search(app_nickname + '.' + session['hash'] + '.+\.services\.tmp$', file):
        service_tmp_files.append(file)

if debugmode:
    print()
    print('tmp files...')
    for i in service_tmp_files:
        print(i)

service_tmp_files.sort(reverse=True)

# just keep the 2 last files for comparison
# if not re.match('^/tmp/?$', tmp_dir):
i=2
while i < len(service_tmp_files):
    file = os.path.join(tmp_dir, service_tmp_files[i])
    # print(file)
    os.remove(file)
    # shutil.move(os.path.join(tmp_dir, service_tmp_files[i]), '/tmp')
    i += 1

hashes = []
changes = False
# script is ran for the first time (or after reboot)
if len(service_tmp_files) == 1:
    print('No old runs detected...')
else:
    # compare last 2 files
    for tmp_file in [service_tmp_files[0],service_tmp_files[1]]:
        hasher = hashlib.md5()
        with open(os.path.join(tmp_dir, tmp_file), 'rb') as afile:
            buf = afile.read()
            hasher.update(buf)
        hash = hasher.hexdigest()
        # print(hash)
        hashes.append(hash)

    # compare
    if not hashes[0] == hashes[1]:
        changes = True

if not changes:
    print('No changes, no notifications...')

####################################
# DESKTOP ALERT
####################################
# notify_desktop = False
# if session['global_config']['desktop']['enabled']:
#     if session['global_config']['desktop']['trigger'] == 'change':
#         if len(changes) != 0:
#             notify_desktop = True
#     # contiuous notifications
#     else:
#         if global_status == 'WARNING':
#             notify_desktop = True
#
# if notify_desktop:
#     desktop_notify(messages)

####################################
# COMPILE LIST OF EMAIL RECIPIENTS
####################################
notify_email = False
if session['global_config']['email']['enabled']:
    if changes:
        notify_email = True

# log mails - purely for debugging - /tmp used
mail_log_file_path = os.path.join('/tmp', app_nickname + '.' + session['hash'] + '.' + datetime_stamp + '.' + session['id'] + '.mail.log')
mail_log_file = open(mail_log_file_path, 'a')

# pretty output
report = []

# warnings
for level, messages in warnings.items():
    report.append('%%% ' + level.upper() + ' %%%')
    for message in messages:
        report.append(message)
    report.append('')

# failed connections
if len(failed_connections):
    report.append('%%% FAILED %%%')
    for f in failed_connections:
        report.append(f.split(';')[3].rstrip("\n"))
    report.append('')

# ignored mounts
if len(ignored_mounts):
    report.append('%%% IGNORED %%%')
    for f in ignored_mounts:
        report.append(f.split(';')[3])

print()
print('%%%%%% FINAL REPORT %%%%%%')
print()
for b in report:
    print(b)

# send messages
if notify_email:
    print()
    recipients_to_notify = []
    # messages

    recipients_to_notify = session['global_config']['notify']

    # no recipients
    if len(recipients_to_notify) == 0:
        print('No email recipients found...')
        print()
        exit()

    ####################################
    # PREPARE MAILS
    ####################################
    # no mail config - allow tmp files to be created!!
    if not session['global_config']['email']['enabled'] == True:
        print('Email not enabled...')
        print()
        exit()

    mails = {}

    for recipient in recipients_to_notify:
        mails[recipient] = {}

        if len(warnings):
            status = 'DISK SPACE ' + warning_level_max.upper()
        else:
            status = 'DISK SPACE OK'

        hostname = socket.gethostname()
        subject = app_nickname.upper() + ' @' + hostname + ' ' + status

        mails[recipient]['subject'] = subject
        mails[recipient]['body'] = report

    ####################################
    # SEND MAILS
    ####################################
    # iterate all mails
    fqdn = socket.getfqdn()
    for recipient in mails.keys():

        sender = app_nickname + '@' + fqdn

        message = []
        message.append('From: <' + sender + '>')
        message.append('To: <' + recipient + '>')
        message.append('Subject: ' + mails[recipient]['subject'])
        # newline between subject and message?
        message.append('')
        for line in mails[recipient]['body']:
            message.append(line)

        message.append('')
        message.append('Run ID: {}'.format(session['id']))

        if debugmode:
            print("\n".join(message))

        try:
            print('Sending mails to server {}...'.format(session['global_config']['email']['server']))
            smtpObj = smtplib.SMTP(session['global_config']['email']['server'], 25)
            # smtpObj.set_debuglevel(True)
            smtpObj.sendmail(sender, recipient, "\n".join(message))
            print("Successfully sent email to " + recipient + "...")
        except:
            print("Error! Unable to send email...")
            mail_log_file.write('ERROR sending mail to {}'.format(recipient))
            exit(1)

        # log
        for line in message:
            mail_log_file.write(line)

        mail_log_file.write("\n\n --- \n\n")

    # close log file
    mail_log_file.close()

print()
print('Bye...')
