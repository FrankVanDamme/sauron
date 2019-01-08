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
# PATH
####################################
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

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

column_widths = [32, 8, 16, 32]

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
parser.add_argument('-c', '--configfile', help='Config json or yaml file', required=True, default=os.path.join(session['dir'], 'config/default.config.yaml'))
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
        print('Abort! Cannot access {}!'.format(services_log_file_path))
        exit(1)

####################################
# CONFIGURATION
####################################
cli_params = {}
cli_params['services'] = args.servicesfile
cli_params['config'] = args.configfile

for type, file_path in cli_params.items():
    if not os.path.isfile(file_path):
        print('Abort! Cannot access {}!'.format(file_path))
        exit(1)

    if not os.stat(file_path).st_size > 0:
        print('Abort! Empty file: {}!'.format(file_path))
        exit(1)


    with open(file_path) as file:
        if re.search('.+\.json$', file_path):
            session[type] = json.load(file)
        elif re.search('.+\.ya?ml$', file_path):
            try:
                session[type] = yaml.load(file)
            except yaml.YAMLError as exc:
                if hasattr(exc, 'problem_mark'):
                    mark = exc.problem_mark
                print("Error reading yaml, position: ({}:{})".format(mark.line + 1, mark.column + 1))
                exit(1)
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
        dir = os.path.expanduser(session['config']["dirs"][type])
    except:
        print('Abort! Directive dir:{} not set??'.format(type))
        exit(1)
    # use expanduser to deal with a tilda
    if os.path.isdir(dir) != True:
        print("Abort! {} dir {} not found!".format(type, dir))
        exit(1)

# set the variables
log_dir = os.path.normpath(os.path.expanduser(session['config']["dirs"]["log"]))
tmp_dir = os.path.normpath(os.path.expanduser(session['config']["dirs"]["tmp"]))

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
hits = {}

# setup warning levels
warning_levels = ['critical', 'warning', 'notice', 'info']

hits_level_max = ''

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

# # delete random service
# if monkey:
#     services = list(session['services'].keys())
#     random_service =  random.choice(services)
#     print('--> Monkey deleted service {} :)'.format(random_service))
#     session['services'].pop(random_service, None)
#     print()


# create the progress bar
number_of_services = len(session['services'].items())
bar = Bar('Scanning...', max=number_of_services)

print('Check {} services...'.format(len(session['services'].items())))
print()

# list of services per recipient
configured_services_per_recipient = {}

# request the urls
for service, service_config in session['services'].items():

    if debugmode:
        print('+ + Connect to service {} + +'.format(service))

    # Ports are handled in ~/.ssh/config since we use OpenSSH
    COMMAND = "df -Ph | grep -E '^/dev' | tr -s ' ' "

    timeout = str(session['config']['ssh_timeout'])
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
        bar.next()
        continue

    if debugmode:
        print()
        print('======> {} <======'.format(service))
        print(result)
        print()
        print('===> Service config:')
        print(service_config)
        print('===> Session config:')
        print(session['config']['thresholds'])

    for line in result:
        if debugmode:
            print(line)
        pieces = line.split(' ')
        mount = pieces[5].strip()
        # monkey mode
        if monkey:
            usage = random.randint(0, 100)
            size = '-'
        else:
            usage = int(pieces[4].strip('%'))
            size = '{}/{}+{}'.format(pieces[1], pieces[2], pieces[3])
            size = '{}/{}'.format(pieces[2], pieces[1])
        if debugmode:
            print('=> Checking mount {}, usage: {}'.format(mount, usage))

        thresholds = {}
        ####################################
        # CHECK CONFIG
        ####################################
        # ignored mounts
        skip_mount = False
        # the service config overrides the global config
        for resource in [service_config, session['config']]:
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
                        print('=> Skipping ignored mount: "{}"'.format(mount))

                    # pretty output per line
                    space=(30-len(service))*' '
                    line = '{};{};ignored;'.format(datetime_stamp, session['id'])
                    usage = '{}%'.format(usage)
                    column_fields = [service, usage, size, mount]
                    i = 0
                    for field in column_fields:
                        field = str(field).strip()
                        seperator = (column_widths[i] - len(field)) * ' '
                        line = line + field + seperator
                        i += 1

                    ignored_mounts.append(line)
                    skip_mount = True
                break

        #  ignore the mount
        if skip_mount:
            continue

        # threshold overriding
        for level in warning_levels:
            # global defaults
            if not level in session['config']['thresholds']['default']:
                print('Must have default thresholds in global config file! Missing level {}'.format(level))
                exit(1)
            else:
                thresholds[level] = session['config']['thresholds']['default'][level]
            # global override
            if mount in session['config']['thresholds']:
                if level in session['config']['thresholds'][mount]:
                    thresholds[level] = session['config']['thresholds'][mount][level]
            # service override
            if 'thresholds' in service_config:
                if 'default' in service_config['thresholds']:
                    if level in service_config['thresholds']['default']:
                        thresholds[level] = service_config['thresholds']['default'][level]
                # mount override
                if mount in service_config['thresholds']:
                    if level in service_config['thresholds'][mount]:
                        thresholds[level] = service_config['thresholds'][mount][level]

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
            if level not in hits:
                hits[level] = {}

            # pretty output per line
            line=''
            usage='{}%'.format(usage)
            column_fields = [service, usage, size, mount]

            i=0
            for field in column_fields:
                field=str(field).strip()
                seperator = (column_widths[i] - len(field)) * ' '
                line = line + field + seperator
                i+=1

            if service not in hits[level]:
                hits[level][service] = []
            hits[level][service].append(line)
            # set the maximum
            if hits_level_max == '':
                hits_level_max = warning_level
            else:
                if warning_level_weights[warning_level] > warning_level_weights[hits_level_max]:
                    hits_level_max = warning_level

        # store the status in tmp
        line = "{};{};{}\n".format(service, mount, warning_level)
        statuses.append(line)

    # build an array of all recipients and their services
    if session['config']['email']['enabled']:
        # check if secondary recipients need to be added
        if 'services' in session['config']['email'].keys() and session['config']['email']['services'] == True:
            search_config_files = [service_config, session['config']]
        else:
            search_config_files = [session['config']]
        # iterate
        for config in search_config_files:
            # setup notices
            if 'notify' in config:
                for recipient in config['notify']:
                    # check if email already exists
                    if not recipient in configured_services_per_recipient.keys():
                        configured_services_per_recipient[recipient] = []
                    # add this service
                    configured_services_per_recipient[recipient].append(service)
    bar.next()

bar.finish()

if debugmode:
    print('===> Services per recipient...')
    print(configured_services_per_recipient)
    print()

####################################
# SERVICES TMP AND LOG FILES
####################################
services_tmp_file = open(services_tmp_file_path, 'w')

print('===> Write log file... {}'.format(services_log_file_path))
services_log_file = open(services_log_file_path, 'a')

# store status
for status in statuses:
    services_tmp_file.write(status)

# log warnings
if len(hits):
    # log file
    for level, messages in hits.items():
        for service in messages.keys():
            for message in messages[service]:
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
if len(hits) == 0:
    global_status = 'OK!'
else:
    global_status = 'NOT OK'
    print('MAX WARNING LEVEL: {}'.format(hits_level_max.upper()))

print('SERVICES GLOBAL STATUS: {}!'.format(global_status, hits_level_max.upper()))

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
    print('===> Tmp files...')
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
changed_services = {}
# script is ran for the first time (or after reboot)
if len(service_tmp_files) == 1:
    print('No old runs detected...')
else:
    ####################################
    # COMPARE THE STATUSES
    # ####################################
    # store the statuses
    service_status_log = {}
    i = 0
    for run in ['new', 'old']:

        service_log_file_path = os.path.join(tmp_dir, service_tmp_files[i])
        # open the files
        service_log_file_handle = open(service_log_file_path, 'r')

        # store the contents of the files in a list
        service_log_lines = service_log_file_handle.readlines()

        # store the contents of the lists in a associative dictionary
        service_status_log[run] = {}

        ii = 0
        while ii < len(service_log_lines):
            # new services
            line = service_log_lines[ii].strip()
            p = line.split(';')
            service = p[0]
            status = p[2]
            service_status_log[run][service] = status
            ii += 1

        i += 1

    for service, new_status in service_status_log['new'].items():
        # do not compare a new service
        if not service in service_status_log['old']:
            changed_services[service] = new_status
            print('New service detected... {}'.format(service))
        elif not service_status_log['new'][service] == service_status_log['old'][service]:
            changed_services[service] = new_status
            print('Change in service detected... {}'.format(service))

if len(changed_services) == 0:
    print('No changes, no notifications...')

####################################
# COMPILE LIST OF EMAIL RECIPIENTS
####################################
notify_email = False
if session['config']['email']['enabled']:
    if len(changed_services) != 0:
        notify_email = True

changed_service_recipients = []
# check all services per recipent for changes
for recipient, services in configured_services_per_recipient.items():
    # check if changed
    for service in services:
        if service in changed_services:
            # check if in dict
            if not recipient in changed_service_recipients:
                changed_service_recipients.append(recipient)
                break

if debugmode:
    print('===> Changed services...')
    print(changed_services)
    print('===> Notify following recipients...')
    print(changed_service_recipients)

# log mails - purely for debugging - /tmp used
mail_log_file_path = os.path.join('/tmp', app_nickname + '.' + session['hash'] + '.' + datetime_stamp + '.' + session['id'] + '.mail.log')
mail_log_file = open(mail_log_file_path, 'a')

# pretty output
report = {}

# mark message if changed
message_mark = '(!)'

# hits
for level in warning_levels:
    if level in hits:
        # set key
        report[level] = []

        for service in hits[level]:
            for message in hits[level][service]:
                # mark changed service
                if service in changed_services.keys():
                    message = message + ' ' + message_mark
                report[level].append(message)

# failed connections
report['failed'] = []
if len(failed_connections):
    for f in failed_connections:
        report['failed'].append(f.split(';')[3].rstrip("\n"))

# ignored mounts
report['ignored'] = []
if len(ignored_mounts):
    for f in ignored_mounts:
        report['ignored'].append(f.split(';')[3])

print()
print('%%%%%% REPORT %%%%%%')
print()

types = warning_levels.copy()
types.append('failed')
types.append('ignored')
for type in types:
    if type not in report:
        continue

    print('%%% {} %%%'.format(type))
    # sort
    report[type] = sorted(report[type])
    # iterate services
    for b in report[type]:
        print(b)
    print()

# send messages
if notify_email:
    print()

    # no recipients
    if len(changed_service_recipients) == 0:
        print('No email recipients found...')
        print()
        exit()

    ####################################
    # PREPARE MAILS
    ####################################
    mails = {}

    for recipient in changed_service_recipients:

        level_max = ''
        hit_found = False

        hits_per_recipient = {}
        for level in warning_levels:
            hits_per_recipient[level] = []


        body = []
        # filter relevant messages
        for level, messages in hits.items():
            if len(messages):
                # add services
                for service in messages.keys():
                    if service in configured_services_per_recipient[recipient]:
                        # get max level for the subject
                        if level_max == '':
                            level_max = level
                        else:
                            if warning_level_weights[level] > warning_level_weights[level_max]:
                                level_max = level
                        for message in messages[service]:
                            hit_found = True
                            # mark changed service
                            if service in changed_services.keys():
                                message = message + ' ' + message_mark
                            hits_per_recipient[level].append(message)

        # services are OK
        if hit_found:
            for level in warning_levels:
                if level in hits_per_recipient.keys():
                    body.append('+++ ' + level.upper() + ' +++')

                    for message in hits_per_recipient[level]:
                        if len(message):
                            body.append(message)

                    body.append('')


            # check if notification limit is set for this user
            if recipient in session['config']['limit_notify']:
                if not level_max in session['config']['limit_notify'][recipient]:
                    continue

            status = 'DISK SPACE {}'.format(level_max.upper())
        else:
            status = 'DISK SPACE OK'

        # extra info for admins
        if recipient in session['config']['notify']:
            for type in ['failed', 'ignored']:
                body.append('+++ ' + type.upper() + ' +++')
                for b in report[type]:
                    body.append(b)
                body.append('')

        hostname = socket.gethostname()
        subject = app_nickname.upper() + ' @' + hostname + ' ' + status

        mails[recipient] = {}
        mails[recipient]['subject'] = subject
        mails[recipient]['body'] = body

    ####################################
    # SEND MAILS
    ####################################
    # iterate all mails
    fqdn = socket.getfqdn()
    # mail error
    mail_errors = []

    i=1
    # iterate all recipients
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
            print('------ MAIL {} ------'.format(i))
            print(' --- ', end='')
            print("\n --- ".join(message))
            print('---')
            print('Debugmode, skip sending mails...')
        else:
            try:
                print('Sending mail to server {}... '.format(session['config']['email']['server']), end='')
                smtpObj = smtplib.SMTP(session['config']['email']['server'], 25)
                # smtpObj.set_debuglevel(True)
                smtpObj.sendmail(sender, recipient, "\n".join(message))
                print("Successfully sent email to " + recipient + "...")
            except:
                print("Failed!")
                mail_log_file.write('ERROR sending mail to {}'.format(recipient))
                mail_errors.append(recipient)

        # log
        for line in message:
            mail_log_file.write(line)

        mail_log_file.write("\n\n --- \n\n")

        i+=1

    # close log file
    mail_log_file.close()

    if len(mail_errors):
        print('Sending of mails failed for recipients: {}'.format(', '.join(mail_errors)))
        exit(1)

print()
print('Bye...')
