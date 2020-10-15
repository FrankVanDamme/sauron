#! /usr/bin/python3

####################################
# IMPORT LIBRARIES
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
# import requests
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
# sleep
import time
# http requests:
# $ apt install python3-urllib3
# import urllib3
# yaml supprt
import yaml

# include 3d party libraries: add the lib/ dir to the path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'lib'))

# progress bar
from progress.bar import Bar

####################################
# CHANG DIR
####################################
abspath = os.path.abspath(__file__)
dname = os.path.dirname(abspath)
os.chdir(dname)

####################################
# VERSION
####################################
app_version = "2.3"
app_name = "sauron"
app_nickname = app_name + app_version.split('.')[0]
git_commits = os.popen('cd ' + os.path.dirname(os.path.abspath(__file__)) + '; git rev-list HEAD | wc -l 2>/dev/null;').read().rstrip()
git_hash = os.popen('cd ' + os.path.dirname(os.path.abspath(__file__)) + '; git rev-parse --short HEAD 2>/dev/null;').read().rstrip()
app_full_version = '{}.{}.{}'.format(app_version, git_commits, git_hash)

####################################
# SESSION
####################################
session = {}
session['dir'] = os.path.dirname(__file__)
session['id'] = str(uuid.uuid4())

argument_list_hash = sys.argv[1:]
# do not hash debugmode
hash_blacklist = ['-d', '--debug']

for option in hash_blacklist:
    if option in argument_list_hash:
        argument_list_hash.remove(option) # remove these options for the hash

session['hash'] = hashlib.md5('.'.join(argument_list_hash).encode('utf-8')).hexdigest()

# max tries to connect ssh
max_ssh_retry = 3

####################################
# DATE AND TIME
####################################
date_stamp = str(datetime.datetime.now().date())
format = '%Y-%m-%d_%H%M%S'
datetime_stamp = str(datetime.datetime.now().strftime(format))

# time the script
start_time = time.time()

####################################
# PARSE CLI ARGUMENTS
####################################
# check version
if sys.argv[1]:
    if sys.argv[1] == '-v' or sys.argv[1] == '--version':
        print(app_full_version)
        exit()

parser = argparse.ArgumentParser(description=app_name + app_version)
parser.add_argument('-c', '--configfile', help='Config json or yaml file', required=True, default=os.path.join(session['dir'], 'config/default.config.yaml'))
# flag without arguments
# parser.add_argument('-f', '--force', help='send a mail in any case', required=False, default=False, action='store_true')
parser.add_argument('-i', '--inode', help='check inode use, not disk', required=False, default=False, action='store_true')
parser.add_argument('-d', '--debug', help='debug mode', required=False, default=False, action='store_true')
parser.add_argument('-m', '--monkey', help='mokey mode', required=False, default=False, action='store_true')
parser.add_argument('-s', '--servicesfile', help='Services json or yaml file', required=True)
parser.add_argument('-v', '--version', help='version', required=False, action='store_true')
parser.add_argument('-q', '--query', help='Query', required=False)
parser.add_argument('--quiet', help='Do not send e-mails', required=False, default=False, action='store_true')
# parser.add_argument('-v', '--verbose', help='verbose', required=False, default=False, action='store_true')
# parser.add_argument('-t', '--tag', help='tag, e.g. server name', required=False, default=False)
args = parser.parse_args()

# we can do a query on the cli, e.g. which mounts larger than X percent
if args.query:

    if not re.search('^[<>]=?[0-9]{1,3}[%]$', args.query) and not re.search('^[!=]=?[0-9]{1,3}[%]$', args.query):
        print('Query must match a comparison operator! For example: <=50%')
        exit(1)

    query = {}

    query['operator'] = re.findall('^[^0-9]+', args.query)[0]

    query['value'] = int(re.findall('[0-9]+', args.query)[0])

# we can also measure inode usage rather than disk usage
if args.inode:
    inode = True
    verify_type = 'inode usage'
else:
    inode = False
    verify_type = 'disk space'

####################################
# DEBUGGING
####################################
monkey = False

# debugmode
if args.debug:
    debugmode = True
    # randomize values when in debug
    if args.monkey:
        monkey = True
else:
    debugmode = False

####################################
# PRE-FLIGHT CHECKS
####################################
cli_params = {}
cli_params['services'] = args.servicesfile
cli_params['config'] = args.configfile

for type, file_path in cli_params.items():
    # check if files provided on the cli exist
    if not os.path.isfile(file_path) and not os.path.islink(file_path):
        print('Abort! Cannot access {}! Does the file exist?'.format(file_path))
        exit(1)

    # check if files provided on the cli are not empty
    if not os.stat(file_path).st_size > 0:
        print('Abort! Empty file: {}!'.format(file_path))
        exit(1)

    # check if file is json or yaml, if so, load it
    with open(file_path) as file:
        if re.search('.+\.json$', file_path):
            session[type] = json.load(file)
        elif re.search('.+\.ya?ml$', file_path):
            try:
                session[type] = yaml.load(file, Loader=yaml.SafeLoader)
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

# check if log and tmp directories are configured properly
for type in ['log', 'tmp']:
    try:
        # use expanduser to deal with a tilda
        dir = os.path.expanduser(session['config']["dirs"][type])
    except:
        print('Abort! Directive dir:{} not set??'.format(type))
        exit(1)

    # check is the dir exists
    if os.path.isdir(dir) != True:
        print("Abort! {} dir {} not found!".format(type, dir))
        exit(1)

# set the variables
log_dir = os.path.normpath(os.path.expanduser(session['config']["dirs"]["log"]))
tmp_dir = os.path.normpath(os.path.expanduser(session['config']["dirs"]["tmp"]))

####################################
# FUNCTIONS
####################################
def pretty_title(string, type = 'h2'):
    string = ' {} '.format(string)

    if type == 'h1':
        symbol = '$'
        width = 80
    elif type == 'h2':
        symbol = '_'
        width = 80
    elif type == 'h3':
        symbol = '_'
        width = 60
    elif type == 'h4':
        symbol = '_'
        width = 40

    return string.center(width, symbol)

# 'System', 'Size', 'Used', 'Use%', 'Mount'
def pretty_df(service, size, used, used_percent, mount):

    line =  (service.ljust(36) + size.ljust(6) + used.ljust(6) + used_percent.ljust(6) + mount)
    return(line)

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
# CREATE LOCK FILE
####################################
lockfile = "/tmp/{}.LOCK.{}".format(app_nickname, session['hash'])

# it exists, abort
if os.path.isfile(lockfile):
    print('Abort, lock file exists! {}'.format(lockfile))
    exit(1)
# create it
else:
    file = open(lockfile, "w")
    # file.write("\n")
    file.close()

####################################
# KICK-OFF
####################################
print('Version: {} {}'.format(app_name, app_full_version))
print('Hash/ID: {} {}'.format(session['hash'], session['id']))
print()

####################################
# ITERATE SERVICES
####################################
messages = []
connectivity_checked = False

# write status in tmp file
statuses = []

# actual list of hits/warnings
hits = {}

# setup warning levels
warning_levels = ['full', 'critical', 'warning', 'notice', 'info']

# the highest hit level (subject of mail)
hits_level_max = ''

# add weights to the levels so we can determine the max value
warning_level_weights = {}
w = 0
for level in warning_levels:
    warning_level_weights[level] = w
    w -= 1

# tmp and log file paths
services_tmp_file_path = os.path.join(tmp_dir, app_nickname + '.' + session['hash'] + '.' + datetime_stamp + '.' + session['id'] + '.services.tmp')
services_log_file_path = os.path.join(log_dir, app_nickname + '.' + date_stamp + '.services.log')

# mail body categories
categories = {}
for type in ['ignored', 'unknown', 'failed', 'query']:
    categories[type] = []

# create the progress bar
if not debugmode:
    number_of_services = len(session['services'].items())
    bar = Bar('Scanning...', max=number_of_services)

print('Check {} for {} services...'.format(verify_type, len(session['services'].items())))
print()

# list of services per mail recipient
configured_services_per_recipient = {}

# do the request for the urls
for service, service_config in sorted(session['services'].items()):

    # if debugmode:
    #     print()
    #     print('+ + + + Connect to service {} + + + +'.format(service))
    #     print()

    if inode:
        options = "-Phi"
    else:
        options = "-Ph"

    # Ports are handled in ~/.ssh/config since we use OpenSSH
    COMMAND = "df " + options + " | grep -E '^/dev' | tr -s ' ' "

    timeout = str(session['config']['ssh_timeout'])

    i=0

    while i < max_ssh_retry:

        # do the command over ssh
        ssh = subprocess.Popen(["ssh", '-o BatchMode=yes', '-o ConnectTimeout='+timeout, "%s" % service, COMMAND], shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        output = ssh.stdout.readlines()

        if len(output) != 0:
            break

        # wait
        time.sleep(3)

        i += 1

    # continue if no connection can be established
    if len(output) == 0:
        error = ssh.stderr.readlines()
        if debugmode:
            print('Failed! Write connection error for {} to log file... {}'.format(service, services_log_file_path))
        services_log_file = open(services_log_file_path, 'a')
        line = "{};{};error;{} {}\n".format(datetime_stamp, session['id'], service, error[0].decode().rstrip())
        categories['failed'].append(line)
        services_log_file.write(line)
        services_log_file.close()
        if not debugmode:
            bar.next()
        continue

    # decode the result
    result = []
    for o in output:
        result.append((o.decode()))

    if debugmode:
        print()
        print(pretty_title(service, 'h1'))
        print()
        print(result)

        print()
        print(pretty_title('Service Config', 'h3'))
        print()
        print(service_config)

        print()
        print(pretty_title('Session Config', 'h3'))
        print()
        print(session['config']['thresholds'])

    for line in result:
        pieces = line.split(' ')
        mount = pieces[5].strip()
        if debugmode:
            print()
            print(pretty_title(mount, 'h4'))
            print()

            # print('Checking {}'.format(mount))
            print(line.rstrip())

        # ignored/unknown mounts
        ignored_mount = False
        unknown_mount = False

        # monkey mode
        if monkey:
            usage = random.randint(0, 100)
            size = '-'
        else:
            try:
                usage = int(pieces[4].strip('%'))
            except:
                usage = 0
                unknown_mount = True

            size = pieces[1]
            used = pieces[2]

        if debugmode:
            print('mount: {} usage: {}'.format(mount, usage))

        thresholds = {}

        ####################################
        # CHECK CONFIG
        ####################################
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
                    line = '{};{};ignored;'.format(datetime_stamp, session['id'])
                    used_percent = '{}%'.format(usage)

                    line = line + pretty_df(service, size, used, used_percent, mount) # 0

                    categories['ignored'].append(line)
                    ignored_mount = True
                break

        #  ignore the mount
        if ignored_mount:
            continue
        elif unknown_mount:
            categories['unknown'].append('{} {}'.format(service, mount))
            continue

        # threshold overriding
        for level in warning_levels:

            # skip full
            if level == 'full':
                thresholds[level] = 100
            # global defaults
            elif not level in session['config']['thresholds']['default']:
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

        # get query
        if args.query:

            comparison = str(usage) + ' ' + query['operator'] + ' ' + str(query['value'])

            if eval(comparison):
                line = '{};{};query;'.format(datetime_stamp, session['id'])
                used_percent = '{}%'.format(usage)
                line = line + pretty_df(service, size, used, used_percent, mount) # 1
                categories['query'].append(line)

        # set default to OK
        warning_level = 'OK'

        for level in warning_levels:

            # compare usage
            if usage >= thresholds[level]:
                warning_level = level
                break

        # compare with highest level
        if not warning_level == 'OK':
            # add this mount to the log
            if level not in hits:
                hits[level] = {}

            # pretty output per line
            line=''
            used_percent='{}%'.format(usage)

            line = line + pretty_df(service, size, used, used_percent, mount) # 2

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
    if not debugmode:
        bar.next()

if not debugmode:
    bar.finish()

# print()
# print(pretty_title('Report', 'h1'))
# print()

if debugmode:
    print()
    print(pretty_title('Services per Recipient'))
    print()
    print(configured_services_per_recipient)
    print()

####################################
# TMP AND LOG FILES
####################################
services_tmp_file = open(services_tmp_file_path, 'w')

print()
print(pretty_title('Log'))
print()
print('Write log file... {}'.format(services_log_file_path))
print()

services_log_file = open(services_log_file_path, 'a')

# store status
for status in statuses:
    services_tmp_file.write(status)
    # print nicely
    # print(status, end='')
    status_list = status.split(';')
    # print(list)
    # exit()
    mount_index = status_list[0] + ':' + status_list[1]
    print(mount_index.ljust(60, '.'), status_list[2], end = '')
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
print(pretty_title('Status'))
print()
# print final status
if len(hits) == 0:
    global_status = 'OK'
    global_status1 = 'OK'
else:
    global_status = 'NOT OK'
    global_status1 = hits_level_max.upper()

print('Global Status'.ljust(60, '.'), global_status1)
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
    print(pretty_title('Temporary Files'))
    print()
    for i in service_tmp_files:
        print(os.path.join(tmp_dir, i))

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
service_status_log = {}

####################################
# COMPARE THE STATUSES
####################################
# store the statuses
i = 0
for run in ['new', 'old']:

    # there are no old runs if running for the first time
    if len(service_tmp_files) == 1 and run == 'old':
        print('No old runs detected...')
        service_status_log['old'] = {}

    else:

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
            # print(line)
            p = line.split(';')
            service = p[0]
            mount = p[1]
            status = p[2]

            if service not in  service_status_log[run].keys():
                service_status_log[run][service] = {}

            service_status_log[run][service][mount] = status
            ii += 1

    i += 1

if debugmode:
    print()
    print(pretty_title('Compare Status'))
    print()

    for run in ['old', 'new']:
        for server, mounts in service_status_log[run].items():
            print(pretty_title(server + ' ({})'.format(run), 'h4'))
            for key, value in mounts.items():
                print(key.ljust(80, '.') + value)
        print()

old_services = list(service_status_log['old'].keys())
new_services = list(service_status_log['new'].keys())

for service in new_services:
    # do not compare a new service
    if not service in old_services:
        changed_services[service] = True
        print('New service detected... {}'.format(service))
    else:
        for mount, new_status in service_status_log['new'][service].items():
            if mount not in service_status_log['old'][service].keys():
                service_status_log['old'][service][mount] = ''

            if not service_status_log['new'][service][mount] == service_status_log['old'][service][mount]:
                changed_services[service] = True

    if service in changed_services.keys():
        print('Change in service detected... {}'.format(service))

if len(changed_services) == 0:
    print('No changes since last run...')
else:
    if debugmode:
        print('Changed Services:')
        print(changed_services)
print()

####################################
# COMPILE MAILING LIST
####################################
notify_email = False

# allow a quiet cli run
if args.quiet:
    print('Quiet mode is set...')
else:
    if session['config']['email']['enabled']:
        # print('E-mail enabled in config...')
        if len(changed_services) != 0 and global_status != 'OK':
            notify_email = True
        # elif args.force:
        #     notify_email = True

changed_service_recipients = []
# check all services per recipient for changes
for recipient, services in configured_services_per_recipient.items():
    # check if changed
    for service in services:
        if service in changed_services:
            # check if in dict
            if not recipient in changed_service_recipients:
                changed_service_recipients.append(recipient)
                break

if debugmode and len(changed_services) != 0:
    print()
    print(pretty_title('Changed Services', 'h3'))
    print()
    print(changed_services)
    print()
    print(pretty_title('Notify Recipients', 'h3'))
    print()
    print(changed_service_recipients)

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
                    message = message + ' ' + message_mark # 1
                report[level].append(message)

# gather the data and add to the report
for category, data in categories.items():
    report[category] = []
    if len(categories[category]):
        for f in categories[category]:
            report[category].append(f.split(';')[3].rstrip("\n"))

print()
# do some magic to capitalize every word in a string
print(pretty_title('{} Report '.format(" ".join([
   word.capitalize()
   for word in verify_type.split(" ")
]))))
print()

output = pretty_df('System', 'Size', 'Used', 'Use%', 'Mount') # 3
print(output)
print()

types = warning_levels.copy()
for type in categories.keys():
    types.append(type)

# issues to be reported
reported_issues = False

for type in types:
    if type not in report:
        continue

    if len(report[type]) == 0:
        continue

    title = type.upper()

    if type == 'query':
        title = title + ' ' + args.query

    print('+++ {} ({}) +++'.format(title, len(report[type])))
    # sort
    report[type] = sorted(report[type])
    # iterate services
    for b in report[type]:
        reported_issues = True
        print(b)
    print()

print()
print(pretty_title('Notifications'))
print()

if reported_issues is False:
    print('No issues reported, status OK.')

# send messages
if notify_email:
    if debugmode:
        print('Send notifcations (simulated)...')
    else:
        print('Send notifications (e-mail)...')

    print()

    # log mails - purely for debugging - /tmp used
    mail_log_file_path = os.path.join('/tmp', app_nickname + '.' + session['hash'] + '.' + datetime_stamp + '.' + session['id'] + '.mail.log')
    # open the mail log file
    mail_log_file = open(mail_log_file_path, 'a')

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

        # add verify type to body
        body.append('Verifying {}...'.format(verify_type))
        body.append('')

        # print the titles
        body.append(pretty_df('System', 'Size', 'Used', 'Use%', 'Mount'))
        body.append('')

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
            if 'limit_notify' in session['config']:
                if recipient in session['config']['limit_notify']:
                    if not level_max in session['config']['limit_notify'][recipient]:
                        continue

            status = '{} {}'.format(verify_type.upper(), level_max.upper())

        else:
            status = '{} OK'.format(verify_type.upper())

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
else:
    print('Not sending notifications...')

print()

####################################
# REMOVE LOCK FILE
####################################
# remove the lock file
if os.path.isfile(lockfile):
    os.remove(lockfile)

####################################
# WRAP UP
####################################
sec = int(round(time.time()-start_time))
script_time = datetime.timedelta(seconds =sec)
print('Script time:', script_time)
print()
print('Bye...')
