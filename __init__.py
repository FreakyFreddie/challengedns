import os
from flask import Blueprint, render_template, request, abort, redirect, url_for
from CTFd.utils import admins_only, is_admin
from CTFd.models import db

import json

from subprocess import Popen, PIPE, STDOUT
import shlex

from .models import *
from .blacklist import *

def load(app):
    #create tables
    app.db.create_all()

    # create plugin blueprint with template folder
    challengedns = Blueprint('challengedns', __name__, template_folder='cdnstemplates')

    #valid configuration settions with their type
    valid_settings ={
        'DNS IP': ['text', '10.0.7.4'],
        'Root domain': ['text', 'ctf.be'],
        'Nameserver': ['text', 'ns1.ctf.be'],
        'Keyfile': ['text', '/opt/CTFd/nsupdate.key'],
        'Port': ['number', '53']
    }

    delete_format = '''\
            server {0}
            update delete {1} A
            send\
            '''

    create_format = '''\
        server {0}
        update add {1} {2} A {3}
        send\
        '''

    update_format = '''\
        server {0}
        update delete {1} A
        send
        server {0}
        update add {1} {2} A {3}
        send\
        '''

    # Set up route to configuration interface
    @challengedns.route('/admin/challengedns/configure', methods=['GET', 'POST'])
    @admins_only
    def configure():
        if request.method == 'POST':
            settings = {}
            errors = []

            for key in valid_settings:
                if key in request.form:
                    settings[key]=[valid_settings[key][0], request.form[key]]
                else:
                    errors.append("%s is not a valid setting." % key)

            # error handling
            if len(errors) > 0:
                return render_template('init_settings.html', errors=errors, settings=settings)
            else:
                #write all key-value pairs to database & redirect to manage
                for key in settings:
                    challengednsconfig = challengeDNSConfig.query.filter_by(option=key).first()

                    # if key does not exist in database, add entry, else update
                    if challengednsconfig == None:
                        challengednsconfig = challengeDNSConfig(key,settings[key][1])
                        db.session.add(challengednsconfig)
                        db.session.commit()
                        db.session.flush()
                    else:
                        challengednsconfig.value = settings[key][1]
                        db.session.commit()
                        db.session.flush()

                return redirect(url_for('.manage'), code=302)

        else:
            # generate dictionary with already filled in config options + empty options
            settings = config_opts_db()

            return render_template('init_settings.html', settings=settings)


    # Set up route to management interface
    @challengedns.route('/admin/challengedns/manage', methods=['GET'])
    @admins_only
    def manage():
        if not is_configured():
            return redirect(url_for('.configure'), code=302)
        else:
            errors = []
            records = []

            #if fetch_zone_records failed, return error
            try:
                records = fetch_zone_records()
            except Exception as e:
                print("Caught Exception : " + str(e))
                errors.append("Caught Exception : " + str(e))

            if len(errors) > 0:
                return render_template('manage.html', errors=errors, dns_records=[])

            return render_template('manage.html', dns_records=records)


    @challengedns.route('/admin/challengedns/manage/update', methods=['POST'])
    @admins_only
    def update_list():
        try:
            records = fetch_zone_records()
        except Exception as e:
            print("Caught Exception : " + str(e))
            return "Caught Exception : " + str(e)

        return json.dumps(records)

    @challengedns.route('/admin/challengedns/manage/record/<string:chalname>/delete', methods=['POST'])
    @admins_only
    def delete_record(chalname):
        try:
            return delete_operation(chalname)
        except Exception as e:
            print("Caught Exception : " + str(e))
            return "Caught Exception : " + str(e)


    @challengedns.route('/admin/challengedns/manage/record/<string:chalname>/update', methods=['POST'])
    @admins_only
    def update_record(chalname):
        if request.form["ipaddress"]:
            try:
                return update_operation(chalname, request.form["ipaddress"])
            except Exception as e:
                print("Caught Exception : " + str(e))
                return "Caught Exception : " + str(e)
        else:
            return "chalname not set."

    @challengedns.route('/admin/challengedns/manage/record/new', methods=['POST'])
    @admins_only
    def create_record():
        if request.form["chalname"] and request.form["ipaddress"]:
            try:
                return create_operation(request.form["chalname"], request.form["ipaddress"])
            except Exception as e:
                print("Caught Exception : " + str(e))
                return "Caught Exception : " + str(e)
        else:
            return "ipaddress or chalname not set."

    def delete_operation(chalname):
        #check if exists
        #delete
        nameserver = challengeDNSConfig.query.filter_by(option="DNS IP").first()

        if nameserver and chalname:
            chalname = chalname.lower()

            # Append only if chalname not blacklisted
            if chalname in chalname_blacklist:
                return "This record name is blacklisted."

            operation = delete_format.format(
                nameserver,
                chalname)
            return_code, stdout = nsupdate(operation)
            if return_code != 0:
                return stdout
            else:
                print('Record deleted.')
                return "Success!"
        else:
            print("Parameters not correct.")
            return "Parameters not correct."

    def update_operation(chalname, ipaddress):
        #check if exists
        #update record
        nameserver = challengeDNSConfig.query.filter_by(option="DNS IP").first()

        if nameserver and chalname and ipaddress:
            chalname = chalname.lower()

            # Append only if chalname not blacklisted
            if chalname in chalname_blacklist:
                return "This record name is blacklisted."

            operation = update_format.format(
                nameserver,
                chalname,
                8640,
                ipaddress)

            return_code, stdout = nsupdate(operation)
            if return_code != 0:
                return stdout
            else:
                print('Record updated')
                return "Success!"
        else:
            print("Parameters not correct.")
            return "Parameters not correct."

    def create_operation(chalname, ipaddress):
        # check if exists
        # update record
        nameserver = challengeDNSConfig.query.filter_by(option="DNS IP").first()

        if nameserver and chalname and ipaddress:
            chalname = chalname.lower()

            # Append only if chalname not blacklisted
            if chalname in chalname_blacklist:
                return "This record name is blacklisted."
            
            operation = create_format.format(
                nameserver,
                chalname,
                8640,
                ipaddress)

            return_code, stdout = nsupdate(operation)
            
            if return_code != 0:
                return stdout
            else:
                print('Record created.')
                return "Success!"

        else:
            print("Parameters not correct.")
            return "Parameters not correct."


    def nsupdate(operation):
        keyfile = challengeDNSConfig.query.filter_by(option="Keyfile").first()

        cmd = 'nsupdate -k {0}'.format(keyfile)

        # open subprocess and execute nsupdate cmd
        # shlex.split() splits the cmd string using shell-like syntax
        subp = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)

        stdout =subp.communicate(input=operation)[0]

        return subp.returncode, stdout.decode()

    def output_zone_records(rootdomain, nameserver):
        cmd = 'dig @{0} {1} axfr'.format(nameserver, rootdomain)

        # open subprocess and execute dig cmd
        # shlex.split() splits the cmd string using shell-like syntax
        subp = Popen(shlex.split(cmd), stdout=PIPE, stdin=PIPE, stderr=STDOUT)

        stdout =subp.communicate(input=cmd)[0]

        return subp.returncode, stdout.decode()

    def fetch_zone_records():
        rootdomain = challengeDNSConfig.query.filter_by(option="Root domain").first()
        nameserver = challengeDNSConfig.query.filter_by(option="Nameserver").first()

        return_code, cmd_output = output_zone_records(rootdomain, nameserver)
        records = []

        recs = cmd_output.splitlines()

        for rec in recs:
            record = rec.split()

            # Only append A records
            # Only append name a
            if record[3] == "A":
                rootdomain += "."
                chalname = record[0].replace(rootdomain, "")

                # Append only if chalname not blacklisted
                if chalname not in chalname_blacklist:
                    # append challenge name and IP
                    records.append([record[0],record[4]])

        return records

    # plugin is not configured when one key has no value
    def is_configured():
        configured = True

        for key in valid_settings:
            challengednsconfigopt = challengeDNSConfig.query.filter_by(option=key).first()
            if challengednsconfigopt == None:
                configured = False

        return configured


    # generate dictionary with already filled in config options + empty options
    def config_opts_db():
        settings = {}

        for key in valid_settings:
            challengednsconfigopt = challengeDNSConfig.query.filter_by(option=key).first()

            if challengednsconfigopt == None:
                settings[key] = [valid_settings[key][0], valid_settings[key][1]]
            else:
                settings[key] = [valid_settings[key][0], challengednsconfigopt.value]

        return settings

    app.register_blueprint(challengedns)